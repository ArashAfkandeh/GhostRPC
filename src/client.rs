use crate::config::ClientConfig;

use crate::net_utils::{enable_tcp_keepalive, get_random_headers};
use crate::routing::extract_sni;

use bytes::{Bytes, BytesMut};
use http::{Method, Request};
use std::{
    sync::{atomic::{AtomicUsize, Ordering}, Arc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};


pub struct ConnectionState {
    pub client: Option<h2::client::SendRequest<Bytes>>,
    pub consecutive_errors: u32,
    pub ewma_latency: f64,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self { client: None, consecutive_errors: 0, ewma_latency: 500.0 }
    }
}

#[derive(Debug, Clone)]
pub struct ActiveNode {
    pub location: String,
    pub sni: String,
    pub share_sni: u32,
}

async fn connect_h2_node(node: &ActiveNode, clean_ips: &[String], tls_connector: &TlsConnector) -> Result<h2::client::SendRequest<Bytes>, String> {
    let (sni_host, sni_port) = if let Some(idx) = node.sni.rfind(':') {
        (&node.sni[..idx], &node.sni[idx+1..])
    } else {
        (node.sni.as_str(), "443")
    };

    use futures::stream::{FuturesUnordered, StreamExt};
    let mut connect_tasks = FuturesUnordered::new();
    
    for ip in clean_ips {
        let addr_str = if ip.contains(':') && !ip.starts_with('[') {
             if ip.split(':').count() > 2 {
                 format!("[{}]:{}", ip, sni_port) // IPv6
             } else {
                 ip.to_string() // User provided IPv4:Port in clean_ip? Unlikely but supported
             }
        } else {
             format!("{}:{}", ip, sni_port)
        };
        
        connect_tasks.push(async move {
            let addrs = tokio::net::lookup_host(&addr_str).await.map_err(|e| e.to_string())?.collect::<Vec<_>>();
            for addr in addrs {
                 if let Ok(Ok(stream)) = tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(addr)).await {
                     return Ok::<_, String>(stream);
                 }
            }
            Err::<_, String>("Failed".into())
        });
    }

    let mut tcp_opt = None;
    while let Some(res) = connect_tasks.next().await {
        if let Ok(stream) = res {
            tcp_opt = Some(stream);
            break;
        }
    }

    let tcp = tcp_opt.ok_or_else(|| "All TCP connection attempts (Racing) failed".to_string())?;
    let _ = tcp.set_nodelay(true);
    crate::net_utils::enable_tcp_bbr(&tcp);
    crate::net_utils::tune_socket_buffers(&tcp);
    enable_tcp_keepalive(&tcp);

    let domain = rustls::pki_types::ServerName::try_from(sni_host).map_err(|e| e.to_string())?.to_owned();
    let tls_stream = tls_connector.connect(domain, tcp).await.map_err(|e| e.to_string())?;
    
    // Use aggressive HTTP/2 flow control windows (Default 65KB is too slow for WAN)
    let (client, mut conn) = h2::client::Builder::new()
        .initial_window_size(2_097_152) // 2 MB Stream Window
        .initial_connection_window_size(4_194_304) // 4 MB Connection Window
        .max_frame_size(1_048_576) // 1 MB max frame
        .handshake(tls_stream).await.map_err(|e| e.to_string())?;

    let mut ping_pong = conn.ping_pong().unwrap();
    tokio::spawn(async move {
        let ping_loop = async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                match tokio::time::timeout(std::time::Duration::from_secs(2), ping_pong.ping(h2::Ping::opaque())).await {
                    Ok(Ok(_)) => {},
                    _ => {
                        tracing::warn!("H2 Ping failed or timed out. Dropping connection.");
                        break;
                    }
                }
            }
        };
        tokio::select! {
            res = conn => {
                if let Err(e) = res { tracing::debug!("H2 background connection closed: {:?}", e); }
            }
            _ = ping_loop => {}
        }
    });
    Ok(client)
}

pub async fn run_client(cfg: ClientConfig, cancel_token: CancellationToken) {
    let mut flat_remotes = Vec::new();
    for loc in cfg.remotes.iter() {
        let sharing = loc.share_sni.unwrap_or(0);
        for sni in loc.sni.iter() {
            flat_remotes.push(ActiveNode {
                location: loc.location.clone(),
                sni: sni.clone(),
                share_sni: sharing,
            });
        }
    }
    if flat_remotes.is_empty() {
        error!("No remote servers defined!");
        return;
    }

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    
    let mut tls_config_h2 = rustls::ClientConfig::builder()
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();
    tls_config_h2.alpn_protocols = vec![b"h2".to_vec()];
    let tls_connector = Arc::new(TlsConnector::from(Arc::new(tls_config_h2)));

    let pool_per_node = cfg.pool_size_per_node.unwrap_or(16);
    let total_pool_size = flat_remotes.len() * pool_per_node;

    info!("Initializing Distributed Pool ({} nodes x {} conns = {} total streams)...", flat_remotes.len(), pool_per_node, total_pool_size);

    let mut pool: Vec<(Arc<Mutex<ConnectionState>>, ActiveNode)> = Vec::new();
    for _ in 0..pool_per_node {
        for remote in &flat_remotes {
            pool.push((Arc::new(Mutex::new(ConnectionState::default())), remote.clone()));
        }
    }
    let pool = Arc::new(pool);

    // Pre-load clean IPs from file BEFORE starting anything
    let clean_ip_file = cfg.clean_ip_file.clone().unwrap_or_else(|| "ips/clean_ips.txt".to_string());
    let source_ips_file = cfg.source_ips_file.clone().unwrap_or_else(|| "ips/source_ips.txt".to_string());
    let check_interval_minutes = cfg.check_interval_minutes.unwrap_or(60);
    let max_ping_ms = cfg.max_ping_ms.unwrap_or(150);

    let initial_ips: Vec<String> = if let Ok(content) = tokio::fs::read_to_string(&clean_ip_file).await {
        content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    } else {
        Vec::new()
    };

    let clean_ips_global = Arc::new(tokio::sync::RwLock::new(initial_ips));

    // Start IP Scanner (background periodic refresh)
    let scanner = crate::scanner::Scanner::new(
        clean_ip_file,
        source_ips_file,
        check_interval_minutes,
        max_ping_ms,
        clean_ips_global.clone(),
        cfg.remotes.clone(),
        tls_connector.clone(),
    );
    scanner.start();

    // Eager Pool Maintainer (Background Connect)
    for (slot_arc, remote) in pool.iter() {
        let slot = slot_arc.clone();
        let remote = remote.clone();
        let tls = tls_connector.clone();
        let token = cancel_token.clone();
        let clean_ips = clean_ips_global.clone();
        
        tokio::spawn(async move {
            let mut backoff_ms: u64 = 500;
            let max_backoff_ms: u64 = 30000;
            
            loop {
                if token.is_cancelled() { break; }
                
                let is_none = slot.lock().await.client.is_none();
                if is_none {
                    let start_time = tokio::time::Instant::now();
                    let current_ips = clean_ips.read().await.clone();
                    if !current_ips.is_empty() {
                        if let Ok(new_client) = connect_h2_node(&remote, &current_ips, &tls).await {
                            let mut guard = slot.lock().await;
                            guard.client = Some(new_client);
                            guard.consecutive_errors = 0;
                            guard.ewma_latency = start_time.elapsed().as_millis() as f64;
                            tracing::trace!("🔥 Pool Maintainer: Warmed up connection to {} ({}ms)", remote.sni, guard.ewma_latency);
                            
                            // Reset backoff on success
                            backoff_ms = 500;
                        } else {
                            // Exponential Backoff with Jitter (Enterprise Grade)
                            backoff_ms = std::cmp::min(max_backoff_ms, (backoff_ms as f64 * 1.5) as u64);
                            let jitter = (rand::random::<u64>() % 1000) + 100;
                            backoff_ms = std::cmp::min(max_backoff_ms, backoff_ms + jitter);
                            tracing::debug!("⚠️ Pool Maintainer: Failed to connect to {}, backing off for {}ms", remote.sni, backoff_ms);
                        }
                    }
                } else {
                    // Reset backoff if we are connected
                    backoff_ms = 500;
                }
                
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                    _ = token.cancelled() => break,
                }
            }
        });
    }

    // Warmup: Wait for at least one pool connection before accepting user traffic
    {
        let warmup_start = tokio::time::Instant::now();
        let warmup_timeout = Duration::from_secs(30);
        loop {
            if cancel_token.is_cancelled() { return; }
            let mut has_ready = false;
            for (slot_arc, _) in pool.iter() {
                let guard = slot_arc.lock().await;
                if guard.client.is_some() {
                    has_ready = true;
                    break;
                }
            }
            if has_ready {
                info!("✅ Pool warmup complete in {}ms, starting listeners...", warmup_start.elapsed().as_millis());
                break;
            }
            if warmup_start.elapsed() > warmup_timeout {
                warn!("⚠️ Pool warmup timed out after 30s, starting listeners anyway...");
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    let conn_counter = Arc::new(AtomicUsize::new(0));

    let mut mapped_routes = std::collections::HashMap::new();
    for loc in cfg.remotes.iter() {
        crate::routing::parse_port_mappings(&loc.port_mappings, Some(&loc.location), &mut mapped_routes);
    }
    for (local_bind, route_table) in &mapped_routes {
        if let Some(def) = &route_table.default_upstream {
            tracing::debug!("Mapping {} -> Default Upstream: {}", local_bind, def);
        }
        for (sni, up) in &route_table.sni_rules {
            tracing::debug!("Mapping {} (SNI: {}) -> Upstream: {}", local_bind, sni, up);
        }
    }    for (local_bind, route_table) in mapped_routes {
        let listener = match crate::net_utils::create_reuseport_listener(&local_bind) {
            Ok(l) => l, Err(e) => { error!("Failed to bind {}: {}", local_bind, e); continue; }
        };
        info!("🚀 Listener active on {} with {} SNI rules", local_bind, route_table.sni_rules.len());

        let cfg_clone = cfg.clone();

        let pool_clone = pool.clone();

        let counter_clone = conn_counter.clone();
        let token = cancel_token.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        info!("🛑 Stopping listener on {} due to Hot-Reload", local_bind);
                        break;
                    }
                    accept_res = listener.accept() => {
                        if let Ok((mut local_tcp, peer)) = accept_res {
                            let _ = local_tcp.set_nodelay(true);
                            crate::net_utils::tune_socket_buffers(&local_tcp);
                            enable_tcp_keepalive(&local_tcp);
                            let c_id = counter_clone.fetch_add(1, Ordering::SeqCst);

                            let route_table = route_table.clone();
                            let pool_clone = pool_clone.clone();
                            let cfg_inner = cfg_clone.clone();


                            tokio::spawn(async move {
                                let mut extracted_sni = None;
                                let mut initial_buf = [0u8; 2048];
                                let mut initial_len = 0;
                                let _ = tokio::time::timeout(Duration::from_millis(500), async {
                                    loop {
                                        if initial_len >= 2048 { break; }
                                        let n = match local_tcp.read(&mut initial_buf[initial_len..]).await {
                                            Ok(n) if n > 0 => n,
                                            _ => break,
                                        };
                                        initial_len += n;

                                        if initial_buf[0] != 0x16 { break; }
                                        if let Some(sni) = extract_sni(&initial_buf[..initial_len]) {
                                            extracted_sni = Some(sni);
                                            break;
                                        }

                                        if initial_len >= 5 {
                                            let record_len = ((initial_buf[3] as usize) << 8) | (initial_buf[4] as usize);
                                            if initial_len >= 5 + record_len {
                                                break; 
                                            }
                                        }
                                    }
                                }).await;
                                let initial_data = initial_buf[..initial_len].to_vec();

                                let target_up = if let Some(sni) = &extracted_sni {
                                    trace!("[Conn #{}] Detected SNI: {}", c_id, sni);
                                    route_table.sni_rules.get(sni).cloned().or_else(|| route_table.default_upstream.clone())
                                } else {
                                    route_table.default_upstream.clone()
                                };

                                let target_up = match target_up {
                                    Some(t) => t,
                                    None => {
                                        warn!("[Conn #{}] Connection from {} dropped: No matching SNI or default route.", c_id, peer);
                                        return;
                                    }
                                };

                                debug!("[Conn #{}] Accepted {} -> Routed to {}", c_id, peer, target_up);

                                let (mut local_read, mut local_write) = local_tcp.into_split();

                                let mut final_send_stream = None;
                                let mut final_response = None;
                                let mut global_retries = 0;
                                let mut failed_snis = std::collections::HashSet::new();
                                
                                while global_retries < 5 {
                                    let mut ready_client = None;
                                    let mut retries = 0;
                                    while retries < 5 {
                                        let mut best_client = None;
                                        let mut best_slot = None;
                                        let mut best_remote = None;
                                        let mut lowest_latency = f64::MAX;
                                        let total_pool_size = pool_clone.len();
                                        
                                        for i in 0..total_pool_size {
                                            let (pool_slot, target_remote) = &pool_clone[i];
                                            
                                            if failed_snis.contains(&target_remote.sni) {
                                                continue;
                                            }
                                            
                                            let mut slot_guard = pool_slot.lock().await;
                                            
                                            if let Some(c) = &slot_guard.client {
                                                let mut c_clone = c.clone();
                                                if let Ok(_) = std::future::poll_fn(|cx| c_clone.poll_ready(cx)).await {
                                                    let mut penalty = 0.0;
                                                    if let Some(pref) = route_table.target_locations.get(&target_up) {
                                                        if target_remote.location != *pref {
                                                            if target_remote.share_sni == 0 {
                                                                continue;
                                                            }
                                                            penalty = 10000.0 + (target_remote.share_sni as f64 * 100.0);
                                                        }
                                                    }
                                                    let score = slot_guard.ewma_latency + penalty;
                                                    if score < lowest_latency {
                                                        lowest_latency = score;
                                                        best_client = Some(c_clone);
                                                        best_slot = Some(pool_slot.clone());
                                                        best_remote = Some(target_remote.clone());
                                                    }
                                                } else {
                                                    slot_guard.client = None;
                                                }
                                            }
                                        }

                                        if let Some(c) = best_client {
                                            ready_client = Some((c, best_slot.unwrap(), best_remote.unwrap()));
                                            break;
                                        } else {
                                            retries += 1;
                                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                        }
                                    }
                                    
                                    if ready_client.is_none() {
                                        tracing::warn!("[Conn #{}] All pool slots are disconnected! Connection dropped.", c_id);
                                        return;
                                    }
                                    
                                    let (mut c, pool_slot, target_remote) = ready_client.unwrap();

                                    let final_target_up = target_up.clone();
                                    let is_local = target_up.starts_with("127.") || target_up.starts_with("localhost") || target_up.starts_with("[::1]") || target_up.starts_with("10.") || target_up.starts_with("192.168.") || target_up.starts_with("172.");
                                    let mut try_local = false;
                                    if !is_local {
                                        let mut is_fallback = false;
                                        if let Some(pref) = route_table.target_locations.get(&target_up) {
                                            if target_remote.location != *pref {
                                                is_fallback = true;
                                            }
                                        }
                                        if !is_fallback {
                                            try_local = true;
                                        }
                                    }

                                    let mut req_builder = Request::builder()
                                        .method(Method::POST)
                                        .uri(format!("https://{}{}", target_remote.sni, cfg_inner.hidden_path))
                                        .header("Host", target_remote.sni.clone())
                                        .header("x-tunnel-target", final_target_up.clone())
                                        .header("x-tunnel-secret", cfg_inner.secret.clone().unwrap_or_default());
                                        
                                    if try_local {
                                        req_builder = req_builder.header("x-tunnel-try-local", "true");
                                    }

                                    for (k, v) in get_random_headers() { req_builder = req_builder.header(k, v); }

                                    let start_time = tokio::time::Instant::now();
                                    match c.send_request(req_builder.body(()).unwrap(), false) {
                                        Ok((response_future, send_stream)) => {
                                            if let Ok(Ok(res)) = tokio::time::timeout(tokio::time::Duration::from_millis(5000), response_future).await {
                                                if res.status() == http::StatusCode::OK {
                                                    let latency = start_time.elapsed().as_millis() as f64;
                                                    let mut slot = pool_slot.lock().await;
                                                    slot.ewma_latency = (0.2 * latency) + (0.8 * slot.ewma_latency);
                                                    slot.consecutive_errors = 0;
                                                    
                                                    if !failed_snis.is_empty() {
                                                        tracing::debug!("[Conn #{}] TCP Tunnel successfully fell back to alternate SNI: {}", c_id, target_remote.sni);
                                                    }
                                                    
                                                    final_send_stream = Some(send_stream);
                                                    final_response = Some(res);
                                                    break;
                                                }
                                                tracing::warn!("[Conn #{}] Tunnel failed! Remote server {} returned HTTP {}", c_id, target_remote.sni, res.status());
                                                let mut slot = pool_slot.lock().await;
                                                slot.ewma_latency += 5000.0;
                                                failed_snis.insert(target_remote.sni.clone());
                                            } else {
                                                let mut slot = pool_slot.lock().await;
                                                slot.client = None;
                                                failed_snis.insert(target_remote.sni.clone());
                                            }
                                        }
                                        Err(_) => {
                                            let mut slot = pool_slot.lock().await;
                                            slot.consecutive_errors += 1;
                                            if slot.consecutive_errors >= 3 {
                                                slot.client = None; slot.consecutive_errors = 0;
                                                tracing::warn!("[Conn #{}] Drained node due to send errors.", c_id);
                                            }
                                            failed_snis.insert(target_remote.sni.clone());
                                        }
                                    }

                                    global_retries += 1;
                                }
                                
                                if final_send_stream.is_none() {
                                    tracing::warn!("[Conn #{}] All tunnel attempts failed.", c_id);
                                    return;
                                }
                                
                                let mut send_stream = final_send_stream.unwrap();
                                let response = final_response.unwrap();

                                let (drop_tx, mut drop_rx) = tokio::sync::oneshot::channel::<()>();
                                tokio::spawn(async move {
                                            if !initial_data.is_empty() {
                                                let mut init_buf = BytesMut::with_capacity(5 + initial_data.len());
                                                init_buf.extend_from_slice(&[0, 0, 0, 0, 0]);
                                                init_buf[1..5].copy_from_slice(&(initial_data.len() as u32).to_be_bytes());
                                                init_buf.extend_from_slice(&initial_data);
                                                let framed = init_buf.freeze();
                                                
                                                if crate::net_utils::send_h2_data(&mut send_stream, framed, false).await.is_err() { return; }
                                            }

                                            let mut read_buf = BytesMut::with_capacity(1024 * 1024);
                                            loop {
                                                    if read_buf.capacity() < 65536 + 5 {
                                                        read_buf = BytesMut::with_capacity(1024 * 1024);
                                                    }
                                                    read_buf.extend_from_slice(&[0, 0, 0, 0, 0]);
                                                    tokio::select! {
                                                        _ = &mut drop_rx => break,
                                                        res = local_read.read_buf(&mut read_buf) => {
                                                            let n = match res {
                                                                Ok(0) | Err(_) => break,
                                                                Ok(n) => n,
                                                            };
                                                            read_buf[1..5].copy_from_slice(&(n as u32).to_be_bytes());
                                                            let framed = read_buf.split().freeze();
                                                            
                                                            if crate::net_utils::send_h2_data(&mut send_stream, framed, false).await.is_err() { break; }
                                                        }
                                                    }
                                                }
                                                let _ = send_stream.send_data(Bytes::new(), true);
                                            });

                                        let mut grpc_buf = BytesMut::new();
                                        let mut body = response.into_body();
                                        while let Some(Ok(mut data)) = body.data().await {
                                            let _ = body.flow_control().release_capacity(data.len());
                                            
                                            if grpc_buf.is_empty() {
                                                while data.len() >= 5 {
                                                    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                                                    if data.len() < 5 + len { break; }
                                                    if local_write.write_all(&data[5..5+len]).await.is_err() { return; }
                                                    data = data.slice(5+len..);
                                                }
                                                if !data.is_empty() {
                                                    grpc_buf.extend_from_slice(&data);
                                                }
                                            } else {
                                                grpc_buf.extend_from_slice(&data);
                                                while grpc_buf.len() >= 5 {
                                                    let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                                    if grpc_buf.len() < 5 + len { break; }
                                                    if local_write.write_all(&grpc_buf[5..5+len]).await.is_err() { return; }
                                                    let _ = grpc_buf.split_to(5 + len);
                                                }
                                            }
                                        }
                                        let _ = local_write.shutdown().await;
                                        let _ = drop_tx;
                            });
                        }
                    }
                }
            }
        });
    }
    // Standalone Local L7 Web Server Routing (Independent of GhostRPC Tunnels)
    if let Some(ws_configs) = &cfg.web_server {
        if !ws_configs.is_empty() {
            let mut bind_map: std::collections::HashMap<String, Vec<crate::config::WebServerConfig>> = std::collections::HashMap::new();
            for ws in ws_configs {
                let parts: Vec<&str> = ws.domain.split(':').collect();
                let port = if parts.len() > 1 { parts[1] } else { "443" };
                let bind_addr = format!("0.0.0.0:{}", port);
                bind_map.entry(bind_addr).or_default().push(ws.clone());
            }
            
            let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
            let mut loaded_certs = 0;
            let exe_dir = std::env::current_exe().unwrap_or_else(|_| std::env::current_dir().unwrap_or_default()).parent().unwrap_or(std::path::Path::new("")).to_path_buf();
            let certs_dir = exe_dir.join("certs");
            
            if certs_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(certs_dir) {
                    for entry in entries.flatten() {
                        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            let domain = entry.file_name().to_string_lossy().to_string();
                            let cert_path = entry.path().join("fullchain.pem");
                            let key_path = entry.path().join("privkey.pem");
                            if cert_path.exists() && key_path.exists() {
                                if let Ok(cert_file) = std::fs::File::open(&cert_path) {
                                    if let Ok(key_file) = std::fs::File::open(&key_path) {
                                        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file)).map(|r| r.unwrap()).collect();
                                        if let Ok(Some(key)) = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file)) {
                                            if let Ok(sign_key) = rustls::crypto::ring::sign::any_supported_type(&key) {
                                                let certified_key = rustls::sign::CertifiedKey::new(certs, sign_key);
                                                let _ = resolver.add(&domain, certified_key.clone());
                                                let _ = resolver.add(&format!("*.{}", domain), certified_key);
                                                loaded_certs += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            if loaded_certs == 0 {
                tracing::warn!("⚠️ هیچ گواهینامه‌ای در مسیر certs پیدا نشد! ارتباطات TLS کلاینت ممکن است با خطا مواجه شوند.");
            }

            let mut tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver));
            
            tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

            for (local_bind, ws_list) in bind_map {
                let acceptor = acceptor.clone();
                let ws_list_clone = Arc::new(ws_list);
                let token_clone = cancel_token.clone();
                tokio::spawn(async move {
                    if let Ok(listener) = tokio::net::TcpListener::bind(&local_bind).await {
                        tracing::info!("🔒 Client Standalone L7 Web Server active on {}", local_bind);
                        loop {
                            tokio::select! {
                                _ = token_clone.cancelled() => break,
                                Ok((tcp, _)) = listener.accept() => {
                                    let _ = tcp.set_nodelay(true);
                                    crate::net_utils::tune_socket_buffers(&tcp);
                                    let acceptor = acceptor.clone();
                                    let ws_list = ws_list_clone.clone();
                                    let peer_addr = tcp.peer_addr().ok().map(|a| a.ip());
                                    tokio::spawn(async move {
                                        if let Ok(tls_stream) = acceptor.accept(tcp).await {
                                            let sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
                                            if let Some(s) = &sni {
                                                let matched_routes: Vec<crate::config::WebServerConfig> = ws_list.iter()
                                                    .filter(|c| c.domain.starts_with(s))
                                                    .cloned()
                                                    .collect();
                                                if !matched_routes.is_empty() {
                                                    crate::web_server::handle_web_server_connection(tls_stream, matched_routes, peer_addr).await;
                                                }
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    } else {
                        tracing::error!("Failed to bind TLS listener on {}", local_bind);
                    }
                });
            }
        }
    }

    cancel_token.cancelled().await;
}
