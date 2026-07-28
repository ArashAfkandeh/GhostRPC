use crate::config::ServerConfig;

use crate::net_utils::{enable_tcp_keepalive, get_random_headers};

use bytes::{Bytes, BytesMut};
use http::StatusCode;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

use std::collections::{HashMap, HashSet};
use std::sync::{OnceLock, RwLock};

#[derive(Debug)]
struct WildcardResolver {
    certs: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
}

impl WildcardResolver {
    fn new() -> Self {
        Self { certs: HashMap::new() }
    }

    fn add(&mut self, name: &str, cert: Arc<rustls::sign::CertifiedKey>) {
        self.certs.insert(name.to_string(), cert);
    }
}

impl rustls::server::ResolvesServerCert for WildcardResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?;
        
        if let Some(cert) = self.certs.get(sni) {
            return Some(cert.clone());
        }
        
        if let Some(idx) = sni.find('.') {
            let wildcard = format!("*{}", &sni[idx..]);
            if let Some(cert) = self.certs.get(&wildcard) {
                return Some(cert.clone());
            }
        }
        
        // Fallback to any available wildcard if exact match fails
        // This helps if the client sends no SNI or an unknown SNI
        None
    }
}

// ==========================================
// 6. SERVER MODE
// ==========================================

static DEAD_TARGETS: OnceLock<RwLock<HashSet<String>>> = OnceLock::new();

fn get_dead_targets() -> &'static RwLock<HashSet<String>> {
    DEAD_TARGETS.get_or_init(|| RwLock::new(HashSet::new()))
}

pub async fn run_server(cfg: ServerConfig, cancel_token: CancellationToken) {
    let mut resolver = WildcardResolver::new();
    let mut loaded_certs = 0;
    
    let exe_dir = std::env::current_exe()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
        .parent()
        .unwrap_or(std::path::Path::new(""))
        .to_path_buf();
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
                                        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(certs, sign_key));
                                        resolver.add(&domain, certified_key.clone());
                                        resolver.add(&format!("*.{}", domain), certified_key);
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
        tracing::warn!("⚠️ هیچ گواهینامه‌ای در مسیر certs پیدا نشد! ارتباطات TLS ممکن است با خطا مواجه شوند.");
    }

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = crate::net_utils::create_reuseport_listener(&cfg.bind_addr).unwrap();
    info!("🛡️ Server listening on {}", cfg.bind_addr);
    
    let mut direct_route_table = std::collections::HashMap::new();
    crate::routing::parse_port_mappings(cfg.sni_proxy.as_ref().unwrap_or(&vec![]), None, &mut direct_route_table);
    let local_direct_route = Arc::new(direct_route_table.get(&cfg.bind_addr).cloned().unwrap_or_default());

    let mut web_server_map: std::collections::HashMap<String, Vec<crate::config::WebServerConfig>> = std::collections::HashMap::new();
    if let Some(ws_configs) = &cfg.web_server {
        for ws in ws_configs {
            let domain_only = ws.domain.split(':').next().unwrap_or(&ws.domain).to_string();
            web_server_map.entry(domain_only).or_default().push(ws.clone());
        }
    }
    let local_web_server_map = Arc::new(web_server_map);

    let mut unique_targets = HashSet::new();
    for target in local_direct_route.sni_rules.values() {
        unique_targets.insert(target.clone());
    }
    if let Some(target) = &local_direct_route.default_upstream {
        unique_targets.insert(target.clone());
    }

    let cancel_hc = cancel_token.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_hc.cancelled() => break,
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }
            let mut targets_to_check = unique_targets.clone();
            {
                let dead = get_dead_targets().read().unwrap();
                for t in dead.iter() {
                    targets_to_check.insert(t.clone());
                }
            }
            
            let mut current_dead = HashSet::new();
            for target in &targets_to_check {
                match tokio::time::timeout(std::time::Duration::from_secs(2), TcpStream::connect(target)).await {
                    Ok(Ok(_)) => {}, // target is up
                    _ => {
                        current_dead.insert(target.clone());
                    }
                }
            }
            *get_dead_targets().write().unwrap() = current_dead;
        }
    });

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("🛑 Stopping server listener on {} due to Hot-Reload", cfg.bind_addr);
                break;
            }
            accept_res = listener.accept() => {
                if let Ok((mut tcp, peer)) = accept_res {
                    tracing::debug!("🔗 Accepted TCP connection from {}", peer);
                    let _ = tcp.set_nodelay(true);
                    crate::net_utils::enable_tcp_bbr(&tcp);
                    crate::net_utils::tune_socket_buffers(&tcp);
                    enable_tcp_keepalive(&tcp);

                    let acceptor = acceptor.clone();
                    let cfg_path = cfg.hidden_path.clone();
                    let cfg_camo = cfg.camouflage_target.clone();
                    let cfg_secret = cfg.secret.clone();
                    let direct_route = local_direct_route.clone();
                    let web_server_map = local_web_server_map.clone();

                    tokio::spawn(async move {
                        let mut initial_buf = [0u8; 2048];
                        let mut initial_len = 0;
                        let mut extracted_sni = None;
                        
                        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                            loop {
                                if initial_len >= 2048 { break; }
                                let n = match tcp.read(&mut initial_buf[initial_len..]).await {
                                    Ok(n) if n > 0 => n,
                                    _ => break,
                                };
                                initial_len += n;

                                if initial_buf[0] != 0x16 { break; }
                                if let Some(sni) = crate::routing::extract_sni(&initial_buf[..initial_len]) {
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
                        
                        let target_up = if let Some(sni) = &extracted_sni {
                            direct_route.sni_rules.get(sni).cloned().or_else(|| direct_route.default_upstream.clone())
                        } else {
                            direct_route.default_upstream.clone()
                        };

                        if let Some(target) = target_up {
                            if get_dead_targets().read().unwrap().contains(&target) {
                                return; // Circuit Breaker: Target is dead, drop instantly without overhead
                            }

                            tracing::debug!("🔄 SNI Routing triggered for {:?} -> {}", extracted_sni, target);
                            match tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(&target)).await {
                                Ok(Ok(mut upstream_tcp)) => {
                                    let _ = upstream_tcp.set_nodelay(true);
                                    crate::net_utils::tune_socket_buffers(&upstream_tcp);
                                    crate::net_utils::enable_tcp_keepalive(&upstream_tcp);
                                    
                                    if initial_len > 0 {
                                        if upstream_tcp.write_all(&initial_buf[..initial_len]).await.is_err() { return; }
                                    }
                                    
                                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut upstream_tcp).await;
                                }
                                Ok(Err(_)) | Err(_) => {
                                    // Soft fallback if it fails before health check detects it
                                    // Just return, no sleep, no warn log spam
                                }
                            }
                            return;
                        }

                        let prefixed_tcp = crate::prefixed_stream::PrefixedStream {
                            prefix: initial_buf[..initial_len].to_vec(),
                            inner: tcp,
                        };

                        let tls_stream = match acceptor.accept(prefixed_tcp).await { 
                            Ok(s) => { tracing::debug!("🔒 TLS Handshake succeeded"); s }, 
                            Err(e) => { tracing::debug!("TLS Accept failed: {:?}", e); return } 
                        };

                        let tls_sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
                        
                        if let Some(sni) = &tls_sni {
                            if let Some(ws_routes) = web_server_map.get(sni) {
                                tracing::debug!("🔒 L7 Web Server Routing triggered for {:?}", sni);
                                crate::web_server::handle_web_server_connection(tls_stream, ws_routes.clone(), Some(peer.ip())).await;
                                return;
                            }
                        }
                        let mut h2 = match h2::server::Builder::new()
                            .initial_window_size(2_097_152) // 2 MB Stream Window
                            .initial_connection_window_size(4_194_304) // 4 MB Connection Window
                            .max_frame_size(1_048_576) // 1 MB max frame
                            .handshake(tls_stream).await { Ok(h) => h, Err(e) => { tracing::debug!("H2 Handshake failed: {:?}", e); return } };

                        while let Some(Ok((req, mut respond))) = h2.accept().await {
                            let tunnel_target = if req.uri().path() != cfg_path {
                                None
                            } else {
                                let t_hdr = req.headers().get("x-tunnel-target").and_then(|h| h.to_str().ok());
                                let s_hdr = req.headers().get("x-tunnel-secret").and_then(|h| h.to_str().ok());
                                match (t_hdr, s_hdr) {
                                    (Some(t_val), Some(s_val)) if s_val == cfg_secret.clone().unwrap_or_default() => Some(t_val.to_string()),
                                    _ => {
                                        tracing::warn!("Unauthorized or malformed request to hidden path from {}", peer);
                                        None
                                    }
                                }
                            };

                            if tunnel_target.is_none() {
                                if let Some(camo) = &cfg_camo {
                                    if camo.starts_with("http://") || camo.starts_with("https://") {
                                        let url = format!("{}{}", camo, req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
                                        tokio::spawn(async move {
                                            let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
                                            match client.get(&url).send().await {
                                                Ok(mut resp) => {
                                                    let mut res_builder = http::Response::builder().status(resp.status());
                                                    for (k, v) in resp.headers() {
                                                        let k_str = k.as_str().to_lowercase();
                                                        if k_str != "transfer-encoding" && k_str != "connection" && k_str != "content-length" {
                                                            res_builder = res_builder.header(k.clone(), v.clone());
                                                        }
                                                    }
                                                    if let Ok(mut send_stream) = respond.send_response(res_builder.body(()).unwrap(), false) {
                                                        while let Ok(Some(chunk)) = resp.chunk().await {
                                                            if crate::net_utils::send_h2_data(&mut send_stream, chunk, false).await.is_err() { break; }
                                                        }
                                                        let _ = send_stream.send_data(Bytes::new(), true);
                                                    }
                                                }
                                                Err(_) => {
                                                    let _ = respond.send_response(http::Response::builder().status(404).body(()).unwrap(), true);
                                                }
                                            }
                                        });
                                    } else {
                                        let camo_clone = camo.clone();
                                        tokio::spawn(async move {
                                            let mut file_path = std::path::PathBuf::from(&camo_clone);
                                            if file_path.parent().map(|p| p.as_os_str().is_empty()).unwrap_or(true) {
                                                let exe_dir = std::env::current_exe()
                                                    .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
                                                    .parent()
                                                    .unwrap_or(std::path::Path::new(""))
                                                    .to_path_buf();
                                                file_path = exe_dir.join(&camo_clone);
                                            }

                                            if let Ok(content) = tokio::fs::read(&file_path).await {
                                                let res = http::Response::builder()
                                                    .status(200)
                                                    .header("content-type", "text/html; charset=utf-8")
                                                    .body(())
                                                    .unwrap();
                                                if let Ok(mut send_stream) = respond.send_response(res, false) {
                                                    let framed = Bytes::from(content);
                                                    let _ = crate::net_utils::send_h2_data(&mut send_stream, framed, true).await;
                                                }
                                            } else {
                                                let _ = respond.send_response(http::Response::builder().status(404).body(()).unwrap(), true);
                                            }
                                        });
                                    }
                                } else {
                                    let _ = respond.send_response(http::Response::builder().status(404).body(()).unwrap(), true);
                                }
                                continue;
                            }

                            let mut target = tunnel_target.unwrap();
                            if !target.contains(':') {
                                target = format!("127.0.0.1:{}", target);
                            }
                            
                            let is_explicit_local = target.contains("127.0.0.1") || target.contains("localhost") || target.contains("GHOST_LOCAL");
                            let try_local = is_explicit_local || req.headers().get("x-tunnel-try-local").map_or(false, |v| v == "true");
                            tracing::debug!("🎯 Valid tunnel request received for target: {} (try_local: {})", target, try_local);
                            
                            tokio::spawn(async move {
                                let mut tcp_stream = None;
                                if try_local {
                                    if let Some(idx) = target.rfind(':') {
                                        let port_str = &target[idx + 1..];
                                        let local_v4 = format!("127.0.0.1:{}", port_str);
                                        let local_v6 = format!("[::1]:{}", port_str);
                                        
                                        if let Ok(Ok(tcp)) = tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(&local_v4)).await {
                                            tracing::debug!("✅ Successfully connected to local fallback target (IPv4): {}", local_v4);
                                            tcp_stream = Some(tcp);
                                        } else if let Ok(Ok(tcp)) = tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(&local_v6)).await {
                                            tracing::debug!("✅ Successfully connected to local fallback target (IPv6): {}", local_v6);
                                            tcp_stream = Some(tcp);
                                        } else {
                                            tracing::debug!("⚠️ Local targets (IPv4/IPv6) not available, falling back to original: {}", target);
                                        }
                                    }
                                }
                                
                                if tcp_stream.is_none() {
                                    if get_dead_targets().read().unwrap().contains(&target) {
                                        // Circuit Breaker: Target is dead, drop instantly without Tarpit
                                        let _ = respond.send_response(http::Response::builder().status(StatusCode::BAD_GATEWAY).body(()).unwrap(), true);
                                        return;
                                    }

                                    match tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(&target)).await {
                                        Ok(Ok(tcp)) => {
                                            tracing::debug!("✅ Successfully connected to target: {}", target);
                                            tcp_stream = Some(tcp);
                                        }
                                        _ => {
                                            tracing::warn!("❌ Failed to connect to target: {}", target);
                                            get_dead_targets().write().unwrap().insert(target.clone());
                                            let _ = respond.send_response(http::Response::builder().status(StatusCode::BAD_GATEWAY).body(()).unwrap(), true);
                                            return;
                                        }
                                    }
                                }
                                
                                let mut res_builder = http::Response::builder().status(StatusCode::OK);
                                for (k, v) in get_random_headers() { res_builder = res_builder.header(k, v); }
                                let mut send_stream = match respond.send_response(res_builder.body(()).unwrap(), false) {
                                    Ok(s) => s,
                                    Err(_) => return,
                                };

                                let target_tcp = tcp_stream.unwrap();
                                let _ = target_tcp.set_nodelay(true);
                                        crate::net_utils::tune_socket_buffers(&target_tcp);
                                        enable_tcp_keepalive(&target_tcp);
                                        let (mut target_read, mut target_write) = target_tcp.into_split();

                                    let (drop_tx, mut drop_rx) = tokio::sync::oneshot::channel::<()>();
                                    tokio::spawn(async move {
                                        let mut read_buf = BytesMut::with_capacity(1024 * 1024);
                                        loop {
                                            if read_buf.capacity() < 65536 + 5 {
                                                read_buf = BytesMut::with_capacity(1024 * 1024);
                                            }
                                            read_buf.extend_from_slice(&[0, 0, 0, 0, 0]);
                                            tokio::select! {
                                                _ = &mut drop_rx => break,
                                                res = target_read.read_buf(&mut read_buf) => {
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
                                    let mut body = req.into_body();
                                    while let Some(Ok(mut data)) = body.data().await {
                                        let _ = body.flow_control().release_capacity(data.len());
                                        
                                        if grpc_buf.is_empty() {
                                            while data.len() >= 5 {
                                                let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                                                if len > 1048576 { tracing::warn!("OOM protection: TCP frame too large"); return; }
                                                if data.len() < 5 + len { break; }
                                                if target_write.write_all(&data[5..5+len]).await.is_err() { return; }
                                                data = data.slice(5+len..);
                                            }
                                            if !data.is_empty() {
                                                grpc_buf.extend_from_slice(&data);
                                            }
                                        } else {
                                            grpc_buf.extend_from_slice(&data);
                                            while grpc_buf.len() >= 5 {
                                                let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                                if len > 1048576 { tracing::warn!("OOM protection: TCP frame too large"); return; }
                                                if grpc_buf.len() < 5 + len { break; }
                                                if target_write.write_all(&grpc_buf[5..5+len]).await.is_err() { return; }
                                                let _ = grpc_buf.split_to(5 + len);
                                            }
                                        }
                                    }
                                    let _ = target_write.shutdown().await;
                                    let _ = drop_tx;
                            });
                        }
                    });
                }
            }
        }
    }
}
