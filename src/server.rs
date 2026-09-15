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

use std::collections::{HashMap, HashSet};
use std::sync::{OnceLock, RwLock};

#[derive(Debug)]
struct WildcardResolver {
    certs: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
}

impl WildcardResolver {
    fn new() -> Self {
        Self {
            certs: HashMap::new(),
        }
    }

    fn add(&mut self, name: &str, cert: Arc<rustls::sign::CertifiedKey>) {
        self.certs.insert(name.to_string(), cert);
    }
}

impl rustls::server::ResolvesServerCert for WildcardResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
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

pub async fn run_server(
    cfg: ServerConfig,
    cancel_token: CancellationToken,
) {


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
                                let certs: Vec<_> =
                                    rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
                                        .map(|r| r.unwrap())
                                        .collect();
                                if let Ok(Some(key)) = rustls_pemfile::private_key(
                                    &mut std::io::BufReader::new(key_file),
                                ) {
                                    if let Ok(sign_key) =
                                        rustls::crypto::ring::sign::any_supported_type(&key)
                                    {
                                        let certified_key = Arc::new(
                                            rustls::sign::CertifiedKey::new(certs, sign_key),
                                        );
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
        tracing::warn!(
            "⚠️ هیچ گواهینامه‌ای در مسیر certs پیدا نشد! ارتباطات TLS ممکن است با خطا مواجه شوند."
        );
    }

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let mut direct_route_table = std::collections::HashMap::new();
    crate::routing::parse_server_sni_proxy(
        cfg.sni_proxy.as_ref().unwrap_or(&vec![]),
        &cfg.bind_addr,
        &mut direct_route_table,
    );
    let local_direct_route = Arc::new(
        direct_route_table
            .get(&cfg.bind_addr)
            .cloned()
            .unwrap_or_default(),
    );

    let mut web_server_map: std::collections::HashMap<String, Vec<crate::config::WebServerConfig>> =
        std::collections::HashMap::new();
    if let Some(ws_configs) = &cfg.web_server {
        for ws in ws_configs {
            let domain_only = ws
                .domain
                .split(':')
                .next()
                .unwrap_or(&ws.domain)
                .to_string();
            web_server_map
                .entry(domain_only)
                .or_default()
                .push(ws.clone());
        }
    }
    let local_web_server_map = Arc::new(web_server_map);

    let mut unique_targets = HashSet::new();
    for (_, rt) in &direct_route_table {
        for target in rt.sni_rules.values() {
            for t in target.split(',') {
                unique_targets.insert(t.trim().to_string());
            }
        }
        if let Some(target) = &rt.default_upstream {
            for t in target.split(',') {
                unique_targets.insert(t.trim().to_string());
            }
        }
    }

    let cancel_hc = cancel_token.clone();
    if !unique_targets.is_empty() {
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

                let mut recovered_targets = Vec::new();
                let mut newly_dead_static = Vec::new();

                for target in &targets_to_check {
                    match crate::anti_loop::safe_connect(target, std::time::Duration::from_secs(2)).await {
                        Ok(mut tcp) => {
                            // Smart L4 TCP Probe: Wait up to 50ms to see if connection is instantly closed
                            let mut buf = [0u8; 1];
                            let is_up = match tokio::time::timeout(std::time::Duration::from_millis(50), tokio::io::AsyncReadExt::read(&mut tcp, &mut buf)).await {
                                Ok(Ok(0)) => false, // Connection closed immediately (e.g. by anti-loop or RST)
                                Ok(Err(_)) => false, // IO Error
                                Ok(Ok(_)) => true, // Received data (upstream is alive and sending data)
                                Err(_) => true, // Timeout, connection held open waiting for data (Healthy L4!)
                            };
                            
                            if is_up {
                                recovered_targets.push(target.clone());
                            } else {
                                if unique_targets.contains(target) {
                                    newly_dead_static.push(target.clone());
                                }
                            }
                        }
                        Err(_) => {
                            // Target is DOWN. Ensure static targets are tracked.
                            if unique_targets.contains(target) {
                                newly_dead_static.push(target.clone());
                            }
                        }
                    }
                }

                // Safely apply changes without erasing dynamically added targets
                let mut dead_guard = get_dead_targets().write().unwrap();
                for t in recovered_targets {
                    dead_guard.remove(&t);
                }
                for t in newly_dead_static {
                    dead_guard.insert(t);
                }
            }
        });
    }

    // Start listeners for sni_proxy routes
    for (bind_addr, route_table) in direct_route_table.clone() {
        if bind_addr == cfg.bind_addr {
            continue;
        } // Do not duplicate main listener

        let mut listener_opt = None;
        for i in 0..10 {
            match crate::net_utils::create_reuseport_listener(&bind_addr) {
                Ok(l) => {
                    listener_opt = Some(l);
                    break;
                }
                Err(e) => {
                    tracing::warn!("⚠️ Failed to bind SNI Proxy {} (attempt {}/10): {}. Retrying in 200ms...", bind_addr, i + 1, e);
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
        if let Some(listener) = listener_opt {
            tracing::info!("🛡️ SNI Proxy listening on {}", bind_addr);

            let acceptor = acceptor.clone();
            let cfg_path = cfg.hidden_path.clone();
            let cfg_camo = cfg.camouflage_target.clone();
            let cfg_secret = cfg.secret.clone();
            let direct_route = Arc::new(route_table);
            let web_server_map = local_web_server_map.clone();
            let bind_port = bind_addr.split(':').last().unwrap_or("").to_string();
            let token = cancel_token.clone();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = token.cancelled() => {
                            tracing::info!("🛑 Stopping SNI Proxy listener on {} due to Hot-Reload", bind_addr);
                            break;
                        }
                        accept_res = listener.accept() => {
                            if let Ok((tcp, peer)) = accept_res {
                                if crate::anti_loop::is_loop(&peer) {
                                    crate::net_utils::log_rate_limited(&format!("anti_loop_{}", peer), "🛑 Anti-Loop Firewall: Dropped self-loop connection in SNI proxy.");
                                    continue;
                                }

                                tracing::debug!("🔗 Accepted TCP connection from {} on {}", peer, bind_addr);
                                let _ = tcp.set_nodelay(true);
                                crate::net_utils::enable_tcp_bbr(&tcp);
                                crate::net_utils::tune_socket_buffers(&tcp);
                                crate::net_utils::enable_tcp_keepalive(&tcp);

                                let a = acceptor.clone();
                                let p = cfg_path.clone();
                                let c = cfg_camo.clone();
                                let s = cfg_secret.clone();
                                let d = direct_route.clone();
                                let w = web_server_map.clone();
                                let bp = bind_port.clone();

                                tokio::spawn(async move {
                                    handle_server_connection(tcp, peer, a, p, c, s, d, w, bp).await;
                                });
                            }
                        }
                    }
                }
            });
        } else {
            tracing::error!("❌ Failed to bind SNI Proxy listener on {}", bind_addr);
        }
    }
    let mut bind_addrs = Vec::new();
    if !cfg.bind_addr.is_empty() {
        bind_addrs.push(cfg.bind_addr.clone());
    } else if cfg.web_server.is_some() {
        bind_addrs.push("0.0.0.0:443".to_string());
        bind_addrs.push("0.0.0.0:80".to_string());
    }

    if bind_addrs.is_empty() {
        cancel_token.cancelled().await;
        return;
    }

    let mut handles = Vec::new();

    for bind_addr in bind_addrs {
        let cancel_token = cancel_token.clone();
        let acceptor = acceptor.clone();
        let cfg_path = cfg.hidden_path.clone();
        let cfg_camo = cfg.camouflage_target.clone();
        let cfg_secret = cfg.secret.clone();
        let direct_route = local_direct_route.clone();
        let web_server_map = local_web_server_map.clone();
        
        let handle = tokio::spawn(async move {
            let mut listener_opt = None;
            for i in 0..10 {
                match crate::net_utils::create_reuseport_listener(&bind_addr) {
                    Ok(l) => {
                        listener_opt = Some(l);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("⚠️ Failed to bind Server {} (attempt {}/10): {}. Retrying in 200ms...", bind_addr, i + 1, e);
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }
            if let Some(listener) = listener_opt {
                tracing::info!("🛡️ Server listening on {}", bind_addr);
                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            tracing::info!("🛑 Stopping server listener on {} due to Hot-Reload", bind_addr);
                            break;
                        }
                        accept_res = listener.accept() => {
                            if let Ok((tcp, peer)) = accept_res {
                                if crate::anti_loop::is_loop(&peer) {
                                    crate::net_utils::log_rate_limited(&format!("anti_loop_{}", peer), "🛑 Anti-Loop Firewall: Dropped self-loop connection in main proxy.");
                                    continue;
                                }

                                tracing::debug!("🔗 Accepted TCP connection from {}", peer);
                                let _ = tcp.set_nodelay(true);
                                crate::net_utils::enable_tcp_bbr(&tcp);
                                crate::net_utils::tune_socket_buffers(&tcp);
                                crate::net_utils::enable_tcp_keepalive(&tcp);

                                let acceptor_clone = acceptor.clone();
                                let cfg_path_clone = cfg_path.clone();
                                let cfg_camo_clone = cfg_camo.clone();
                                let cfg_secret_clone = cfg_secret.clone();
                                let direct_route_clone = direct_route.clone();
                                let web_server_map_clone = web_server_map.clone();
                                let bind_port = bind_addr.split(':').last().unwrap_or("").to_string();

                                tokio::spawn(async move {
                                    handle_server_connection(
                                        tcp,
                                        peer,
                                        acceptor_clone,
                                        cfg_path_clone,
                                        cfg_camo_clone,
                                        cfg_secret_clone,
                                        direct_route_clone,
                                        web_server_map_clone,
                                        bind_port,
                                    ).await;
                                });
                            }
                        }
                    }
                }
            } else {
                tracing::error!("❌ Failed to bind main server listener on {}", bind_addr);
            }
        });
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
}

pub async fn handle_server_connection(
    mut tcp: TcpStream,
    peer: std::net::SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    cfg_path: String,
    cfg_camo: Option<String>,
    cfg_secret: Option<String>,
    direct_route: Arc<crate::config::Route>,
    web_server_map: Arc<std::collections::HashMap<String, Vec<crate::config::WebServerConfig>>>,
    bind_port: String,
) {
    let mut initial_buf = [0u8; 8192];
    let mut initial_len = 0;
    let mut extracted_sni = None;

    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        loop {
            if initial_len >= 8192 {
                break;
            }
            let n = match tcp.read(&mut initial_buf[initial_len..]).await {
                Ok(n) if n > 0 => n,
                _ => break,
            };
            initial_len += n;

            if initial_buf[0] == 0x16 {
                if let Some(sni) = crate::routing::extract_sni(&initial_buf[..initial_len]) {
                    tracing::debug!("✅ Successfully extracted SNI {:?} from initial ClientHello bytes", sni);
                    extracted_sni = Some(sni);
                    break;
                }
                if initial_len >= 5 {
                    let record_len = ((initial_buf[3] as usize) << 8) | (initial_buf[4] as usize);
                    if initial_len >= 5 + record_len {
                        break;
                    }
                }
            } else if crate::routing::is_http_request(&initial_buf[..initial_len]) {
                if let Some(host) = crate::routing::extract_http_host(&initial_buf[..initial_len]) {
                    extracted_sni = Some(host);
                    break;
                } else if initial_buf[..initial_len]
                    .windows(4)
                    .any(|w| w == b"\r\n\r\n")
                    || initial_buf[..initial_len].windows(2).any(|w| w == b"\n\n")
                {
                    break;
                }
            } else {
                break;
            }
        }
    })
    .await;

    let target_up = if let Some(sni) = &extracted_sni {
        direct_route
            .sni_rules
            .get(sni)
            .or_else(|| direct_route.sni_rules.get("*"))
            .cloned()
            .or_else(|| direct_route.default_upstream.clone())
    } else {
        direct_route
            .sni_rules
            .get("*")
            .cloned()
            .or_else(|| direct_route.default_upstream.clone())
    };

    if let Some(target_list) = target_up {
        if target_list == "dynamic" {
            if let Some(sni) = &extracted_sni {
                let local_port = tcp.local_addr().map(|a| a.port()).unwrap_or(443);
                tracing::debug!(
                    "🔄 Dynamic SNI Proxy Routing triggered for {} on port {}",
                    sni,
                    local_port
                );
                if let Some(mut upstream_tcp) =
                    crate::dynamic_proxy::resolve_and_connect(sni, local_port).await
                {
                    let _ = upstream_tcp.set_nodelay(true);
                    crate::net_utils::tune_socket_buffers(&upstream_tcp);
                    crate::net_utils::enable_tcp_keepalive(&upstream_tcp);
                    crate::net_utils::enable_tcp_linger_zero(&upstream_tcp);

                    if initial_len > 0 {
                        if upstream_tcp
                            .write_all(&initial_buf[..initial_len])
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }

                    let start_time = std::time::Instant::now();
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut upstream_tcp).await;
                    if start_time.elapsed() < std::time::Duration::from_millis(500) {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
                return;
            } else {
                tracing::warn!("Dynamic proxy requested but no SNI was found in the ClientHello.");
                return;
            }
        }

        let mut healthy_targets = Vec::new();
        {
            let dead_targets = get_dead_targets().read().unwrap();
            for t in target_list.split(',') {
                let t = t.trim();
                if !dead_targets.contains(t) && !t.is_empty() {
                    healthy_targets.push(t.to_string());
                }
            }
        }

        if healthy_targets.is_empty() {
            crate::net_utils::log_rate_limited(
                &format!("circuit_breaker_{:?}", extracted_sni),
                &format!("Circuit Breaker: All targets for SNI {:?} are dead (pool: {}). Dropping.", extracted_sni, target_list)
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            return;
        }

        // Active-Passive Failover: Always pick the first available healthy target (highest priority)
        let target = healthy_targets[0].clone();

        tracing::debug!(
            "🔄 SNI Routing triggered for {:?} -> {} (from pool: {})",
            extracted_sni,
            target,
            target_list
        );
        match crate::anti_loop::safe_connect(&target, std::time::Duration::from_secs(10)).await {
            Ok(mut upstream_tcp) => {
                let _ = upstream_tcp.set_nodelay(true);
                crate::net_utils::tune_socket_buffers(&upstream_tcp);
                crate::net_utils::enable_tcp_keepalive(&upstream_tcp);
                crate::net_utils::enable_tcp_linger_zero(&upstream_tcp);

                if initial_len > 0 {
                    if upstream_tcp
                        .write_all(&initial_buf[..initial_len])
                        .await
                        .is_err()
                    {
                        return;
                    }
                }

                let start_time = std::time::Instant::now();
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut upstream_tcp).await;
                if start_time.elapsed() < std::time::Duration::from_millis(500) {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
            Err(_) => {}
        }
        return;
    }

    let prefixed_tcp = crate::prefixed_stream::PrefixedStream {
        prefix: initial_buf[..initial_len].to_vec(),
        inner: tcp,
    };

    let tls_stream = match tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(prefixed_tcp)).await {
        Ok(Ok(s)) => {
            tracing::debug!("🔒 TLS Handshake succeeded");
            s
        }
        Ok(Err(e)) => {
            let err_msg = e.to_string();
            if e.kind() == std::io::ErrorKind::UnexpectedEof || e.kind() == std::io::ErrorKind::ConnectionReset || err_msg.contains("eof") {
                // Health checks or scanners (TCP Pings)
                tracing::trace!("TCP Ping/Healthcheck detected and dropped (UnexpectedEof)");
            } else {
                tracing::debug!("TLS Accept failed: {:?}", e);
            }
            return;
        }
        Err(_) => {
            tracing::debug!("TLS Accept timed out after 10s (Likely GFW Dropped ClientHello)");
            return;
        }
    };

    let tls_sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string());
    tracing::debug!("🔍 [TLS Accept] Connection from {} completed TLS handshake. Received SNI: {:?}", peer, tls_sni);

    if let Some(sni) = &tls_sni {
        if let Some(ws_routes) = web_server_map.get(sni) {
            tracing::info!("🌐 [Routing] SNI {:?} matched Web Server config! Delegating to L7 web server.", sni);
            crate::web_server::handle_web_server_connection(
                tls_stream,
                ws_routes.clone(),
                Some(peer.ip()),
            )
            .await;
            return;
        } else {
            tracing::debug!("⚠️ [Routing] SNI {:?} was received but did not match any domain in web_server_map. Falling back to GhostRPC Tunnel (HTTP/2).", sni);
        }
    } else {
        tracing::debug!("⚠️ [Routing] No SNI provided by client {}. Falling back to GhostRPC Tunnel (HTTP/2).", peer);
    }
    let mut h2 = match h2::server::Builder::new()
        .initial_window_size(8_388_608) // 8 MB Stream Window (High BDP throughput)
        .initial_connection_window_size(1_073_741_824) // 1 GB Connection Window
        .max_frame_size(65_535) // 64 KB max frame (Prevents HoL blocking on lossy networks)
        .handshake(tls_stream)
        .await
    {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!("H2 Handshake failed: {:?}", e);
            return;
        }
    };

    while let Some(Ok((req, mut respond))) = h2.accept().await {
        let tunnel_target = if req.uri().path() != cfg_path {
            None
        } else {
            let t_hdr = req
                .headers()
                .get("x-tunnel-target")
                .and_then(|h| h.to_str().ok());
            let s_hdr = req
                .headers()
                .get("x-tunnel-secret")
                .and_then(|h| h.to_str().ok());
            match (t_hdr, s_hdr) {
                (Some(t_val), Some(s_val)) if s_val == cfg_secret.clone().unwrap_or_default() => {
                    Some(t_val.to_string())
                }
                _ => {
                    tracing::warn!(
                        "Unauthorized or malformed request to hidden path from {}",
                        peer
                    );
                    None
                }
            }
        };

        if tunnel_target.is_none() {
            if let Some(camo) = &cfg_camo {
                if camo.starts_with("http://") || camo.starts_with("https://") {
                    let url = format!(
                        "{}{}",
                        camo,
                        req.uri()
                            .path_and_query()
                            .map(|pq| pq.as_str())
                            .unwrap_or("/")
                    );
                    tokio::spawn(async move {
                        let client = reqwest::Client::builder()
                            .redirect(reqwest::redirect::Policy::none())
                            .build()
                            .unwrap();
                        match client.get(&url).send().await {
                            Ok(mut resp) => {
                                let mut res_builder =
                                    http::Response::builder().status(resp.status());
                                for (k, v) in resp.headers() {
                                    let k_str = k.as_str().to_lowercase();
                                    if k_str != "transfer-encoding"
                                        && k_str != "connection"
                                        && k_str != "content-length"
                                    {
                                        res_builder = res_builder.header(k.clone(), v.clone());
                                    }
                                }
                                if let Ok(mut send_stream) =
                                    respond.send_response(res_builder.body(()).unwrap(), false)
                                {
                                    while let Ok(Some(chunk)) = resp.chunk().await {
                                        if crate::net_utils::send_h2_data(
                                            &mut send_stream,
                                            chunk,
                                            false,
                                        )
                                        .await
                                        .is_err()
                                        {
                                            break;
                                        }
                                    }
                                    let _ = send_stream.send_data(Bytes::new(), true);
                                }
                            }
                            Err(_) => {
                                let _ = respond.send_response(
                                    http::Response::builder().status(404).body(()).unwrap(),
                                    true,
                                );
                            }
                        }
                    });
                } else {
                    let camo_clone = camo.clone();
                    tokio::spawn(async move {
                        let mut file_path = std::path::PathBuf::from(&camo_clone);
                        if file_path
                            .parent()
                            .map(|p| p.as_os_str().is_empty())
                            .unwrap_or(true)
                        {
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
                                let _ =
                                    crate::net_utils::send_h2_data(&mut send_stream, framed, true)
                                        .await;
                            }
                        } else {
                            let _ = respond.send_response(
                                http::Response::builder().status(404).body(()).unwrap(),
                                true,
                            );
                        }
                    });
                }
            } else {
                let _ = respond.send_response(
                    http::Response::builder().status(404).body(()).unwrap(),
                    true,
                );
            }
            continue;
        }

        let mut target = tunnel_target.unwrap();
        if !target.contains(':') {
            target = format!("127.0.0.1:{}", target);
        }

        let is_loop = if target.starts_with("127.0.0.1:")
            || target.starts_with("localhost:")
            || target.starts_with("[::1]:")
        {
            if let Some(idx) = target.rfind(':') {
                let port_str = &target[idx + 1..];
                port_str == bind_port
            } else {
                false
            }
        } else {
            false
        };

        if is_loop {
            tracing::warn!(
                "🔄 Routing loop detected! Target {} matches our own listen port. Rejecting.",
                target
            );
            let _ = respond.send_response(
                http::Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(())
                    .unwrap(),
                true,
            );
            return;
        }

        let is_explicit_local = target.contains("127.0.0.1")
            || target.contains("localhost")
            || target.contains("GHOST_LOCAL");
        let try_local = is_explicit_local
            || req
                .headers()
                .get("x-tunnel-try-local")
                .map_or(false, |v| v == "true");
        tracing::debug!(
            "🎯 Valid tunnel request received for target: {} (try_local: {})",
            target,
            try_local
        );

        tokio::spawn(async move {
            if get_dead_targets().read().unwrap().contains(&target) {
                crate::net_utils::log_rate_limited(&format!("cb_{}", target), &format!("❌ Circuit Breaker active for dead target: {}", target));
                // 1-second tarpit to prevent 100% CPU from client retry storms, while avoiding 2GB RAM leaks
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let _ = respond.send_response(
                    http::Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(())
                        .unwrap(),
                    true,
                );
                return;
            }

            let mut tcp_stream = None;
            if try_local {
                if let Some(idx) = target.rfind(':') {
                    let port_str = &target[idx + 1..];
                    let local_v4 = format!("127.0.0.1:{}", port_str);
                    let local_v6 = format!("[::1]:{}", port_str);

                    match crate::anti_loop::safe_connect(&local_v4, std::time::Duration::from_secs(10)).await {
                        Ok(tcp) => {
                            tracing::debug!(
                                "✅ Successfully connected to local fallback target (IPv4): {}",
                                local_v4
                            );
                            tcp_stream = Some(tcp);
                        }
                        Err(_) => match crate::anti_loop::safe_connect(&local_v6, std::time::Duration::from_secs(10)).await {
                            Ok(tcp) => {
                                tracing::debug!(
                                    "✅ Successfully connected to local fallback target (IPv6): {}",
                                    local_v6
                                );
                                tcp_stream = Some(tcp);
                            }
                            Err(_) => {
                                tracing::debug!(
                                    "⚠️ Local targets (IPv4/IPv6) not available for {}",
                                    target
                                );
                            }
                        }
                    }
                }
            }

            if tcp_stream.is_none() {
                if try_local {
                    crate::net_utils::log_rate_limited(&format!("fail_local_{}", target), &format!("❌ Failed to connect to local target for {}", target));
                    get_dead_targets().write().unwrap().insert(target.clone());
                    
                    let _ = respond.send_response(
                        http::Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(())
                            .unwrap(),
                        true,
                    );
                    return;
                }

                match crate::anti_loop::safe_connect(&target, std::time::Duration::from_secs(10)).await {
                    Ok(tcp) => {
                        tracing::debug!("✅ Successfully connected to target: {}", target);
                        tcp_stream = Some(tcp);
                    }
                    _ => {
                        crate::net_utils::log_rate_limited(&format!("fail_{}", target), &format!("❌ Failed to connect to target: {}", target));
                        get_dead_targets().write().unwrap().insert(target.clone());

                        let _ = respond.send_response(
                            http::Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(())
                                .unwrap(),
                            true,
                        );
                        return;
                    }
                }
            }

            let mut res_builder = http::Response::builder().status(StatusCode::OK);
            for (k, v) in get_random_headers() {
                res_builder = res_builder.header(k, v);
            }
            let mut send_stream = match respond.send_response(res_builder.body(()).unwrap(), false)
            {
                Ok(s) => s,
                Err(_) => return,
            };

            let target_tcp = tcp_stream.unwrap();
            let _ = target_tcp.set_nodelay(true);
            crate::net_utils::tune_socket_buffers(&target_tcp);
            enable_tcp_keepalive(&target_tcp);
            crate::net_utils::enable_tcp_linger_zero(&target_tcp);
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
                        if len > 1048576 {
                            tracing::warn!("OOM protection: TCP frame too large");
                            return;
                        }
                        if data.len() < 5 + len {
                            break;
                        }
                        if target_write.write_all(&data[5..5 + len]).await.is_err() {
                            return;
                        }
                        data = data.slice(5 + len..);
                    }
                    if !data.is_empty() {
                        grpc_buf.extend_from_slice(&data);
                    }
                } else {
                    grpc_buf.extend_from_slice(&data);
                    while grpc_buf.len() >= 5 {
                        let len = u32::from_be_bytes([
                            grpc_buf[1],
                            grpc_buf[2],
                            grpc_buf[3],
                            grpc_buf[4],
                        ]) as usize;
                        if len > 1048576 {
                            tracing::warn!("OOM protection: TCP frame too large");
                            return;
                        }
                        if grpc_buf.len() < 5 + len {
                            break;
                        }
                        if target_write.write_all(&grpc_buf[5..5 + len]).await.is_err() {
                            return;
                        }
                        let _ = grpc_buf.split_to(5 + len);
                    }
                }
            }
            let _ = target_write.shutdown().await;
            let _ = drop_tx;
        });
    }
}
