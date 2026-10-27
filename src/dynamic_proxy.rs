use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Resolves the SNI dynamically using DNS and returns an established TCP connection
    
pub async fn resolve_and_connect(sni: &str, port: u16) -> Option<TcpStream> {
    let addr_str = format!("{}:{}", sni, port);
    debug!("Dynamic SNI Proxy: Attempting to resolve {}", addr_str);

    match tokio::net::lookup_host(&addr_str).await {
        Ok(addrs) => {
            for addr in addrs {
                debug!("Dynamic SNI Proxy: Resolved {} to {}", sni, addr);
                if let Ok(stream) = crate::anti_loop::safe_connect(
                    addr,
                    std::time::Duration::from_millis(1500) // 1.5s timeout for fast fallback
                ).await {
                    debug!("Dynamic SNI Proxy: Successfully connected to {} on port {}", addr, port);
                    return Some(stream);
                } else {
                    debug!("Dynamic SNI Proxy: Connection to {} failed or timed out. Trying next...", addr);
                }
            }
            warn!("Dynamic SNI Proxy: All connection attempts to {} failed.", sni);
            None
        }
        Err(e) => {
            warn!("Dynamic SNI Proxy: DNS resolution for {} failed: {}", sni, e);
            None
        }
    }
}
