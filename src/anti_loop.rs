use tokio::net::{TcpStream, TcpSocket, lookup_host};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::{Instant, Duration};
use std::io;
use std::sync::LazyLock;

// Stores (SocketAddr, Timestamp) of all outbound connections initiated by this proxy.
// This state allows us to deterministically detect if an incoming connection
// is a loop (i.e. originated from ourselves).
pub static OUTBOUND_LOCAL_ADDRS: LazyLock<DashMap<SocketAddr, Instant>> = LazyLock::new(|| DashMap::new());

/// Records the source port of an outbound socket before it initiates the TCP SYN.
pub fn track_outbound(addr: SocketAddr) {
    let now = Instant::now();
    OUTBOUND_LOCAL_ADDRS.insert(addr, now);
    
    // Amortized lazy cleanup: 10% chance per insertion to clean up old entries.
    // We only need to track the address for a few seconds to detect loops.
    // If a connection takes > 10 seconds to loop back, it's either dropped or invalid anyway.
    if rand::random::<u8>() % 10 == 0 {
        OUTBOUND_LOCAL_ADDRS.retain(|_, time| now.duration_since(*time).as_secs() < 10);
    }
}

/// Checks if an incoming peer address is one of our own active outbound source ports.
/// If true, this connection is a loop and MUST be dropped.
pub fn is_loop(peer_addr: &SocketAddr) -> bool {
    OUTBOUND_LOCAL_ADDRS.contains_key(peer_addr)
}

/// Replaces `TcpStream::connect` by explicitly binding the socket to port 0
/// first, so we know the ephemeral source port before we attempt to connect.
/// This allows the `listener.accept()` loop to immediately reject loops.
pub async fn safe_connect<A: tokio::net::ToSocketAddrs + std::fmt::Display>(
    target: A,
    timeout_duration: Duration
) -> io::Result<TcpStream> {
    let addrs = lookup_host(&target).await?;
    let mut last_err = None;

    for addr in addrs {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };

        // Try to bind to an ephemeral port
        let bind_addr: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        
        let _ = socket.bind(bind_addr); // Ignore error; OS will assign on connect if bind fails

        let mut tracked_addr = None;
        if let Ok(local_addr) = socket.local_addr() {
            if local_addr.port() != 0 {
                track_outbound(local_addr);
                tracked_addr = Some(local_addr);
            }
        }

        match tokio::time::timeout(timeout_duration, socket.connect(addr)).await {
            Ok(Ok(stream)) => {
                // In case local_addr wasn't resolved until connect (e.g. bind failed but connect succeeded)
                if tracked_addr.is_none() {
                    if let Ok(l_addr) = stream.local_addr() {
                        track_outbound(l_addr);
                    }
                }
                return Ok(stream);
            }
            Ok(Err(e)) => {
                if let Some(l) = tracked_addr {
                    OUTBOUND_LOCAL_ADDRS.remove(&l);
                }
                last_err = Some(e);
            }
            Err(_) => {
                if let Some(l) = tracked_addr {
                    OUTBOUND_LOCAL_ADDRS.remove(&l);
                }
                last_err = Some(io::Error::new(io::ErrorKind::TimedOut, "connection timed out"));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("could not resolve target: {}", target))))
}
