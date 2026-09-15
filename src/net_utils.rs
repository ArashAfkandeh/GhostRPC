

use socket2::{SockRef, TcpKeepalive};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::warn;

// ==========================================
// 2. TCP KEEPALIVE (بخشی از "2. TCP KEEPALIVE & CRYPTO")
// ==========================================

pub fn enable_tcp_keepalive(stream: &TcpStream) {
    let sock = SockRef::from(stream);
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(15)).with_interval(Duration::from_secs(5));
    if let Err(e) = sock.set_tcp_keepalive(&ka) {
        warn!("Failed to set TCP Keepalive: {}", e);
    }
}

pub fn enable_tcp_linger_zero(stream: &TcpStream) {
    let sock = SockRef::from(stream);
    if let Err(e) = sock.set_linger(Some(Duration::from_secs(0))) {
        warn!("Failed to set SO_LINGER: {}", e);
    }
}

pub fn tune_socket_buffers(stream: &TcpStream) {
    // Only keeping socket reference for future tuning if needed.
    // Explicit SO_RCVBUF and SO_SNDBUF removed to allow Linux TCP Auto-Tuning.
    let _sock = SockRef::from(stream);
    
    // Clamp TCP MSS to 1300 to fix MTU blackhole issues (very common in Iran)
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let mss: libc::c_int = 1300;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                &mss as *const _ as *const libc::c_void,
                std::mem::size_of_val(&mss) as libc::socklen_t,
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub fn enable_tcp_bbr(stream: &TcpStream) {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let bbr = b"bbr\0";
    unsafe {
        let res = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            bbr.as_ptr() as *const _,
            (bbr.len() - 1) as libc::socklen_t, // pass length without null terminator or with? Wait, usually we pass the string length, e.g. 3 for "bbr"
        );
        if res != 0 {
            warn!("Failed to set TCP BBR. Is it enabled in the kernel?");
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn enable_tcp_bbr(_stream: &TcpStream) {
    // BBR setting is Linux-specific
}



pub fn get_random_headers() -> Vec<(&'static str, &'static str)> {
    let user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    ];
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let ua = user_agents[(now % user_agents.len() as u128) as usize];
    vec![
        ("user-agent", ua),
        ("accept", "application/grpc-web, application/grpc, */*"),
        ("accept-language", "en-US,en;q=0.9"),
        ("te", "trailers"),
        ("content-type", "application/grpc"),
    ]
}

pub fn create_reuseport_listener(addr_str: &str) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Socket, Domain, Type, Protocol};
    use std::net::SocketAddr;
    
    let addr: SocketAddr = addr_str.parse().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut try_addr = addr;
    let mut domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let mut socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    
    socket.set_reuse_address(true)?;
    
    // Clamp TCP MSS to 1300 on the listener to announce it in SYN-ACK.
    // This perfectly fixes MTU blackholes for all incoming client connections.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let mss: libc::c_int = 1300;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                &mss as *const _ as *const libc::c_void,
                std::mem::size_of_val(&mss) as libc::socklen_t,
            );
        }
    }
    
    #[cfg(target_family = "unix")]
    if let Err(e) = socket.set_reuse_port(true) {
        tracing::warn!("Failed to set SO_REUSEPORT (Hot-reload might drop connections during restart): {}", e);
    }
    
    if let Err(e) = socket.bind(&try_addr.into()) {
        if addr.is_ipv6() {
            tracing::warn!("⚠️ Failed to bind to IPv6 address {}: {}. Falling back to IPv4 (0.0.0.0)...", addr, e);
            try_addr = format!("0.0.0.0:{}", addr.port()).parse().unwrap();
            domain = Domain::IPV4;
            socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_reuse_address(true)?;
            #[cfg(target_family = "unix")]
            let _ = socket.set_reuse_port(true);
            socket.bind(&try_addr.into())?;
        } else {
            return Err(e);
        }
    }
    socket.listen(1024)?; // backlog of 1024
    
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(std_listener)
}


pub async fn send_h2_data(send_stream: &mut h2::SendStream<bytes::Bytes>, mut data: bytes::Bytes, end_of_stream: bool) -> Result<(), ()> {
    if data.is_empty() {
        if end_of_stream {
            return send_stream.send_data(bytes::Bytes::new(), true).map_err(|_| ());
        }
        return Ok(());
    }

    while !data.is_empty() {
        send_stream.reserve_capacity(data.len());
        if send_stream.capacity() == 0 {
            if let Some(Err(_)) | None = std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await {
                return Err(());
            }
        }
        let to_send = std::cmp::min(send_stream.capacity(), data.len());
        let chunk = data.split_to(to_send);
        let is_last = data.is_empty() && end_of_stream;
        if send_stream.send_data(chunk, is_last).is_err() {
            return Err(());
        }
    }
    Ok(())
}

use dashmap::DashMap;
use std::time::Instant;

static LOG_RATE_LIMITS: std::sync::OnceLock<DashMap<String, Instant>> = std::sync::OnceLock::new();

pub fn log_rate_limited(key: &str, msg: &str) {
    let map = LOG_RATE_LIMITS.get_or_init(DashMap::new);
    let now = Instant::now();
    let should_log = match map.get(key) {
        Some(last_logged) => now.duration_since(*last_logged) > Duration::from_secs(10),
        None => true,
    };
    
    if should_log {
        tracing::warn!("{}", msg);
        map.insert(key.to_string(), now);
    }
}
