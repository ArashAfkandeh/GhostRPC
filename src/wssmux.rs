//! WssMux transport: WebSocket over TLS (HTTP/1.1 upgrade) carrying a yamux multiplexer.
//!
//! It is the second wire protocol next to HTTP/2 (gRPC) and is used by BOTH tunnel kinds:
//!
//!   Direct : client (Iran)   --WSS--> server (abroad)   client opens yamux sub-streams
//!   Reverse: server (abroad) --WSS--> client (Iran)     client STILL opens the sub-streams
//!
//! In both kinds the Iran client is the one that owns the user connection, so it is always the
//! side that OPENS a yamux sub-stream; the abroad server always ACCEPTS it and connects to the target.
//! (yamux is symmetric, so which side dialed the WebSocket does not matter.)
//!
//! Wire format of one tunnel sub-stream:
//!   opener  -> acceptor : [len u16 BE]["<target>\n<try_local 0|1>"]
//!   acceptor-> opener   : [1] connected  /  [0] failed
//!   then raw bytes in both directions (yamux half-close = EOF).
//!
//! The TLS layer advertises ALPN `http/1.1` (WebSocket needs HTTP/1.1), which is also how the
//! server tells a WssMux connection from an HTTP/2 one on the very same port.
//! Authentication is the same as the HTTP/2 tunnel: `hidden_path` + `x-tunnel-secret`.

use bytes::Bytes;
use futures::{Sink, Stream};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config, client_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use tokio_util::{
    compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt},
    sync::CancellationToken,
};
use tracing::{debug};
use yamux::{Config as YamuxConfig, Connection, Control, Mode};

/// One tunnel sub-stream (a yamux stream adapted to tokio's I/O traits).
pub type MuxStream = Compat<yamux::Stream>;

const MAX_WS_CHUNK: usize = 64 * 1024;
const PING_EVERY: Duration = Duration::from_secs(15);
const DEAD_AFTER: Duration = Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const ACK_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_REQUEST: usize = 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

// ==========================================================================
// WebSocket <-> byte stream adapter (with keep-alive + dead-peer detection)
// ==========================================================================

/// Presents a `WebSocketStream` as a plain byte stream (one binary message per write).
/// A WebSocket ping is sent every `PING_EVERY` (keeps CDNs / NATs from timing the connection
/// out); if nothing at all is received for `DEAD_AFTER` the connection is reported dead.
pub struct WsIo<S> {
    ws: WebSocketStream<S>,
    rbuf: Bytes,
    ping: tokio::time::Interval,
    ping_due: bool,
    last_rx: tokio::time::Instant,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsIo<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        let mut ping = tokio::time::interval(PING_EVERY);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            ws,
            rbuf: Bytes::new(),
            ping,
            ping_due: false,
            last_rx: tokio::time::Instant::now(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            while this.ping.poll_tick(cx).is_ready() {
                if this.last_rx.elapsed() > DEAD_AFTER {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "wssmux peer silent",
                    )));
                }
                this.ping_due = true;
            }
            if this.ping_due {
                if let Poll::Ready(Ok(())) = Pin::new(&mut this.ws).poll_ready(cx) {
                    if Pin::new(&mut this.ws)
                        .start_send(Message::Ping(Vec::new()))
                        .is_ok()
                    {
                        this.ping_due = false;
                    }
                    let _ = Pin::new(&mut this.ws).poll_flush(cx);
                }
            }
            if !this.rbuf.is_empty() {
                let n = this.rbuf.len().min(out.remaining());
                out.put_slice(&this.rbuf.split_to(n));
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.ws).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    this.last_rx = tokio::time::Instant::now();
                    match msg {
                        Message::Binary(b) => this.rbuf = Bytes::from(b),
                        Message::Close(_) => return Poll::Ready(Ok(())),
                        // tungstenite queues the Pong itself; make sure it gets flushed.
                        Message::Ping(_) => {
                            let _ = Pin::new(&mut this.ws).poll_flush(cx);
                        }
                        _ => {}
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    use tokio_tungstenite::tungstenite::Error as E;
                    return match e {
                        E::ConnectionClosed | E::AlreadyClosed => Poll::Ready(Ok(())),
                        e => Poll::Ready(Err(io_err(e))),
                    };
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.ws).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io_err(e))),
            Poll::Pending => return Poll::Pending,
        }
        let n = buf.len().min(MAX_WS_CHUNK);
        if let Err(e) = Pin::new(&mut this.ws).start_send(Message::Binary(buf[..n].to_vec())) {
            return Poll::Ready(Err(io_err(e)));
        }
        let _ = Pin::new(&mut this.ws).poll_flush(cx);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws).poll_flush(cx).map_err(io_err)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws).poll_close(cx).map_err(io_err)
    }
}

fn ws_config() -> WebSocketConfig {
    let mut c = WebSocketConfig::default();
    c.max_message_size = Some(4 * 1024 * 1024);
    c.max_frame_size = Some(4 * 1024 * 1024);
    c
}

fn yamux_config() -> YamuxConfig {
    let mut c = YamuxConfig::default();
    // Defaults (256 KiB) cap a single stream at ~1 MB/s on a 200 ms path; the HTTP/2 tunnel uses
    // 8 MB windows for the same reason.
    c.set_receive_window(8 * 1024 * 1024);
    c.set_max_buffer_size(16 * 1024 * 1024);
    c.set_split_send_size(32 * 1024);
    c
}

// ==========================================================================
// Session handle + driver
// ==========================================================================

/// Handle to one live WssMux session (one WebSocket connection = one yamux connection).
#[derive(Clone)]
pub struct MuxClient {
    pub control: Control,
    pub dead: CancellationToken,
    /// Keeps an opener-only session alive; the driver closes the session once every handle is gone.
    _lease: Option<Arc<()>>,
}

impl MuxClient {
    pub fn alive(&self) -> bool {
        !self.dead.is_cancelled()
    }

    /// Opens a tunnel to `target` over this session (see the module docs for the wire format).
    pub async fn open_tunnel(&self, target: &str, try_local: bool) -> Result<MuxStream, ()> {
        let mut ctl = self.control.clone();
        let st = match tokio::time::timeout(OPEN_TIMEOUT, ctl.open_stream()).await {
            Ok(Ok(s)) => s,
            _ => {
                // The session cannot open streams any more: report it dead so it gets replaced.
                self.dead.cancel();
                return Err(());
            }
        };
        let mut st = st.compat();
        let payload = format!("{}\n{}", target, if try_local { "1" } else { "0" });
        let mut req = Vec::with_capacity(2 + payload.len());
        req.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        req.extend_from_slice(payload.as_bytes());
        let res = tokio::time::timeout(ACK_TIMEOUT, async {
            st.write_all(&req).await?;
            st.flush().await?;
            let mut ack = [0u8; 1];
            st.read_exact(&mut ack).await?;
            Ok::<u8, io::Error>(ack[0])
        })
        .await;
        match res {
            Ok(Ok(1)) => Ok(st),
            Ok(Ok(0)) => Err(()),
            _ => {
                self.dead.cancel();
                Err(())
            }
        }
    }
}

/// How a session reacts to sub-streams opened by the remote side.
struct SessionOpts {
    /// Some(bind_port): serve inbound tunnel requests (abroad server side). None: opener only.
    accept_with_bind_port: Option<String>,
    /// Opener-only sessions are closed once nobody holds a `MuxClient` any more.
    lease: Option<Weak<()>>,
    /// When cancelled (hot-reload) an accepting session drains and closes once idle.
    drain_on: Option<CancellationToken>,
}

static ACTIVE_ACCEPTED: AtomicUsize = AtomicUsize::new(0);

fn start_session<S>(
    ws: WebSocketStream<S>,
    mode: Mode,
    opts: SessionOpts,
    lease_arc: Option<Arc<()>>,
) -> MuxClient
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = WsIo::new(ws).compat();
    let mut conn = Connection::new(io, yamux_config(), mode);
    let control = conn.control();
    let dead = CancellationToken::new();

    // Driver: must be polled to completion (yamux requirement), so it is never cancelled.
    {
        let dead = dead.clone();
        let accept = opts.accept_with_bind_port.clone();
        tokio::spawn(async move {
            loop {
                match conn.next_stream().await {
                    Ok(Some(st)) => match &accept {
                        Some(bp) => {
                            let bp = bp.clone();
                            tokio::spawn(async move {
                                ACTIVE_ACCEPTED.fetch_add(1, Ordering::Relaxed);
                                serve_stream(st.compat(), &bp).await;
                                ACTIVE_ACCEPTED.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        None => drop(st), // we never expect remote-opened streams here
                    },
                    Ok(None) => break,
                    Err(e) => {
                        debug!("WssMux session ended: {}", e);
                        break;
                    }
                }
            }
            dead.cancel();
        });
    }

    // Watcher: idle-close for opener sessions, drain-close on hot-reload for accepting ones.
    if opts.lease.is_some() || opts.drain_on.is_some() {
        let mut ctl = control.clone();
        let dead = dead.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = dead.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(3)) => {}
                }
                let orphaned = opts.lease.as_ref().map_or(false, |w| w.strong_count() == 0);
                let draining = opts.drain_on.as_ref().map_or(false, |t| t.is_cancelled());
                if (orphaned || draining) && ACTIVE_ACCEPTED.load(Ordering::Relaxed) == 0 {
                    let _ = ctl.close().await;
                    return;
                }
            }
        });
    }

    MuxClient {
        control,
        dead,
        _lease: lease_arc,
    }
}

// ==========================================================================
// ACCEPTING SIDE: serve one tunnel sub-stream (abroad server, Direct and Reverse)
// ==========================================================================

/// Same target semantics as the HTTP/2 paths (loop protection, circuit breaker, try_local):
/// the request is resolved by `reverse::connect_target`, which mirrors the Direct server logic.
async fn serve_stream(mut st: MuxStream, bind_port: &str) {
    let req = tokio::time::timeout(ACK_TIMEOUT, async {
        let mut len = [0u8; 2];
        st.read_exact(&mut len).await?;
        let len = u16::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_REQUEST {
            return Err(io_err("bad request length"));
        }
        let mut payload = vec![0u8; len];
        st.read_exact(&mut payload).await?;
        Ok(payload)
    })
    .await;
    let payload = match req {
        Ok(Ok(p)) => String::from_utf8_lossy(&p).to_string(),
        _ => return,
    };
    let (target, tl) = payload.split_once('\n').unwrap_or((payload.as_str(), "0"));
    let tcp = match crate::reverse::connect_target(target.to_string(), tl == "1", bind_port).await {
        Ok(t) => t,
        Err(()) => {
            let _ = st.write_all(&[0]).await;
            let _ = st.shutdown().await;
            return;
        }
    };
    if st.write_all(&[1]).await.is_err() || st.flush().await.is_err() {
        return;
    }
    let mut tcp = tcp;
    let _stream_guard = crate::metrics::open_stream("tunnel", "wssmux", "-", target);
    let mut st = crate::metrics::Counted::new(st);
    let _ = tokio::io::copy_bidirectional_with_sizes(&mut st, &mut tcp, 64 * 1024, 64 * 1024).await;
}

// ==========================================================================
// OPENING SIDE: pipe a user connection into a tunnel sub-stream (Iran client)
// ==========================================================================

/// Sends `initial` (bytes already read from the user) and then pipes both directions until done.
pub async fn pipe_user(
    local_read: OwnedReadHalf,
    local_write: OwnedWriteHalf,
    initial: &[u8],
    st: MuxStream,
) {
    let Ok(mut local) = local_read.reunite(local_write) else {
        return;
    };
    let mut st = crate::metrics::Counted::new(st);
    if !initial.is_empty() && st.write_all(initial).await.is_err() {
        return;
    }
    let _ =
        tokio::io::copy_bidirectional_with_sizes(&mut local, &mut st, 64 * 1024, 64 * 1024).await;
}

// ==========================================================================
// DIALING SIDE
// ==========================================================================

fn connector() -> &'static TlsConnector {
    static C: OnceLock<TlsConnector> = OnceLock::new();
    C.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // WebSocket needs HTTP/1.1; the server uses this ALPN to tell WssMux from HTTP/2.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsConnector::from(Arc::new(cfg))
    })
}

/// "domain:port" -> (domain, port); a missing/invalid port gives `default_port`.
fn split_sni(sni: &str, default_port: &str) -> (String, String) {
    match sni.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() && !h.contains(':') => {
            (h.to_string(), p.to_string())
        }
        _ => (sni.to_string(), default_port.to_string()),
    }
}

/// Races TCP connections to all candidate addresses; the first to connect wins.
async fn race_tcp(addrs: Vec<String>) -> Result<tokio::net::TcpStream, String> {
    use futures::stream::{FuturesUnordered, StreamExt};
    let mut tasks = FuturesUnordered::new();
    for addr in addrs {
        tasks.push(async move {
            let resolved = tokio::net::lookup_host(&addr)
                .await
                .map_err(|e| e.to_string())?
                .collect::<Vec<_>>();
            for a in resolved {
                if let Ok(s) = crate::anti_loop::safe_connect(a, Duration::from_secs(5)).await {
                    return Ok::<_, String>(s);
                }
            }
            Err("connect failed".to_string())
        });
    }
    while let Some(res) = tasks.next().await {
        if let Ok(s) = res {
            return Ok(s);
        }
    }
    Err("All TCP connection attempts (Racing) failed".to_string())
}

/// Builds a WebSocket client request. `IntoClientRequest` adds the mandatory handshake headers
/// (Host, Upgrade, Connection, Sec-WebSocket-Key/Version); a hand-built `http::Request` would be
/// rejected by tungstenite for lacking them.
fn ws_request(
    url: &str,
    headers: &[(&str, &str)],
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request, String> {
    use tokio_tungstenite::tungstenite::{
        client::IntoClientRequest,
        http::{HeaderName, HeaderValue},
    };
    let mut req = url.into_client_request().map_err(|e| e.to_string())?;
    for (k, v) in headers {
        let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| e.to_string())?;
        let val = HeaderValue::from_str(v).map_err(|e| e.to_string())?;
        req.headers_mut().insert(name, val);
    }
    Ok(req)
}

/// TLS (SNI = `sni_host`) + WebSocket upgrade on `hidden_path` (secret / location as headers).
async fn dial_ws(
    tcp: tokio::net::TcpStream,
    sni_host_port: &str,
    sni_host: &str,
    hidden_path: &str,
    secret: &str,
    location: Option<&str>,
) -> Result<WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>, String> {
    let _ = tcp.set_nodelay(true);
    crate::net_utils::enable_tcp_bbr(&tcp);
    crate::net_utils::tune_socket_buffers(&tcp);
    crate::net_utils::enable_tcp_keepalive(&tcp);
    let name = rustls::pki_types::ServerName::try_from(sni_host.to_string())
        .map_err(|e| e.to_string())?
        .to_owned();
    let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector().connect(name, tcp))
        .await
        .map_err(|_| "tls handshake timed out".to_string())?
        .map_err(|e| format!("tls handshake failed: {}", e))?;
    if tls.get_ref().1.alpn_protocol() != Some(b"http/1.1".as_slice()) {
        return Err(
            "server did not negotiate http/1.1 (WssMux unavailable on this endpoint)".to_string(),
        );
    }
    let ua = crate::net_utils::get_random_headers()
        .into_iter()
        .find(|(k, _)| *k == "user-agent")
        .map(|(_, v)| v)
        .unwrap_or("Mozilla/5.0");
    let mut hdrs: Vec<(&str, &str)> = vec![("user-agent", ua), ("x-tunnel-secret", secret)];
    if let Some(l) = location {
        hdrs.push(("x-tunnel-location", l));
    }
    let req = ws_request(&format!("wss://{}{}", sni_host_port, hidden_path), &hdrs)?;
    let (ws, resp) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        client_async_with_config(req, tls, Some(ws_config())),
    )
    .await
    .map_err(|_| "websocket handshake timed out".to_string())?
    .map_err(|e| format!("websocket handshake failed: {}", e))?;
    debug!("WssMux upgrade answered {}", resp.status());
    Ok(ws)
}

/// Proves that WebSocket frames really travel through the whole path (client -> CDN -> origin and
/// back) before the session is used: sends a Ping and waits for the matching Pong.
///
/// A CDN / middlebox can happily answer the HTTP upgrade with `101` and then never forward a
/// single frame; such a session looks alive but every tunnel opened on it stalls until the ACK
/// timeout. Only used on Direct sessions, where the server never sends yamux data first.
async fn probe_ws<S>(ws: &mut WebSocketStream<S>) -> Result<Duration, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use futures::{SinkExt, StreamExt};
    let t0 = tokio::time::Instant::now();
    let token: Vec<u8> = rand::random::<u64>().to_be_bytes().to_vec();
    let res = tokio::time::timeout(PROBE_TIMEOUT, async {
        ws.send(Message::Ping(token.clone()))
            .await
            .map_err(|e| e.to_string())?;
        loop {
            match ws.next().await {
                Some(Ok(Message::Pong(p))) if p == token => return Ok::<(), String>(()),
                Some(Ok(Message::Close(_))) | None => return Err("closed by the peer".to_string()),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e.to_string()),
            }
        }
    })
    .await;
    match res {
        Ok(Ok(())) => Ok(t0.elapsed()),
        Ok(Err(e)) => Err(format!("ws probe failed: {}", e)),
        Err(_) => Err(format!(
            "ws probe timed out: upgrade succeeded but no frame came back within {}s (CDN/path does not forward WebSocket frames)",
            PROBE_TIMEOUT.as_secs()
        )),
    }
}

/// IP scanner health check: the full tunnel handshake (TLS with ALPN http/1.1, WebSocket upgrade,
/// authentication, and Ping/Pong) over an already connected `tcp`.
pub async fn probe_endpoint_with_location(
    tcp: tokio::net::TcpStream,
    sni_host_port: &str,
    sni_host: &str,
    hidden_path: &str,
    secret: &str,
    location: Option<&str>,
) -> Result<Duration, String> {
    let mut ws =
        dial_ws(tcp, sni_host_port, sni_host, hidden_path, secret, location).await?;
    let res = probe_ws(&mut ws).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), ws.close(None)).await;
    res
}

/// Direct mode (Iran client): dials `node_sni` through the clean IPs and returns an opener session.
pub async fn connect_direct(
    node_sni: &str,
    clean_ips: &[String],
    hidden_path: &str,
    secret: &str,
) -> Result<MuxClient, String> {
    let (host, port) = split_sni(node_sni, "443");
    let addrs: Vec<String> = clean_ips
        .iter()
        .map(|ip| {
            if ip.contains(':') && !ip.starts_with('[') {
                if ip.split(':').count() > 2 {
                    format!("[{}]:{}", ip, port)
                } else {
                    ip.to_string()
                }
            } else {
                format!("{}:{}", ip, port)
            }
        })
        .collect();
    let tcp = race_tcp(addrs).await?;
    let mut ws = dial_ws(tcp, node_sni, &host, hidden_path, secret, None).await?;
    match probe_ws(&mut ws).await {
        Ok(rtt) => debug!(
            "WssMux Direct path to {} verified (ping/pong {}ms)",
            node_sni,
            rtt.as_millis()
        ),
        Err(e) => {
            return Err(e);
        }
    }
    let lease = Arc::new(());
    let opts = SessionOpts {
        accept_with_bind_port: None,
        lease: Some(Arc::downgrade(&lease)),
        drain_on: None,
    };
    Ok(start_session(ws, Mode::Client, opts, Some(lease)))
}

/// Parameters of one reverse dial (abroad server -> Iran client).
pub struct ReverseDial<'a> {
    pub addrs: &'a [String],
    pub sni: &'a str,
    pub location: Option<&'a str>,
    pub secret: &'a str,
    pub hidden_path: &'a str,
    pub bind_port: &'a str,
}

/// Reverse mode (abroad server): dials the Iran client and serves the tunnels it opens.
/// The returned handle's `dead` token fires when the session ends.
pub async fn dial_reverse(
    d: &ReverseDial<'_>,
    drain_on: CancellationToken,
) -> Result<MuxClient, String> {
    let tcp = race_tcp(d.addrs.to_vec()).await?;
    let ws = dial_ws(tcp, d.sni, d.sni, d.hidden_path, d.secret, d.location).await?;
    let opts = SessionOpts {
        accept_with_bind_port: Some(d.bind_port.to_string()),
        lease: None,
        drain_on: Some(drain_on),
    };
    Ok(start_session(ws, Mode::Client, opts, None))
}

// ==========================================================================
// LISTENING SIDE
// ==========================================================================

async fn accept_ws<S>(
    stream: S,
    peer: std::net::SocketAddr,
    hidden_path: &str,
    secret: &str,
    location_out: Option<Arc<std::sync::Mutex<String>>>,
) -> Option<WebSocketStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    let hp = hidden_path.to_string();
    let sec = secret.to_string();
    let cb = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let authed = req.uri().path() == hp
            && req
                .headers()
                .get("x-tunnel-secret")
                .and_then(|h| h.to_str().ok())
                .map_or(false, |s| ct_eq(s.as_bytes(), sec.as_bytes()));
        if !authed {
            let mut r = ErrorResponse::new(None);
            *r.status_mut() = http::StatusCode::NOT_FOUND;
            return Err(r);
        }
        if let (Some(out), Some(l)) = (
            &location_out,
            req.headers()
                .get("x-tunnel-location")
                .and_then(|h| h.to_str().ok()),
        ) {
            *out.lock().unwrap() = l.to_string();
        }
        Ok(resp)
    };
    match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        accept_hdr_async_with_config(stream, cb, Some(ws_config())),
    )
    .await
    {
        Ok(Ok(ws)) => Some(ws),
        Ok(Err(e)) => {
            crate::net_utils::log_rate_limited(
                &format!("wss_auth_{}", peer.ip()),
                &format!("🔒 WssMux request from {} rejected ({})", peer, e),
            );
            None
        }
        Err(_) => {
            debug!("WssMux upgrade from {} timed out", peer);
            None
        }
    }
}

/// Direct mode, server side: a TLS connection that negotiated `http/1.1` on the tunnel port.
pub async fn serve_direct<S>(
    stream: S,
    peer: std::net::SocketAddr,
    hidden_path: &str,
    secret: &str,
    bind_port: &str,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(ws) = accept_ws(stream, peer, hidden_path, secret, None).await else {
        return;
    };
    debug!("🔌 WssMux (Direct) session from {}", peer);
    let opts = SessionOpts {
        accept_with_bind_port: Some(bind_port.to_string()),
        lease: None,
        drain_on: None,
    };
    let session = start_session(ws, Mode::Server, opts, None);
    session.dead.cancelled().await;
}

/// Reverse mode, client side: the abroad server dialed in over WssMux. The session is registered
/// with the reverse registry (so user connections can use it) until it dies.
pub async fn serve_reverse<S>(
    stream: S,
    peer: std::net::SocketAddr,
    hidden_path: &str,
    secret: &str,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let loc = Arc::new(std::sync::Mutex::new(String::new()));
    let Some(ws) = accept_ws(stream, peer, hidden_path, secret, Some(loc.clone())).await else {
        return;
    };
    let mut location = loc.lock().unwrap().clone();
    if !location.is_empty() && !crate::reverse::is_known_location(&location) {
        location.clear(); // an unknown label simply means "unlabeled" (same as the HTTP/2 path)
    }
    let opts = SessionOpts {
        accept_with_bind_port: None,
        lease: None,
        drain_on: None,
    };
    let session = start_session(ws, Mode::Server, opts, None);
    debug!(
        "🔁 Reverse WssMux session from {} registered{}",
        peer,
        if location.is_empty() {
            String::new()
        } else {
            format!(" (location '{}')", location)
        }
    );
    let id = crate::reverse::register_ws_session(&location, session.clone());
    session.dead.cancelled().await;
    crate::reverse::remove_ws_session(&location, id);
    debug!("🔁 Reverse WssMux session from {} closed", peer);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    /// End-to-end over loopback (no TLS): WebSocket + yamux + target connect + ACK + data.
    async fn pair() -> (MuxClient, tokio::task::JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (tcp, peer) = l.accept().await.unwrap();
            serve_direct(tcp, peer, "/p", "sekret", "1").await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let req = ws_request(
            &format!("ws://{}/p", addr),
            &[("x-tunnel-secret", "sekret")],
        )
        .unwrap();
        let (ws, _) = client_async_with_config(req, tcp, Some(ws_config()))
            .await
            .unwrap();
        let lease = Arc::new(());
        let opts = SessionOpts {
            accept_with_bind_port: None,
            lease: Some(Arc::downgrade(&lease)),
            drain_on: None,
        };
        (start_session(ws, Mode::Client, opts, Some(lease)), srv)
    }

    #[tokio::test]
    async fn tunnel_roundtrip_and_failures() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = echo.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&b[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let (client, _srv) = pair().await;
        // two concurrent tunnels share one session; payload bigger than any single frame/window chunk
        let mut handles = Vec::new();
        for i in 0..2u8 {
            let c = client.clone();
            handles.push(tokio::spawn(async move {
                let st = c
                    .open_tunnel(&format!("127.0.0.1:{}", echo_port), true)
                    .await
                    .expect("open");
                let data: Vec<u8> = (0..300_000u32).map(|x| (x as u8).wrapping_add(i)).collect();
                let d2 = data.clone();
                let (mut r, mut w) = tokio::io::split(st);
                let writer = tokio::spawn(async move {
                    w.write_all(&d2).await.unwrap();
                    w.flush().await.unwrap();
                    w
                });
                let mut got = vec![0u8; data.len()];
                r.read_exact(&mut got).await.unwrap();
                assert_eq!(got, data);
                let _ = writer.await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // a dead target is reported through the ACK byte (and the session survives)
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        assert!(
            client
                .open_tunnel(&format!("127.0.0.1:{}", closed_port), true)
                .await
                .is_err()
        );
        assert!(client.alive());
        assert!(
            client
                .open_tunnel(&format!("127.0.0.1:{}", echo_port), true)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn wrong_secret_is_rejected() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, peer) = l.accept().await.unwrap();
            serve_direct(tcp, peer, "/p", "sekret", "1").await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        // A well-formed upgrade request with a wrong secret must be refused by the server (404),
        // not merely fail locally because of a malformed request.
        let req = ws_request(&format!("ws://{}/p", addr), &[("x-tunnel-secret", "WRONG")]).unwrap();
        let err = client_async_with_config(req, tcp, Some(ws_config()))
            .await
            .err()
            .expect("must be rejected");
        assert!(
            matches!(&err, tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 404),
            "expected an HTTP 404 refusal, got: {err}"
        );
    }

    #[test]
    fn sni_split() {
        assert_eq!(
            split_sni("a.example.com:2083", "443"),
            ("a.example.com".into(), "2083".into())
        );
        assert_eq!(
            split_sni("a.example.com", "443"),
            ("a.example.com".into(), "443".into())
        );
    }
}
