//! Reverse tunnel (works simultaneously with Direct, and works THROUGH a CDN such as Cloudflare).
//!
//! Direct : client (Iran)  --HTTP/2 POST streams--> server (abroad)   [server connects to targets]
//! Reverse: server (abroad) --HTTP/2 POST streams--> client (Iran)    [server STILL connects to targets]
//!
//! The abroad server is always the HTTP/2 *client* here, exactly like the Iran client is in Direct
//! mode, so everything on the wire is ordinary HTTPS + HTTP/2 gRPC-style streaming. A CDN in front
//! of the Iran VPS therefore handles it the same way it handles the Direct tunnel.
//!
//! Protocol (frames use the same 5-byte gRPC header as the Direct tunnel: [flag u8][len u32 BE]):
//!   1. server opens N "parked" streams:  POST <hidden_path>, headers x-tunnel-secret / x-tunnel-location.
//!   2. client answers 200 at once and keeps the stream idle (empty keep-alive frames every 20 s so
//!      that intermediaries do not time it out).
//!   3. when a local user connects, the client picks a parked stream and sends an ASSIGN frame
//!      (flag 1, payload "target\n<try_local 0|1>"). The server connects to the target and answers with
//!      an ACK frame (flag 2, payload [1] ok / [0] failed). On ok both sides pipe data frames (flag 0).
//!   4. the server immediately parks a replacement stream.

use crate::config::{ClientConfig, ServerConfig};
use crate::transport::Proto;
use bytes::{Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const FLAG_DATA: u8 = 0;
const FLAG_ASSIGN: u8 = 1;
const FLAG_ACK: u8 = 2;
const MAX_FRAME: usize = 1_048_576;
const PARKED_PER_CONN: usize = 4;
const KEEPALIVE_SECS: u64 = 20;

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

fn frame(flag: u8, payload: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(5 + payload.len());
    b.extend_from_slice(&[flag]);
    b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    b.extend_from_slice(payload);
    b.freeze()
}

/// Pops one complete frame from `buf`. Ok(None) = need more data, Err = protocol violation.
fn pop_frame(buf: &mut BytesMut) -> Result<Option<(u8, Bytes)>, ()> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > MAX_FRAME {
        return Err(());
    }
    if buf.len() < 5 + len {
        return Ok(None);
    }
    let flag = buf[0];
    let _ = buf.split_to(5);
    let payload = buf.split_to(len).freeze();
    Ok(Some((flag, payload)))
}

// ==========================================================================
// CLIENT SIDE (Iran): accepts HTTP/2 connections, keeps parked streams
// ==========================================================================

pub struct ReverseCtx {
    acceptor: TlsAcceptor,
    secret: String,
    hidden_path: String,
    max_parked: usize,
    sni_patterns: Vec<String>,
    /// Protocol priority (`[client].protocols`): which of h2 / WssMux this client accepts, and which
    /// one is tried first when both are available for a user connection.
    protocols: Vec<Proto>,
    pub bind: Option<String>,
}

static CTX: OnceLock<RwLock<Option<Arc<ReverseCtx>>>> = OnceLock::new();
static LOCATIONS: OnceLock<RwLock<HashMap<String, u32>>> = OnceLock::new();
static LOC_EWMA: OnceLock<Mutex<HashMap<String, f64>>> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

struct Parked {
    id: u64,
    take: oneshot::Sender<oneshot::Sender<(SendStream<Bytes>, RecvStream)>>,
}
static PARKED: OnceLock<Mutex<HashMap<String, VecDeque<Parked>>>> = OnceLock::new();

/// Reverse tunnels that were dialed in over WssMux (one yamux session each), by location label.
struct WsSession {
    id: u64,
    mux: crate::wssmux::MuxClient,
}
static WS_SESSIONS: OnceLock<Mutex<HashMap<String, Vec<WsSession>>>> = OnceLock::new();
static WS_RR: AtomicUsize = AtomicUsize::new(0);

fn ws_sessions() -> &'static Mutex<HashMap<String, Vec<WsSession>>> {
    WS_SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// True when `loc` is a `[[client.remotes]]` location (an unknown label means "unlabeled").
pub fn is_known_location(loc: &str) -> bool {
    locations().read().unwrap().contains_key(loc)
}

pub fn register_ws_session(location: &str, mux: crate::wssmux::MuxClient) -> u64 {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    ws_sessions()
        .lock()
        .unwrap()
        .entry(location.to_string())
        .or_default()
        .push(WsSession { id, mux });
    id
}

pub fn remove_ws_session(location: &str, id: u64) {
    let mut m = ws_sessions().lock().unwrap();
    if let Some(v) = m.get_mut(location) {
        v.retain(|s| s.id != id);
    }
}

/// Picks a live WssMux session of `location` (round-robin) and prunes dead ones.
fn pick_ws(location: &str) -> Option<crate::wssmux::MuxClient> {
    let mut m = ws_sessions().lock().unwrap();
    let v = m.get_mut(location)?;
    v.retain(|s| s.mux.alive());
    if v.is_empty() {
        return None;
    }
    let i = WS_RR.fetch_add(1, Ordering::Relaxed) % v.len();
    Some(v[i].mux.clone())
}

fn ctx_cell() -> &'static RwLock<Option<Arc<ReverseCtx>>> {
    CTX.get_or_init(|| RwLock::new(None))
}
fn locations() -> &'static RwLock<HashMap<String, u32>> {
    LOCATIONS.get_or_init(|| RwLock::new(HashMap::new()))
}
fn ewma_map() -> &'static Mutex<HashMap<String, f64>> {
    LOC_EWMA.get_or_init(|| Mutex::new(HashMap::new()))
}
fn parked() -> &'static Mutex<HashMap<String, VecDeque<Parked>>> {
    PARKED.get_or_init(|| Mutex::new(HashMap::new()))
}
fn current_ctx() -> Option<Arc<ReverseCtx>> {
    ctx_cell().read().unwrap().clone()
}

/// Called by `run_client` on every (re)load.
pub fn set_known_locations(map: HashMap<String, u32>) {
    *locations().write().unwrap() = map;
}

fn load_cert_dir() -> HashMap<String, Arc<rustls::sign::CertifiedKey>> {
    let mut map = HashMap::new();
    let exe_dir = std::env::current_exe()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
        .parent()
        .unwrap_or(std::path::Path::new(""))
        .to_path_buf();
    let Ok(entries) = std::fs::read_dir(exe_dir.join("certs")) else {
        return map;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let domain = entry.file_name().to_string_lossy().to_string();
        let (Ok(cf), Ok(kf)) = (
            std::fs::File::open(entry.path().join("fullchain.pem")),
            std::fs::File::open(entry.path().join("privkey.pem")),
        ) else {
            continue;
        };
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cf))
            .filter_map(|r| r.ok())
            .collect();
        let Ok(Some(key)) = rustls_pemfile::private_key(&mut std::io::BufReader::new(kf)) else {
            continue;
        };
        let Ok(sign_key) = rustls::crypto::ring::sign::any_supported_type(&key) else {
            continue;
        };
        let ck = Arc::new(rustls::sign::CertifiedKey::new(certs, sign_key));
        map.insert(domain.clone(), ck.clone());
        map.insert(format!("*.{}", domain), ck);
    }
    map
}

fn self_signed() -> Result<Arc<rustls::sign::CertifiedKey>, String> {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| e.to_string())?;
    let sign_key =
        rustls::crypto::ring::sign::any_supported_type(&key_der).map_err(|e| e.to_string())?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(
        vec![cert.der().clone()],
        sign_key,
    )))
}

/// Real certificate from `certs/` (e.g. issued by the built-in ACME; required for Cloudflare
/// "Full (strict)") when the SNI matches, otherwise a self-signed one (fine for "Full").
#[derive(Debug)]
struct ReverseCertResolver {
    certs: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    fallback: Arc<rustls::sign::CertifiedKey>,
}
impl rustls::server::ResolvesServerCert for ReverseCertResolver {
    fn resolve(
        &self,
        ch: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(sni) = ch.server_name() {
            if let Some(c) = self.certs.get(sni) {
                return Some(c.clone());
            }
            if let Some(idx) = sni.find('.') {
                if let Some(c) = self.certs.get(&format!("*{}", &sni[idx..])) {
                    return Some(c.clone());
                }
            }
        }
        Some(self.fallback.clone())
    }
}

/// Builds the reverse context from the client config and publishes it. None = disabled.
pub fn configure(cfg: &ClientConfig) -> Option<Arc<ReverseCtx>> {
    let bind = cfg
        .reverse_bind_addr
        .as_ref()
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty());
    let sni_patterns: Vec<String> = cfg
        .reverse_tunnel_sni
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let set = |v: Option<Arc<ReverseCtx>>| {
        *ctx_cell().write().unwrap() = v;
    };
    if bind.is_none() && sni_patterns.is_empty() {
        set(None);
        return None;
    }
    let secret = cfg.secret.clone().unwrap_or_default();
    if secret.is_empty() {
        tracing::error!("❌ Reverse disabled: [client].secret must be set.");
        set(None);
        return None;
    }
    let fallback = match self_signed() {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("❌ Reverse: TLS setup failed: {}", e);
            set(None);
            return None;
        }
    };
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ReverseCertResolver {
            certs: load_cert_dir(),
            fallback,
        }));
    // Same ALPN list as the Direct server acceptor (server.rs): h2 first, http/1.1 as fallback.
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let ctx = Arc::new(ReverseCtx {
        acceptor: TlsAcceptor::from(Arc::new(tls)),
        secret,
        hidden_path: cfg.hidden_path.clone(),
        // Same default philosophy as Direct (pool_size_per_node = 8): no config needed.
        max_parked: cfg.pool_size_per_node.unwrap_or(8).max(1) * 16,
        sni_patterns,
        protocols: crate::transport::parse_list(cfg.protocols.as_ref(), "client"),
        bind,
    });
    set(Some(ctx.clone()));
    Some(ctx)
}

/// True when `sni` identifies a reverse tunnel (used to share a port with other client listeners).
pub fn sni_matches(sni: &str) -> bool {
    let Some(ctx) = current_ctx() else {
        return false;
    };
    let sni = sni.to_lowercase();
    ctx.sni_patterns.iter().any(|p| match p.strip_prefix("*.") {
        Some(rest) => sni.ends_with(&format!(".{}", rest)),
        None => *p == sni,
    })
}

/// True when at least one parked reverse stream is available (used by pool warm-up).
pub fn has_ready_slot() -> bool {
    parked().lock().unwrap().values().any(|q| !q.is_empty())
        || ws_sessions()
            .lock()
            .unwrap()
            .values()
            .any(|v| v.iter().any(|s| s.mux.alive()))
}

/// (key, share_sni, ewma_ms) of every parked-stream group that has an idle stream.
/// `share_sni` is None for unlabeled reverse tunnels (pure forwarders: usable for every target but
/// ranked behind the target's own location, and they never use `try_local`).
pub fn candidates() -> Vec<(String, Option<u32>, f64)> {
    let locs = locations().read().unwrap();
    let ew = ewma_map().lock().unwrap();
    let p = parked().lock().unwrap();
    let mut names: Vec<String> = p
        .iter()
        .filter(|(_, q)| !q.is_empty())
        .map(|(loc, _)| loc.clone())
        .collect();
    for (loc, v) in ws_sessions().lock().unwrap().iter() {
        if v.iter().any(|s| s.mux.alive()) && !names.contains(loc) {
            names.push(loc.clone());
        }
    }
    names
        .into_iter()
        .map(|loc| {
            let share = if loc.is_empty() {
                None
            } else {
                locs.get(&loc).copied()
            };
            let e = ew.get(&loc).copied().unwrap_or(300.0);
            (loc, share, e)
        })
        .collect()
}

fn remove_parked(location: &str, id: u64) {
    let mut p = parked().lock().unwrap();
    if let Some(q) = p.get_mut(location) {
        q.retain(|e| e.id != id);
    }
}

async fn take_stream(location: &str) -> Option<(SendStream<Bytes>, RecvStream)> {
    loop {
        let entry = {
            let mut p = parked().lock().unwrap();
            p.get_mut(location).and_then(|q| q.pop_back())
        };
        let entry = entry?;
        let (htx, hrx) = oneshot::channel();
        if entry.take.send(htx).is_err() {
            continue; // the parked stream died meanwhile
        }
        if let Ok(Ok(streams)) = tokio::time::timeout(Duration::from_secs(2), hrx).await {
            return Some(streams);
        }
    }
}

/// Takes a parked stream of `location`, tells the server which target to connect to and waits
/// for its ACK. Returns the streams plus any bytes received after the ACK frame.
pub async fn open_stream(
    location: &str,
    target: &str,
    try_local: bool,
) -> Result<(SendStream<Bytes>, RecvStream, Bytes), ()> {
    let (mut send, mut recv) = take_stream(location).await.ok_or(())?;
    let t0 = tokio::time::Instant::now();
    let payload = format!("{}\n{}", target, if try_local { "1" } else { "0" });
    crate::net_utils::send_h2_data(&mut send, frame(FLAG_ASSIGN, payload.as_bytes()), false)
        .await?;

    let mut buf = BytesMut::new();
    let ack = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match recv.data().await {
                Some(Ok(chunk)) => {
                    let _ = recv.flow_control().release_capacity(chunk.len());
                    buf.extend_from_slice(&chunk);
                    loop {
                        match pop_frame(&mut buf) {
                            Ok(Some((FLAG_ACK, p))) => return Some(p.first() == Some(&1)),
                            Ok(Some(_)) => continue,
                            Ok(None) => break,
                            Err(_) => return None,
                        }
                    }
                }
                _ => return None,
            }
        }
    })
    .await;

    let mut m = ewma_map().lock().unwrap();
    let e = m.entry(location.to_string()).or_insert(300.0);
    match ack {
        Ok(Some(true)) => {
            *e = 0.2 * (t0.elapsed().as_millis() as f64) + 0.8 * *e;
            Ok((send, recv, buf.freeze()))
        }
        _ => {
            *e += 5000.0;
            Err(())
        }
    }
}

/// A tunnel taken from the reverse side, whichever protocol the abroad server dialed in with.
pub enum ReverseConn {
    H2(SendStream<Bytes>, RecvStream, Bytes),
    Mux(crate::wssmux::MuxStream),
}

fn preferred_available_protocol(order: &[Proto], h2_ready: bool, wss_ready: bool) -> Option<Proto> {
    order.iter().copied().find(|proto| match proto {
        Proto::H2 => h2_ready,
        Proto::WssMux => wss_ready,
    })
}

/// Opens a tunnel over the highest-priority Reverse protocol that currently has a ready session.
/// Protocol fallback is left to the background dial managers, not repeated for every user request.
pub async fn open_any(location: &str, target: &str, try_local: bool) -> Result<ReverseConn, ()> {
    let order = current_ctx()
        .map(|c| c.protocols.clone())
        .unwrap_or_else(|| vec![Proto::H2, Proto::WssMux]);
    let h2_ready = parked()
        .lock()
        .unwrap()
        .get(location)
        .is_some_and(|q| !q.is_empty());
    let wss_ready = ws_sessions()
        .lock()
        .unwrap()
        .get(location)
        .is_some_and(|sessions| sessions.iter().any(|s| s.mux.alive()));
    let selected = preferred_available_protocol(&order, h2_ready, wss_ready);

    match selected {
        Some(Proto::H2) => {
            let (send, recv, leftover) = open_stream(location, target, try_local).await?;
            Ok(ReverseConn::H2(send, recv, leftover))
        }
        Some(Proto::WssMux) => {
            let mux = pick_ws(location).ok_or(())?;
            let t0 = tokio::time::Instant::now();
            let result = mux.open_tunnel(target, try_local).await;
            let mut ewma = ewma_map().lock().unwrap();
            let latency = ewma.entry(location.to_string()).or_insert(300.0);
            match result {
                Ok(stream) => {
                    *latency = 0.2 * (t0.elapsed().as_millis() as f64) + 0.8 * *latency;
                    Ok(ReverseConn::Mux(stream))
                }
                Err(()) => {
                    *latency += 5000.0;
                    Err(())
                }
            }
        }
        None => Err(()),
    }
}

/// Client side: dedicated listener for servers dialing in (only when not sharing a port).
pub async fn run_listener(ctx: Arc<ReverseCtx>, bind: String, cancel: CancellationToken) {
    let mut listener_opt = None;
    for i in 0..10 {
        match crate::net_utils::create_reuseport_listener(&bind) {
            Ok(l) => {
                listener_opt = Some(l);
                break;
            }
            Err(e) => {
                warn!(
                    "⚠️ Failed to bind reverse listener {} (attempt {}/10): {}. Retrying in 200ms...",
                    bind,
                    i + 1,
                    e
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    let Some(listener) = listener_opt else {
        tracing::error!("❌ Failed to bind reverse listener on {}", bind);
        return;
    };
    info!("🔁 Reverse tunnel listener active on {}", bind);
    let _ = ctx;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("🛑 Stopping reverse listener on {} due to Hot-Reload (established reverse tunnels stay alive)", bind);
                break;
            }
            res = listener.accept() => {
                let Ok((tcp, peer)) = res else { continue };
                if crate::anti_loop::is_loop(&peer) { continue; }
                let _ = tcp.set_nodelay(true);
                crate::net_utils::enable_tcp_bbr(&tcp);
                crate::net_utils::tune_socket_buffers(&tcp);
                crate::net_utils::enable_tcp_keepalive(&tcp);
                tokio::spawn(async move { handle_inbound(tcp, peer).await; });
            }
        }
    }
}

/// Handles one inbound connection (TLS + HTTP/2 server). `S` may be a PrefixedStream when the
/// port is shared with other client listeners.
pub async fn handle_inbound<S>(stream: S, peer: std::net::SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(ctx) = current_ctx() else { return };
    let tls = match tokio::time::timeout(Duration::from_secs(10), ctx.acceptor.accept(stream)).await
    {
        Ok(Ok(s)) => s,
        _ => return,
    };
    // Same dispatch rule as the Direct server: ALPN decides, and when a CDN negotiated no ALPN the
    // first decrypted bytes do (HTTP/2 preface = HTTP/2, otherwise a WebSocket upgrade).
    let Some((wire, tls)) = crate::transport::detect_wire(tls).await else {
        return;
    };
    if wire == crate::transport::Wire::WsMux {
        if ctx.protocols.contains(&Proto::WssMux) {
            crate::wssmux::serve_reverse(tls, peer, &ctx.hidden_path, &ctx.secret).await;
        }
        return;
    }
    if !ctx.protocols.contains(&Proto::H2) {
        return;
    }
    let mut h2 = match h2::server::Builder::new()
        .initial_window_size(8_388_608)
        .initial_connection_window_size(1_073_741_824)
        .max_frame_size(65_535)
        .max_concurrent_streams(2048)
        .handshake::<_, Bytes>(tls)
        .await
    {
        Ok(h) => h,
        Err(e) => {
            debug!("Reverse H2 handshake failed: {:?}", e);
            return;
        }
    };
    let announced = Arc::new(AtomicBool::new(false));
    while let Some(Ok((req, respond))) = h2.accept().await {
        let ctx = ctx.clone();
        let announced = announced.clone();
        tokio::spawn(async move {
            handle_park_request(req, respond, ctx, peer, announced).await;
        });
    }
}

async fn handle_park_request(
    req: http::Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    ctx: Arc<ReverseCtx>,
    peer: std::net::SocketAddr,
    announced: Arc<AtomicBool>,
) {
    let hdr = |n: &str| {
        req.headers()
            .get(n)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    };
    let mut location = hdr("x-tunnel-location").unwrap_or_default();
    let authed = req.uri().path() == ctx.hidden_path
        && hdr("x-tunnel-secret")
            .map(|s| ct_eq(s.as_bytes(), ctx.secret.as_bytes()))
            .unwrap_or(false);
    if !authed {
        crate::net_utils::log_rate_limited(
            &format!("rev_auth_{}", peer.ip()),
            &format!(
                "🔒 Reverse request from {} rejected (bad hidden_path or secret)",
                peer
            ),
        );
        let _ = respond.send_response(
            http::Response::builder().status(404).body(()).unwrap(),
            true,
        );
        return;
    }
    // A label is optional; an unknown one simply means "unlabeled".
    if !location.is_empty() && !locations().read().unwrap().contains_key(&location) {
        location.clear();
    }
    let total: usize = parked().lock().unwrap().values().map(|q| q.len()).sum();
    if total >= ctx.max_parked {
        let _ = respond.send_response(
            http::Response::builder().status(503).body(()).unwrap(),
            true,
        );
        return;
    }

    let mut rb = http::Response::builder().status(200);
    for (k, v) in crate::net_utils::get_random_headers() {
        rb = rb.header(k, v);
    }
    let mut send = match respond.send_response(rb.body(()).unwrap(), false) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut recv = req.into_body();

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let (take_tx, mut take_rx) = oneshot::channel();
    parked()
        .lock()
        .unwrap()
        .entry(location.clone())
        .or_default()
        .push_back(Parked { id, take: take_tx });
    if !announced.swap(true, Ordering::Relaxed) {
        info!(
            "🔁 Reverse tunnel connection from {} registered{}",
            peer,
            if location.is_empty() {
                String::new()
            } else {
                format!(" (location '{}')", location)
            }
        );
    }

    loop {
        enum Ev {
            Handoff(Result<oneshot::Sender<(SendStream<Bytes>, RecvStream)>, ()>),
            Tick,
            Closed,
            Chunk(usize),
        }
        let ev = tokio::select! {
            h = &mut take_rx => Ev::Handoff(h.map_err(|_| ())),
            _ = tokio::time::sleep(Duration::from_secs(KEEPALIVE_SECS)) => Ev::Tick,
            d = recv.data() => match d { Some(Ok(c)) => Ev::Chunk(c.len()), _ => Ev::Closed },
        };
        match ev {
            Ev::Handoff(Ok(htx)) => {
                let _ = htx.send((send, recv));
                return;
            }
            Ev::Handoff(Err(_)) => return,
            Ev::Tick => {
                if crate::net_utils::send_h2_data(&mut send, frame(FLAG_DATA, &[]), false)
                    .await
                    .is_err()
                {
                    remove_parked(&location, id);
                    return;
                }
            }
            Ev::Chunk(n) => {
                let _ = recv.flow_control().release_capacity(n);
            }
            Ev::Closed => {
                remove_parked(&location, id);
                return;
            }
        }
    }
}

// ==========================================================================
// SERVER SIDE (abroad): HTTP/2 client toward the client (optionally via CDN)
// ==========================================================================

fn build_connector() -> TlsConnector {
    // Always validate the certificate (CDN edge certificates are publicly trusted) - same as Direct.
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Same ALPN as the Direct client connector (client.rs): h2 only.
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    TlsConnector::from(Arc::new(cfg))
}

struct DialerArgs {
    addrs: Vec<String>,
    label: String,
    sni: String,
    name: rustls::pki_types::ServerName<'static>,
    location: Option<String>,
    secret: String,
    hidden_path: String,
    bind_port: String,
    connector: TlsConnector,
    /// Protocol priority (`[server].protocols`).
    protos: Vec<Proto>,
}

/// "domain:port" -> (domain, Some(port)); anything else -> (input, None).
fn split_host_port(s: &str) -> (String, Option<u16>) {
    let s = s.trim();
    if let Some((h, p)) = s.rsplit_once(':') {
        if !h.contains(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h.to_string(), Some(port));
            }
        }
    }
    (s.to_string(), None)
}

/// Adds the default port when missing; handles IPv4, IPv6 (bare or bracketed) and domains.
fn normalize_addr(s: &str, default_port: u16) -> String {
    let s = s.trim();
    if s.starts_with('[') {
        return if s.contains("]:") {
            s.to_string()
        } else {
            format!("{}:{}", s, default_port)
        };
    }
    match s.matches(':').count() {
        0 => format!("{}:{}", s, default_port),
        1 => s.to_string(),
        _ => format!("[{}]:{}", s, default_port),
    }
}

fn host_of(addr: &str) -> String {
    addr.rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']').to_string())
        .unwrap_or_else(|| addr.to_string())
}

/// Spawns the reverse dialers configured in `[[server.reverse]]` (no-op when absent).
/// `secret` and `hidden_path` always come from the enclosing `[server]` section.
pub fn spawn_dialers(cfg: &ServerConfig, cancel: CancellationToken) {
    let Some(list) = cfg.reverse.as_ref().filter(|l| !l.is_empty()) else {
        return;
    };
    let secret = cfg.secret.clone().unwrap_or_default();
    if secret.is_empty() {
        tracing::error!("❌ [[server.reverse]] ignored: [server].secret must be set.");
        return;
    }
    let bind_port = cfg.bind_addr.rsplit(':').next().unwrap_or("").to_string();
    let connector = build_connector();
    let protos = crate::transport::parse_list(cfg.protocols.as_ref(), "server");

    for r in list {
        let (sni_host, sni_port) = match r.sni.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => {
                let (h, p) = split_host_port(s);
                (Some(h), p)
            }
            None => (None, None),
        };
        let default_port = sni_port.unwrap_or(443);
        let mut addrs: Vec<String> = r
            .clean_ip
            .iter()
            .map(|c| c.trim())
            .filter(|c| !c.is_empty())
            .map(|c| normalize_addr(c, default_port))
            .collect();
        if addrs.is_empty() {
            match &sni_host {
                Some(h) => addrs.push(normalize_addr(h, default_port)),
                None => {
                    tracing::error!(
                        "❌ [[server.reverse]] entry skipped: set `clean_ip` and/or `sni`."
                    );
                    continue;
                }
            }
        }
        // SNI/Host: explicit `sni`, else the first clean_ip host.
        let sni = sni_host.clone().unwrap_or_else(|| host_of(&addrs[0]));
        let name = match rustls::pki_types::ServerName::try_from(sni.clone()) {
            Ok(n) => n,
            Err(e) => {
                tracing::error!("❌ [[server.reverse]]: invalid sni '{}': {}", sni, e);
                continue;
            }
        };
        if sni.parse::<std::net::IpAddr>().is_ok() {
            warn!(
                "⚠️ [[server.reverse]]: no domain to use as SNI/Host (only IPs given). Behind a CDN set `sni` to the proxied domain."
            );
        }
        let conns = r.pool_size.unwrap_or(8).max(1);
        info!(
            "🔁 Reverse dialer: {} -> [{}] ({} connection(s) x {} ready streams, protocols: {}{})",
            sni,
            addrs.join(", "),
            conns,
            PARKED_PER_CONN,
            protos
                .iter()
                .map(|p| p.name())
                .collect::<Vec<_>>()
                .join(" > "),
            r.location
                .as_ref()
                .map(|l| format!(", location '{}'", l))
                .unwrap_or_default()
        );
        for idx in 0..conns {
            let a = Arc::new(DialerArgs {
                addrs: addrs.clone(),
                label: sni.clone(),
                sni: sni.clone(),
                name: name.clone(),
                location: r.location.clone().filter(|l| !l.is_empty()),
                secret: secret.clone(),
                hidden_path: cfg.hidden_path.clone(),
                bind_port: bind_port.clone(),
                connector: connector.clone(),
                protos: protos.clone(),
            });
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let jitter = (rand::random::<u64>() % 300) + 150 * idx as u64;
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(jitter)) => {}
                    _ = cancel.cancelled() => return,
                }
                conn_manager(a, cancel).await;
            });
        }
    }
}

async fn connect_h2(
    a: &DialerArgs,
) -> Result<(h2::client::SendRequest<Bytes>, CancellationToken), String> {
    // Race every candidate address (clean CDN IPs / domains); the first TCP connection wins.
    use futures::stream::{FuturesUnordered, StreamExt};
    let mut tasks = FuturesUnordered::new();
    for addr in &a.addrs {
        tasks.push(async move {
            crate::anti_loop::safe_connect(addr.as_str(), Duration::from_secs(5)).await
        });
    }
    let mut tcp_opt = None;
    while let Some(res) = tasks.next().await {
        if let Ok(t) = res {
            tcp_opt = Some(t);
            break;
        }
    }
    drop(tasks);
    let tcp = tcp_opt.ok_or_else(|| "all TCP connection attempts failed".to_string())?;
    let _ = tcp.set_nodelay(true);
    crate::net_utils::enable_tcp_bbr(&tcp);
    crate::net_utils::tune_socket_buffers(&tcp);
    crate::net_utils::enable_tcp_keepalive(&tcp);
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        a.connector.connect(a.name.clone(), tcp),
    )
    .await
    .map_err(|_| "tls handshake timed out".to_string())?
    .map_err(|e| format!("tls handshake failed: {}", e))?;
    let (client, mut conn) = h2::client::Builder::new()
        .initial_window_size(8_388_608)
        .initial_connection_window_size(1_073_741_824)
        .max_frame_size(65_535)
        .handshake::<_, Bytes>(tls)
        .await
        .map_err(|e| format!("h2 handshake failed: {}", e))?;
    let mut ping_pong = conn.ping_pong().ok_or("no ping_pong")?;
    let dead = CancellationToken::new();
    let dead2 = dead.clone();
    tokio::spawn(async move {
        let ping_loop = async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    ping_pong.ping(h2::Ping::opaque()),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    _ => {
                        debug!("Reverse H2 ping failed; dropping connection.");
                        break;
                    }
                }
            }
        };
        tokio::select! { _ = conn => {} _ = ping_loop => {} }
        dead2.cancel();
    });
    Ok((client, dead))
}

/// Keeps one reverse connection alive. Each (re)connect tries the configured protocols in
/// priority order (a protocol that failed recently goes last) and switches to the next one when a
/// protocol cannot connect, or connects but never carries a tunnel (e.g. a CDN without gRPC).
async fn conn_manager(a: Arc<DialerArgs>, cancel: CancellationToken) {
    let mut backoff_ms: u64 = 500;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let started = tokio::time::Instant::now();
        let mut served = false;
        for proto in crate::transport::order(&a.label, &a.protos) {
            let working = match proto {
                Proto::H2 => match connect_h2(&a).await {
                    Ok((client, dead)) => {
                        debug!("🔁 Reverse H2 connection for {} established", a.label);
                        let healthy = Arc::new(AtomicBool::new(false));
                        for _ in 0..PARKED_PER_CONN {
                            tokio::spawn(parker(
                                client.clone(),
                                a.clone(),
                                dead.clone(),
                                cancel.clone(),
                                healthy.clone(),
                            ));
                        }
                        drop(client);
                        tokio::select! {
                            _ = dead.cancelled() => {}
                            // Hot-reload: stop redialing; parkers drain on their own and the H2 connection
                            // closes once its last handle is dropped.
                            _ = cancel.cancelled() => return,
                        }
                        healthy.load(Ordering::Relaxed)
                    }
                    Err(e) => {
                        crate::net_utils::log_rate_limited(
                            &format!("rev_dial_{}", a.label),
                            &format!("⚠️ Reverse dial (h2) for {} failed: {}", a.label, e),
                        );
                        false
                    }
                },
                Proto::WssMux => {
                    let dial = crate::wssmux::ReverseDial {
                        addrs: &a.addrs,
                        sni: &a.sni,
                        location: a.location.as_deref(),
                        secret: &a.secret,
                        hidden_path: &a.hidden_path,
                        bind_port: &a.bind_port,
                    };
                    match crate::wssmux::dial_reverse(&dial, cancel.clone()).await {
                        Ok(session) => {
                            debug!("🔁 Reverse WssMux session for {} established", a.label);
                            let t0 = tokio::time::Instant::now();
                            tokio::select! {
                                _ = session.dead.cancelled() => {}
                                _ = cancel.cancelled() => return,
                            }
                            // A session that dies at once never carried anything: treat as failed.
                            t0.elapsed() > Duration::from_secs(5)
                        }
                        Err(e) => {
                            crate::net_utils::log_rate_limited(
                                &format!("rev_dial_ws_{}", a.label),
                                &format!("⚠️ Reverse dial (wssmux) for {} failed: {}", a.label, e),
                            );
                            false
                        }
                    }
                }
            };
            if working {
                crate::transport::record_ok(&a.label, proto);
                served = true;
                break;
            }
            crate::transport::record_fail(&a.label, proto);
            if a.protos.len() > 1 {
                crate::net_utils::log_rate_limited(
                    &format!("rev_switch_{}_{}", a.label, proto.name()),
                    &format!(
                        "🔀 Reverse {}: protocol {} is unavailable, switching to the next one",
                        a.label,
                        proto.name()
                    ),
                );
            }
        }
        backoff_ms = if served && started.elapsed() > Duration::from_secs(5) {
            300
        } else {
            (backoff_ms * 3 / 2).min(30_000)
        };
        let wait = backoff_ms + (rand::random::<u64>() % 700) + 100;
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(wait)) => {}
            _ = cancel.cancelled() => return,
        }
    }
}

struct Assigned {
    target: String,
    try_local: bool,
    send: SendStream<Bytes>,
    body: RecvStream,
    leftover: BytesMut,
}

enum ParkEnd {
    Assigned(Assigned),
    Drained,
    StreamClosed,
    BadStatus(u16),
    ConnDead,
}

async fn park_once(
    client: &mut h2::client::SendRequest<Bytes>,
    a: &DialerArgs,
    dead: &CancellationToken,
    cancel: &CancellationToken,
    healthy: &AtomicBool,
) -> ParkEnd {
    let ready = tokio::select! {
        r = client.clone().ready() => r,
        _ = dead.cancelled() => return ParkEnd::ConnDead,
    };
    let mut c = match ready {
        Ok(c) => c,
        Err(_) => return ParkEnd::ConnDead,
    };
    let mut rb = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{}{}", a.sni, a.hidden_path))
        .header("Host", a.sni.clone())
        .header("x-tunnel-secret", a.secret.clone());
    if let Some(l) = &a.location {
        rb = rb.header("x-tunnel-location", l.clone());
    }
    for (k, v) in crate::net_utils::get_random_headers() {
        rb = rb.header(k, v);
    }
    let (resp_fut, send) = match c.send_request(rb.body(()).unwrap(), false) {
        Ok(x) => x,
        Err(_) => return ParkEnd::ConnDead,
    };
    let resp = match tokio::time::timeout(Duration::from_secs(20), resp_fut).await {
        Ok(Ok(r)) => r,
        _ => return ParkEnd::StreamClosed,
    };
    if resp.status() != http::StatusCode::OK {
        return ParkEnd::BadStatus(resp.status().as_u16());
    }
    if !healthy.swap(true, Ordering::Relaxed) {
        crate::transport::record_ok(&a.label, Proto::H2);
    }
    let mut body = resp.into_body();
    let mut buf = BytesMut::new();

    let drain_wait = async {
        cancel.cancelled().await;
        tokio::time::sleep(Duration::from_secs(3)).await;
    };
    tokio::pin!(drain_wait);
    loop {
        tokio::select! {
            _ = &mut drain_wait => return ParkEnd::Drained,
            _ = dead.cancelled() => return ParkEnd::ConnDead,
            d = body.data() => match d {
                Some(Ok(chunk)) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    buf.extend_from_slice(&chunk);
                    loop {
                        match pop_frame(&mut buf) {
                            Ok(Some((FLAG_ASSIGN, p))) => {
                                let s = String::from_utf8_lossy(&p).to_string();
                                let (target, tl) = s.split_once('\n').unwrap_or((s.as_str(), "0"));
                                return ParkEnd::Assigned(Assigned {
                                    target: target.to_string(),
                                    try_local: tl == "1",
                                    send,
                                    body,
                                    leftover: buf,
                                });
                            }
                            Ok(Some(_)) => continue, // keep-alive
                            Ok(None) => break,
                            Err(_) => return ParkEnd::StreamClosed,
                        }
                    }
                }
                _ => return ParkEnd::StreamClosed,
            }
        }
    }
}

async fn parker(
    mut client: h2::client::SendRequest<Bytes>,
    a: Arc<DialerArgs>,
    dead: CancellationToken,
    cancel: CancellationToken,
    healthy: Arc<AtomicBool>,
) {
    let mut fails: u32 = 0;
    // Failures on a connection that has never parked a single stream: after a few of them the
    // HTTP/2 path is considered unusable (CDN without gRPC, wrong path...) so the connection is
    // dropped and `conn_manager` switches to the next protocol.
    let mut early_fails: u32 = 0;
    loop {
        if dead.is_cancelled() || cancel.is_cancelled() {
            return;
        }
        match park_once(&mut client, &a, &dead, &cancel, &healthy).await {
            ParkEnd::Assigned(asg) => {
                fails = 0;
                early_fails = 0;
                let a2 = a.clone();
                tokio::spawn(async move { serve_assigned(asg, a2).await });
            }
            ParkEnd::Drained | ParkEnd::ConnDead => return,
            ParkEnd::BadStatus(code) => {
                crate::net_utils::log_rate_limited(
                    &format!("rev_status_{}_{}", a.label, code),
                    &format!(
                        "⚠️ Reverse request for {} was answered with HTTP {} (secret/hidden_path mismatch, or CDN/gRPC setting?)",
                        a.label, code
                    ),
                );
                // 503 only means "the client is at its parked-stream limit": not a protocol problem.
                if code != 503 && !healthy.load(Ordering::Relaxed) {
                    early_fails += 1;
                    if early_fails >= 3 && a.protos.len() > 1 {
                        dead.cancel();
                        return;
                    }
                }
                tokio::select! { _ = tokio::time::sleep(Duration::from_secs(5)) => {} _ = dead.cancelled() => return }
            }
            ParkEnd::StreamClosed => {
                fails += 1;
                if !healthy.load(Ordering::Relaxed) {
                    early_fails += 1;
                    if early_fails >= 3 && a.protos.len() > 1 {
                        dead.cancel();
                        return;
                    }
                }
                let d = if fails < 3 { 200 } else { 2000 };
                tokio::select! { _ = tokio::time::sleep(Duration::from_millis(d)) => {} _ = dead.cancelled() => return }
            }
        }
    }
}

/// Same target semantics as the Direct server path (loop protection, dead-target circuit breaker,
/// try_local), so both tunnel kinds behave identically.
pub(crate) async fn connect_target(
    mut target: String,
    try_local_flag: bool,
    bind_port: &str,
) -> Result<TcpStream, ()> {
    if !target.contains(':') {
        target = format!("127.0.0.1:{}", target);
    }
    let own_port = (target.starts_with("127.0.0.1:")
        || target.starts_with("localhost:")
        || target.starts_with("[::1]:"))
        && target.rsplit(':').next() == Some(bind_port);
    if own_port {
        warn!(
            "🔄 Routing loop detected! Target {} matches our own listen port. Rejecting.",
            target
        );
        return Err(());
    }
    let explicit_local = target.contains("127.0.0.1")
        || target.contains("localhost")
        || target.contains("GHOST_LOCAL");
    let try_local = explicit_local || try_local_flag;
    if crate::server::get_dead_targets()
        .read()
        .unwrap()
        .contains(&target)
    {
        crate::net_utils::log_rate_limited(
            &format!("cb_{}", target),
            &format!("❌ Circuit Breaker active for dead target: {}", target),
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        return Err(());
    }
    let mut tcp = None;
    if try_local {
        if let Some(idx) = target.rfind(':') {
            let port = &target[idx + 1..];
            tcp = match crate::anti_loop::safe_connect(
                format!("127.0.0.1:{}", port),
                Duration::from_secs(10),
            )
            .await
            {
                Ok(t) => Some(t),
                Err(_) => crate::anti_loop::safe_connect(
                    format!("[::1]:{}", port),
                    Duration::from_secs(10),
                )
                .await
                .ok(),
            };
        }
        if tcp.is_none() {
            crate::net_utils::log_rate_limited(
                &format!("fail_local_{}", target),
                &format!("❌ Failed to connect to local target for {}", target),
            );
            crate::server::get_dead_targets()
                .write()
                .unwrap()
                .insert(target);
            return Err(());
        }
    } else {
        match crate::anti_loop::safe_connect(target.as_str(), Duration::from_secs(10)).await {
            Ok(t) => tcp = Some(t),
            Err(_) => {
                crate::net_utils::log_rate_limited(
                    &format!("fail_{}", target),
                    &format!("❌ Failed to connect to target: {}", target),
                );
                crate::server::get_dead_targets()
                    .write()
                    .unwrap()
                    .insert(target);
                return Err(());
            }
        }
    }
    let tcp = tcp.unwrap();
    let _ = tcp.set_nodelay(true);
    crate::net_utils::tune_socket_buffers(&tcp);
    crate::net_utils::enable_tcp_keepalive(&tcp);
    crate::net_utils::enable_tcp_linger_zero(&tcp);
    Ok(tcp)
}

async fn serve_assigned(mut asg: Assigned, a: Arc<DialerArgs>) {
    let tcp = connect_target(asg.target.clone(), asg.try_local, &a.bind_port).await;
    let ok = tcp.is_ok();
    if crate::net_utils::send_h2_data(&mut asg.send, frame(FLAG_ACK, &[ok as u8]), false)
        .await
        .is_err()
        || !ok
    {
        let _ = asg.send.send_data(Bytes::new(), true);
        return;
    }
    let (mut target_read, mut target_write) = tcp.unwrap().into_split();
    let mut send = asg.send;

    let (drop_tx, mut drop_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut read_buf = BytesMut::with_capacity(1024 * 1024);
        loop {
            if read_buf.capacity() < 65536 + 5 {
                read_buf = BytesMut::with_capacity(1024 * 1024);
            }
            read_buf.extend_from_slice(&[0, 0, 0, 0, 0]);
            tokio::select! {
                _ = &mut drop_rx => break,
                res = tokio::io::AsyncReadExt::read_buf(&mut target_read, &mut read_buf) => {
                    let n = match res { Ok(0) | Err(_) => break, Ok(n) => n };
                    read_buf[1..5].copy_from_slice(&(n as u32).to_be_bytes());
                    let framed = read_buf.split().freeze();
                    if crate::net_utils::send_h2_data(&mut send, framed, false).await.is_err() { break; }
                }
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    });

    let mut buf = asg.leftover;
    let mut body = asg.body;
    loop {
        loop {
            match pop_frame(&mut buf) {
                Ok(Some((_, p))) => {
                    if !p.is_empty() && target_write.write_all(&p).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    warn!("OOM protection: reverse frame too large");
                    return;
                }
            }
        }
        match body.data().await {
            Some(Ok(chunk)) => {
                let _ = body.flow_control().release_capacity(chunk.len());
                buf.extend_from_slice(&chunk);
            }
            _ => break,
        }
    }
    let _ = target_write.shutdown().await;
    let _ = drop_tx;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_partial() {
        let f = frame(FLAG_ASSIGN, b"1.2.3.4:80\n1");
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&f[..3]);
        assert!(matches!(pop_frame(&mut buf), Ok(None)));
        buf.extend_from_slice(&f[3..]);
        buf.extend_from_slice(&frame(FLAG_DATA, &[]));
        let (fl, p) = pop_frame(&mut buf).unwrap().unwrap();
        assert_eq!((fl, &p[..]), (FLAG_ASSIGN, &b"1.2.3.4:80\n1"[..]));
        let (fl, p) = pop_frame(&mut buf).unwrap().unwrap();
        assert_eq!((fl, p.len()), (FLAG_DATA, 0));
        assert!(buf.is_empty());
    }

    #[test]
    fn oversize_frame_rejected() {
        let mut buf = BytesMut::from(&[0u8, 0xff, 0xff, 0xff, 0xff][..]);
        assert!(pop_frame(&mut buf).is_err());
    }

    #[test]
    fn addr_and_sni_parsing() {
        assert_eq!(
            split_host_port("a.example.com:2083"),
            ("a.example.com".into(), Some(2083))
        );
        assert_eq!(
            split_host_port("a.example.com"),
            ("a.example.com".into(), None)
        );
        assert_eq!(normalize_addr("104.16.1.1", 2083), "104.16.1.1:2083");
        assert_eq!(normalize_addr("104.16.1.1:8443", 2083), "104.16.1.1:8443");
        assert_eq!(normalize_addr("2606:4700::1", 443), "[2606:4700::1]:443");
        assert_eq!(normalize_addr("[2606:4700::1]", 443), "[2606:4700::1]:443");
        assert_eq!(
            normalize_addr("[2606:4700::1]:8443", 443),
            "[2606:4700::1]:8443"
        );
        assert_eq!(host_of("[2606:4700::1]:8443"), "2606:4700::1");
        assert_eq!(host_of("x.com:1"), "x.com");
    }

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn reverse_protocol_selection_uses_priority_and_availability() {
        let order = [Proto::H2, Proto::WssMux];
        assert_eq!(
            preferred_available_protocol(&order, true, true),
            Some(Proto::H2)
        );
        let reverse_order = [Proto::WssMux, Proto::H2];
        assert_eq!(
            preferred_available_protocol(&reverse_order, true, true),
            Some(Proto::WssMux)
        );
        assert_eq!(
            preferred_available_protocol(&order, false, true),
            Some(Proto::WssMux)
        );
        assert_eq!(preferred_available_protocol(&order, false, false), None);
    }
}
