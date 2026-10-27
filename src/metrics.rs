//! Lightweight, lock-free-where-possible runtime statistics used by the admin panel (`admin.rs`).
//!
//! Everything here is cheap enough to stay compiled in when the panel is disabled:
//! * global byte / stream counters (relaxed atomics),
//! * a registry of live tunnel sessions and live proxied streams,
//! * a 1-second and a 1-minute time series (filled by [`spawn_sampler`]),
//! * a ring buffer with the latest log lines (fed by [`LogLayer`], a `tracing` layer).

use dashmap::DashMap;
use serde::Serialize;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context as LayerContext;
use tracing_subscriber::registry::LookupSpan;

// ==========================================================================
// Counters
// ==========================================================================

/// Payload bytes this process pushed INTO a tunnel (client: user -> server, server: target -> client).
pub static TX_BYTES: AtomicU64 = AtomicU64::new(0);
/// Payload bytes this process received FROM a tunnel.
pub static RX_BYTES: AtomicU64 = AtomicU64::new(0);
/// Proxied streams opened since start / currently open.
pub static STREAMS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static STREAMS_ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// H2 tunnel requests to the configured hidden path rejected for a missing/invalid secret or headers.
pub static UNAUTHORIZED: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn add_tx(n: usize) {
    TX_BYTES.fetch_add(n as u64, Ordering::Relaxed);
}

#[inline]
pub fn add_rx(n: usize) {
    RX_BYTES.fetch_add(n as u64, Ordering::Relaxed);
}

#[inline]
pub fn add_unauthorized() {
    UNAUTHORIZED.fetch_add(1, Ordering::Relaxed);
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

static START: OnceLock<Instant> = OnceLock::new();

pub fn uptime_secs() -> u64 {
    START.get_or_init(Instant::now).elapsed().as_secs()
}

/// Remembers the process start (call once at the top of `main`).
pub fn mark_start() {
    let _ = START.get_or_init(Instant::now);
}

// ==========================================================================
// Role (server / client) of the running configuration
// ==========================================================================

static ROLE: RwLock<&'static str> = RwLock::new("unknown");

pub fn set_role(role: &'static str) {
    *ROLE.write().unwrap() = role;
}

pub fn role() -> &'static str {
    *ROLE.read().unwrap()
}

// ==========================================================================
// Live registries
// ==========================================================================

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Serialize)]
pub struct SessionInfo {
    pub id: u64,
    /// "h2" | "wssmux"
    pub proto: &'static str,
    /// "in": the peer dialed us, "out": we dialed the peer.
    pub dir: &'static str,
    /// Which feature owns it: "direct" | "reverse".
    pub kind: &'static str,
    pub peer: String,
    pub since: u64,
}

#[derive(Clone, Serialize)]
pub struct StreamInfo {
    pub id: u64,
    pub kind: &'static str,
    pub proto: &'static str,
    pub peer: String,
    pub target: String,
    pub since: u64,
}

fn sessions() -> &'static DashMap<u64, SessionInfo> {
    static M: OnceLock<DashMap<u64, SessionInfo>> = OnceLock::new();
    M.get_or_init(DashMap::new)
}

fn streams() -> &'static DashMap<u64, StreamInfo> {
    static M: OnceLock<DashMap<u64, StreamInfo>> = OnceLock::new();
    M.get_or_init(DashMap::new)
}

/// RAII handle of a tunnel session (an HTTP/2 connection or a WssMux session). Dropping it removes
/// the session from the registry.
pub struct SessionGuard(u64);

pub fn open_session(
    proto: &'static str,
    dir: &'static str,
    kind: &'static str,
    peer: impl Into<String>,
) -> SessionGuard {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    sessions().insert(
        id,
        SessionInfo {
            id,
            proto,
            dir,
            kind,
            peer: peer.into(),
            since: now_unix(),
        },
    );
    SessionGuard(id)
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        sessions().remove(&self.0);
    }
}

/// RAII handle of one proxied stream (a user connection travelling through the tunnel).
pub struct StreamGuard(u64);

pub fn open_stream(
    kind: &'static str,
    proto: &'static str,
    peer: impl Into<String>,
    target: impl Into<String>,
) -> StreamGuard {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    STREAMS_TOTAL.fetch_add(1, Ordering::Relaxed);
    STREAMS_ACTIVE.fetch_add(1, Ordering::Relaxed);
    streams().insert(
        id,
        StreamInfo {
            id,
            kind,
            proto,
            peer: peer.into(),
            target: target.into(),
            since: now_unix(),
        },
    );
    StreamGuard(id)
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        streams().remove(&self.0);
        STREAMS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn session_list() -> Vec<SessionInfo> {
    let mut v: Vec<SessionInfo> = sessions().iter().map(|e| e.value().clone()).collect();
    v.sort_by_key(|s| s.since);
    v
}

/// The `limit` most recent streams (newest first) and the total number of open streams.
pub fn stream_list(limit: usize) -> (Vec<StreamInfo>, usize) {
    let total = streams().len();
    let mut v: Vec<StreamInfo> = streams().iter().map(|e| e.value().clone()).collect();
    v.sort_by(|a, b| b.since.cmp(&a.since).then(b.id.cmp(&a.id)));
    v.truncate(limit);
    (v, total)
}

// ==========================================================================
// Byte-counting I/O wrapper (tunnel side of a WssMux stream)
// ==========================================================================

/// Wraps the TUNNEL side of a stream: bytes read from it count as RX, bytes written to it as TX.
pub struct Counted<S> {
    inner: S,
}

impl<S> Counted<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            add_rx(buf.filled().len().saturating_sub(before));
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            add_tx(*n);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ==========================================================================
// Time series
// ==========================================================================

#[derive(Clone, Copy, Serialize)]
pub struct Point {
    /// Unix seconds.
    pub t: u64,
    /// Average bytes per second inside the bucket.
    pub tx: u64,
    pub rx: u64,
    /// Highest number of simultaneously open streams inside the bucket.
    pub streams: u32,
}

const SEC_CAP: usize = 900; // 15 minutes at 1 s
const MIN_CAP: usize = 1440; // 24 hours at 1 min

struct Series {
    sec: VecDeque<Point>,
    min: VecDeque<Point>,
    last_tx: u64,
    last_rx: u64,
    acc_tx: u64,
    acc_rx: u64,
    acc_streams: u32,
    acc_n: u32,
}

fn series() -> &'static Mutex<Series> {
    static S: OnceLock<Mutex<Series>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(Series {
            sec: VecDeque::with_capacity(SEC_CAP),
            min: VecDeque::with_capacity(MIN_CAP),
            last_tx: TX_BYTES.load(Ordering::Relaxed),
            last_rx: RX_BYTES.load(Ordering::Relaxed),
            acc_tx: 0,
            acc_rx: 0,
            acc_streams: 0,
            acc_n: 0,
        })
    })
}

fn push_capped(q: &mut VecDeque<Point>, p: Point, cap: usize) {
    if q.len() >= cap {
        q.pop_front();
    }
    q.push_back(p);
}

fn sample_once() {
    let tx = TX_BYTES.load(Ordering::Relaxed);
    let rx = RX_BYTES.load(Ordering::Relaxed);
    let active = STREAMS_ACTIVE.load(Ordering::Relaxed) as u32;
    let t = now_unix();
    let mut s = series().lock().unwrap();
    let p = Point {
        t,
        tx: tx.saturating_sub(s.last_tx),
        rx: rx.saturating_sub(s.last_rx),
        streams: active,
    };
    s.last_tx = tx;
    s.last_rx = rx;
    push_capped(&mut s.sec, p, SEC_CAP);

    s.acc_tx += p.tx;
    s.acc_rx += p.rx;
    s.acc_streams = s.acc_streams.max(active);
    s.acc_n += 1;
    if s.acc_n >= 60 {
        let n = s.acc_n as u64;
        let m = Point {
            t,
            tx: s.acc_tx / n,
            rx: s.acc_rx / n,
            streams: s.acc_streams,
        };
        push_capped(&mut s.min, m, MIN_CAP);
        s.acc_tx = 0;
        s.acc_rx = 0;
        s.acc_streams = 0;
        s.acc_n = 0;
    }
}

/// Starts the 1 Hz sampler. Safe to call more than once: only the first call spawns the task.
pub fn spawn_sampler() {
    static STARTED: std::sync::Once = std::sync::Once::new();
    STARTED.call_once(|| {
        tokio::spawn(async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                sample_once();
            }
        });
    });
}

/// `res` = "sec" (last 15 minutes, 1 s buckets) or "min" (last 24 hours, 1 min buckets).
pub fn series_points(res: &str) -> Vec<Point> {
    let s = series().lock().unwrap();
    if res == "min" {
        s.min.iter().copied().collect()
    } else {
        s.sec.iter().copied().collect()
    }
}

/// Current throughput in bytes/second (average of the last `n` one-second samples).
pub fn current_rate(n: usize) -> (u64, u64) {
    let s = series().lock().unwrap();
    let take = n.max(1).min(s.sec.len());
    if take == 0 {
        return (0, 0);
    }
    let (mut tx, mut rx) = (0u64, 0u64);
    for p in s.sec.iter().rev().take(take) {
        tx += p.tx;
        rx += p.rx;
    }
    (tx / take as u64, rx / take as u64)
}

// ==========================================================================
// Log ring buffer
// ==========================================================================

#[derive(Clone, Serialize)]
pub struct LogEntry {
    pub seq: u64,
    /// Unix milliseconds.
    pub ts: u64,
    pub level: &'static str,
    pub target: String,
    pub msg: String,
}

const LOG_CAP: usize = 2000;
static LOG_SEQ: AtomicU64 = AtomicU64::new(0);

fn log_buf() -> &'static Mutex<VecDeque<LogEntry>> {
    static B: OnceLock<Mutex<VecDeque<LogEntry>>> = OnceLock::new();
    B.get_or_init(|| Mutex::new(VecDeque::with_capacity(LOG_CAP)))
}

/// Entries with `seq > after`, optionally limited to `min_level` and above, newest `limit` of them,
/// returned oldest-first.
pub fn logs_after(after: u64, min_level: Option<&str>, limit: usize) -> (Vec<LogEntry>, u64) {
    let rank = |l: &str| match l {
        "ERROR" => 4,
        "WARN" => 3,
        "INFO" => 2,
        "DEBUG" => 1,
        _ => 0,
    };
    let min = min_level.map(|l| rank(&l.to_ascii_uppercase())).unwrap_or(0);
    let buf = log_buf().lock().unwrap();
    let mut out: Vec<LogEntry> = buf
        .iter()
        .filter(|e| e.seq > after && rank(e.level) >= min)
        .cloned()
        .collect();
    if out.len() > limit {
        out.drain(..out.len() - limit);
    }
    (out, LOG_SEQ.load(Ordering::Relaxed))
}

#[derive(Default)]
struct MsgVisitor {
    msg: String,
    extra: String,
}

impl Visit for MsgVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.msg, "{:?}", value);
        } else {
            let _ = write!(self.extra, " {}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.msg.push_str(value);
        } else {
            let _ = write!(self.extra, " {}={}", field.name(), value);
        }
    }
}

/// `tracing` layer that mirrors every enabled event into the ring buffer.
pub struct LogLayer;

impl<S> Layer<S> for LogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        let meta = event.metadata();
        let level = match *meta.level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };
        let mut v = MsgVisitor::default();
        event.record(&mut v);
        let mut msg = v.msg;
        msg.push_str(&v.extra);
        if msg.len() > 2000 {
            msg.truncate(2000);
        }
        let entry = LogEntry {
            seq: LOG_SEQ.fetch_add(1, Ordering::Relaxed) + 1,
            ts: now_unix_ms(),
            level,
            target: meta.target().to_string(),
            msg,
        };
        let mut b = log_buf().lock().unwrap();
        if b.len() >= LOG_CAP {
            b.pop_front();
        }
        b.push_back(entry);
    }
}

// ==========================================================================
// Reload request (panel -> main loop)
// ==========================================================================

/// Notified by the panel to force a config reload even when the file content did not change.
pub fn reload_notify() -> &'static tokio::sync::Notify {
    static N: OnceLock<tokio::sync::Notify> = OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}
