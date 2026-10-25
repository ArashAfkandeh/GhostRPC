//! Protocol selection shared by Direct and Reverse tunnels.
//!
//! GhostRPC can carry the tunnel over two wire protocols:
//!
//!   * `h2`     – HTTP/2 (gRPC-style POST streams, see `client.rs` / `server.rs` / `reverse.rs`)
//!   * `wssmux` – WebSocket over TLS (HTTP/1.1 upgrade) carrying a yamux multiplexer (`wssmux.rs`)
//!
//! `protocols = ["h2", "wssmux"]` (in `[client]` / `[server]`) is an ORDERED priority list: the first
//! entry is preferred, the others are automatic fallbacks. When a protocol fails to connect it is
//! put on a short cool-down so that every following (re)connect tries the healthy protocol first.
//! Omitting the key enables both (`h2` first). `protocols = ["h2"]` keeps the legacy behaviour.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock, atomic::{AtomicBool, Ordering}},
    time::{Duration, Instant},
};

/// A protocol that failed recently is tried last for this long.
const COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    H2,
    WssMux,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::H2 => "h2",
            Proto::WssMux => "wssmux",
        }
    }

    fn parse(s: &str) -> Option<Proto> {
        match s.trim().to_ascii_lowercase().as_str() {
            "h2" | "http2" | "grpc" => Some(Proto::H2),
            "wssmux" => Some(Proto::WssMux),
            _ => None,
        }
    }
}

/// Parses the `protocols` config value. Unknown names are reported and skipped, duplicates are
/// dropped, and an absent/empty/invalid list falls back to the default `["h2", "wssmux"]`.
pub fn parse_list(cfg: Option<&Vec<String>>, who: &str) -> Vec<Proto> {
    let mut out: Vec<Proto> = Vec::new();
    if let Some(list) = cfg {
        for raw in list {
            match Proto::parse(raw) {
                Some(p) if !out.contains(&p) => out.push(p),
                Some(_) => {}
                None => tracing::error!(
                    "❌ [{}] protocols: unknown protocol '{}' ignored (valid: \"h2\", \"wssmux\").",
                    who, raw
                ),
            }
        }
    }
    if out.is_empty() {
        if cfg.map_or(false, |l| !l.is_empty()) {
            tracing::error!("❌ [{}] protocols: no valid entry, using the default [\"h2\", \"wssmux\"].", who);
        }
        out = vec![Proto::H2, Proto::WssMux];
    }
    out
}

fn failures() -> &'static Mutex<HashMap<(String, Proto), Instant>> {
    static F: OnceLock<Mutex<HashMap<(String, Proto), Instant>>> = OnceLock::new();
    F.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Remembers that `proto` just failed for `key` (a node SNI / reverse label).
pub fn record_fail(key: &str, proto: Proto) {
    failures().lock().unwrap().insert((key.to_string(), proto), Instant::now());
}

/// Clears the cool-down of `proto` for `key` after a successful connection.
pub fn record_ok(key: &str, proto: Proto) {
    failures().lock().unwrap().remove(&(key.to_string(), proto));
}

/// True while `proto` is cooling down after a failure for `key`.
pub fn is_cooling(key: &str, proto: Proto) -> bool {
    failures()
        .lock()
        .unwrap()
        .get(&(key.to_string(), proto))
        .map_or(false, |t| t.elapsed() < COOLDOWN)
}

/// The order in which to try the protocols for `key`: configured priority, but protocols that
/// failed within the cool-down window go last (stable, so priority is kept inside each group).
pub fn order(key: &str, list: &[Proto]) -> Vec<Proto> {
    let mut v: Vec<Proto> = list.to_vec();
    v.sort_by_key(|p| is_cooling(key, *p));
    v
}

// ---- server-side switches (set on every (re)load by `run_server`) ----

static SERVER_H2: AtomicBool = AtomicBool::new(true);
static SERVER_WSS: AtomicBool = AtomicBool::new(true);

pub fn set_server_protocols(list: &[Proto]) {
    SERVER_H2.store(list.contains(&Proto::H2), Ordering::Relaxed);
    SERVER_WSS.store(list.contains(&Proto::WssMux), Ordering::Relaxed);
}

/// Whether the Direct server accepts WssMux connections (negotiated ALPN `http/1.1`).
pub fn server_accepts_wssmux() -> bool {
    SERVER_WSS.load(Ordering::Relaxed)
}

/// Whether the Direct server accepts HTTP/2 tunnel connections.
pub fn server_accepts_h2() -> bool {
    SERVER_H2.load(Ordering::Relaxed)
}

// ---- inbound wire-protocol detection (shared by Direct server and Reverse acceptor) ----

/// Which tunnel wire protocol an accepted TLS connection speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    H2,
    WsMux,
}

/// Decides between HTTP/2 and WebSocket(+yamux) for a freshly accepted TLS connection.
///
/// 1. ALPN `h2` -> HTTP/2, ALPN `http/1.1` -> WebSocket (direct clients always send ALPN).
/// 2. NO ALPN at all -> this is what CDNs (ArvanCloud / nginx-style origin pulls) do: they speak
///    plain HTTP/1.1 to the origin and offer no ALPN extension. The decrypted stream is peeked:
///    the HTTP/2 client preface starts with `PRI `, anything else is an HTTP/1.1 WebSocket upgrade.
///
/// Returns the stream with the peeked bytes replayed, or None when the peer sent nothing.
pub async fn detect_wire<S>(
    mut tls: tokio_rustls::server::TlsStream<S>,
) -> Option<(Wire, crate::prefixed_stream::PrefixedStream<tokio_rustls::server::TlsStream<S>>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crate::prefixed_stream::PrefixedStream;
    use tokio::io::AsyncReadExt;

    let alpn = tls.get_ref().1.alpn_protocol();
    let wire = if alpn == Some(b"h2".as_slice()) {
        Some(Wire::H2)
    } else if alpn == Some(b"http/1.1".as_slice()) {
        Some(Wire::WsMux)
    } else {
        None
    };
    if let Some(w) = wire {
        return Some((w, PrefixedStream { prefix: Vec::new(), inner: tls }));
    }

    let mut buf = [0u8; 4];
    let mut n = 0usize;
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        while n < buf.len() {
            match tls.read(&mut buf[n..]).await {
                Ok(k) if k > 0 => n += k,
                _ => break,
            }
        }
    })
    .await;
    if n == 0 {
        return None;
    }
    let w = if b"PRI ".starts_with(&buf[..n]) { Wire::H2 } else { Wire::WsMux };
    tracing::debug!("🔎 No ALPN negotiated (CDN origin pull?): sniffed first bytes -> {:?}", w);
    Some((w, PrefixedStream { prefix: buf[..n].to_vec(), inner: tls }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_and_parsing() {
        assert_eq!(parse_list(None, "t"), vec![Proto::H2, Proto::WssMux]);
        let l = vec!["WSSMUX".to_string(), "h2".to_string(), "h2".to_string(), "bogus".to_string()];
        assert_eq!(parse_list(Some(&l), "t"), vec![Proto::WssMux, Proto::H2]);
        let only = vec!["h2".to_string()];
        assert_eq!(parse_list(Some(&only), "t"), vec![Proto::H2]);
        let bad = vec!["nope".to_string()];
        assert_eq!(parse_list(Some(&bad), "t"), vec![Proto::H2, Proto::WssMux]);
    }

    #[test]
    fn failed_protocol_goes_last_then_recovers() {
        let list = [Proto::H2, Proto::WssMux];
        let k = "order-test-node";
        assert_eq!(order(k, &list), vec![Proto::H2, Proto::WssMux]);
        record_fail(k, Proto::H2);
        assert_eq!(order(k, &list), vec![Proto::WssMux, Proto::H2]);
        // both failing: configured priority is kept
        record_fail(k, Proto::WssMux);
        assert_eq!(order(k, &list), vec![Proto::H2, Proto::WssMux]);
        record_ok(k, Proto::H2);
        record_ok(k, Proto::WssMux);
        assert_eq!(order(k, &list), vec![Proto::H2, Proto::WssMux]);
        // other keys are unaffected
        record_fail(k, Proto::H2);
        assert_eq!(order("other", &list), vec![Proto::H2, Proto::WssMux]);
    }
}
