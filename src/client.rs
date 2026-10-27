use crate::config::ClientConfig;

use crate::net_utils::{enable_tcp_keepalive, get_random_headers};
use crate::transport::Proto;

use bytes::{Bytes, BytesMut};
use http::{Method, Request};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

pub struct ConnectionState {
    pub client: Option<h2::client::SendRequest<Bytes>>,
    /// WssMux session (WebSocket + yamux). A pool slot holds either an HTTP/2 connection or a
    /// WssMux session, depending on which protocol connected (see `transport.rs`).
    pub mux: Option<crate::wssmux::MuxClient>,
    pub consecutive_errors: u32,
    pub ewma_latency: f64,
}

#[cfg(test)]
mod tunnel_path_tests {
    use super::{
        TunnelPath, direct_probe_is_ready, effective_tunnel_health_interval,
        select_stable_tunnel_path, select_tunnel_path, tunnel_path_check_interval,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn direct_is_preferred_over_reverse() {
        assert_eq!(select_tunnel_path(true, true), TunnelPath::Direct);
    }

    #[test]
    fn reverse_is_selected_when_direct_is_unavailable() {
        assert_eq!(select_tunnel_path(false, true), TunnelPath::Reverse);
    }

    #[test]
    fn no_route_is_selected_when_both_paths_are_unavailable() {
        assert_eq!(select_tunnel_path(false, false), TunnelPath::Unavailable);
    }

    #[test]
    fn reverse_path_requires_three_periodic_checks_before_direct_recovery() {
        let recovery_checks = AtomicUsize::new(0);

        assert_eq!(
            select_stable_tunnel_path(TunnelPath::Reverse, true, true, false, &recovery_checks),
            TunnelPath::Reverse
        );
        assert_eq!(
            select_stable_tunnel_path(TunnelPath::Reverse, true, true, true, &recovery_checks),
            TunnelPath::Reverse
        );
        assert_eq!(
            select_stable_tunnel_path(TunnelPath::Reverse, true, true, true, &recovery_checks),
            TunnelPath::Reverse
        );
        assert_eq!(
            select_stable_tunnel_path(TunnelPath::Reverse, true, true, true, &recovery_checks),
            TunnelPath::Direct
        );
    }

    #[test]
    fn one_failed_direct_health_check_does_not_change_paths() {
        let health_checks = AtomicUsize::new(0);

        assert_eq!(
            select_stable_tunnel_path(TunnelPath::Direct, false, true, true, &health_checks),
            TunnelPath::Direct
        );
        assert_eq!(
            select_stable_tunnel_path(TunnelPath::Direct, true, true, true, &health_checks),
            TunnelPath::Direct
        );
        assert_eq!(health_checks.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn direct_failover_requires_two_consecutive_failed_health_checks() {
        let health_checks = AtomicUsize::new(0);

        assert_eq!(
            select_stable_tunnel_path(TunnelPath::Direct, false, true, true, &health_checks),
            TunnelPath::Direct
        );
        assert_eq!(
            select_stable_tunnel_path(TunnelPath::Direct, false, true, true, &health_checks),
            TunnelPath::Reverse
        );
    }

    #[test]
    fn direct_is_selected_immediately_when_reverse_is_unavailable() {
        let recovery_checks = AtomicUsize::new(0);
        assert_eq!(
            select_stable_tunnel_path(TunnelPath::Reverse, true, false, false, &recovery_checks),
            TunnelPath::Direct
        );
    }

    #[test]
    fn recovery_streak_resets_when_direct_becomes_unhealthy() {
        let recovery_checks = AtomicUsize::new(0);
        select_stable_tunnel_path(TunnelPath::Reverse, true, true, true, &recovery_checks);

        assert_eq!(
            select_stable_tunnel_path(TunnelPath::Reverse, false, true, true, &recovery_checks),
            TunnelPath::Reverse
        );
        assert_eq!(recovery_checks.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unavailable_path_retries_health_checks_quickly() {
        assert_eq!(
            tunnel_path_check_interval(TunnelPath::Unavailable, Duration::from_secs(60)),
            Duration::from_secs(1)
        );
        assert_eq!(
            tunnel_path_check_interval(TunnelPath::Reverse, Duration::from_secs(60)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn tunnel_health_interval_defaults_to_five_minutes_and_clamps_zero() {
        assert_eq!(effective_tunnel_health_interval(None), 5);
        assert_eq!(effective_tunnel_health_interval(Some(0)), 1);
        assert_eq!(effective_tunnel_health_interval(Some(12)), 12);
    }

    #[tokio::test]
    async fn timed_out_direct_probe_is_not_ready() {
        let ready: Result<Result<(), ()>, tokio::time::error::Elapsed> = Ok(Ok(()));
        let failed: Result<Result<(), ()>, tokio::time::error::Elapsed> = Ok(Err(()));
        let result = tokio::time::timeout(
            std::time::Duration::ZERO,
            std::future::pending::<Result<(), ()>>(),
        )
        .await;

        assert!(direct_probe_is_ready(&ready));
        assert!(!direct_probe_is_ready(&failed));
        assert!(!direct_probe_is_ready(&result));
    }
}

const DEFAULT_TUNNEL_HEALTH_CHECK_INTERVAL_MINUTES: u64 = 5;
const DIRECT_FAILURE_CONFIRMATION_CHECKS: usize = 2;
const DIRECT_RECOVERY_CONFIRMATION_CHECKS: usize = 3;
const TUNNEL_PATH_STARTUP_GRACE_PERIOD: Duration = Duration::from_secs(5);

fn effective_tunnel_health_interval(configured: Option<u64>) -> u64 {
    configured
        .unwrap_or(DEFAULT_TUNNEL_HEALTH_CHECK_INTERVAL_MINUTES)
        .max(1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum TunnelPath {
    Starting = 0,
    Direct = 1,
    Reverse = 2,
    Unavailable = 3,
}

impl TunnelPath {
    fn load(state: &AtomicU8) -> Self {
        match state.load(Ordering::Acquire) {
            1 => Self::Direct,
            2 => Self::Reverse,
            3 => Self::Unavailable,
            _ => Self::Starting,
        }
    }
}

async fn has_direct_path(pool: &[(Arc<Mutex<ConnectionState>>, ActiveNode)]) -> bool {
    for (slot, remote) in pool {
        let mut state = slot.lock().await;
        if !crate::transport::is_cooling(&remote.sni, Proto::WssMux)
            && state
                .mux
                .as_ref()
                .is_some_and(crate::wssmux::MuxClient::alive)
        {
            return true;
        }

        if !crate::transport::is_cooling(&remote.sni, Proto::H2) {
            if let Some(mut client) = state.client.clone() {
                let result = tokio::time::timeout(
                    Duration::from_millis(250),
                    std::future::poll_fn(|cx| client.poll_ready(cx)),
                )
                .await;
                if direct_probe_is_ready(&result) {
                    return true;
                }
                if matches!(result, Ok(Err(_))) {
                    state.client = None;
                    crate::transport::record_fail(&remote.sni, Proto::H2);
                }
            }
        }
    }
    false
}

fn direct_probe_is_ready<T, E>(result: &Result<Result<T, E>, tokio::time::error::Elapsed>) -> bool {
    matches!(result, Ok(Ok(_)))
}

fn select_tunnel_path(direct_ready: bool, reverse_ready: bool) -> TunnelPath {
    if direct_ready {
        TunnelPath::Direct
    } else if reverse_ready {
        TunnelPath::Reverse
    } else {
        TunnelPath::Unavailable
    }
}

fn select_stable_tunnel_path(
    current: TunnelPath,
    direct_ready: bool,
    reverse_ready: bool,
    periodic_check: bool,
    direct_recovery_checks: &AtomicUsize,
) -> TunnelPath {
    match current {
        TunnelPath::Direct if direct_ready => {
            direct_recovery_checks.store(0, Ordering::Relaxed);
            TunnelPath::Direct
        }
        TunnelPath::Direct if reverse_ready => {
            if periodic_check
                && direct_recovery_checks.fetch_add(1, Ordering::Relaxed) + 1
                    < DIRECT_FAILURE_CONFIRMATION_CHECKS
            {
                return TunnelPath::Direct;
            }
            direct_recovery_checks.store(0, Ordering::Relaxed);
            TunnelPath::Reverse
        }
        TunnelPath::Reverse if direct_ready && !reverse_ready => {
            direct_recovery_checks.store(0, Ordering::Relaxed);
            TunnelPath::Direct
        }
        TunnelPath::Reverse if direct_ready && reverse_ready => {
            if !periodic_check
                || direct_recovery_checks.fetch_add(1, Ordering::Relaxed) + 1
                    < DIRECT_RECOVERY_CONFIRMATION_CHECKS
            {
                return TunnelPath::Reverse;
            }
            direct_recovery_checks.store(0, Ordering::Relaxed);
            TunnelPath::Direct
        }
        TunnelPath::Reverse if reverse_ready => {
            direct_recovery_checks.store(0, Ordering::Relaxed);
            TunnelPath::Reverse
        }
        TunnelPath::Direct | TunnelPath::Reverse => {
            direct_recovery_checks.store(0, Ordering::Relaxed);
            TunnelPath::Unavailable
        }
        TunnelPath::Starting | TunnelPath::Unavailable => {
            direct_recovery_checks.store(0, Ordering::Relaxed);
            select_tunnel_path(direct_ready, reverse_ready)
        }
    }
}

fn tunnel_path_check_interval(current: TunnelPath, configured: Duration) -> Duration {
    if current == TunnelPath::Unavailable {
        Duration::from_secs(1)
    } else {
        configured
    }
}

fn publish_tunnel_path(state: &AtomicU8, next: TunnelPath) {
    let previous = state.swap(next as u8, Ordering::AcqRel);
    if previous != next as u8 {
        if next == TunnelPath::Unavailable {
            warn!(
                "No tunnel connection is available: all Direct and Reverse paths failed across the configured protocols."
            );
        } else {
            info!("🔀 Active tunnel path changed: {:?}", next);
        }
    }
}

async fn refresh_tunnel_path(
    pool: &[(Arc<Mutex<ConnectionState>>, ActiveNode)],
    reverse_enabled: bool,
    state: &AtomicU8,
    direct_recovery_checks: &AtomicUsize,
    periodic_check: bool,
    update_lock: &Mutex<()>,
) {
    let _update_guard = update_lock.lock().await;
    let direct_ready = has_direct_path(pool).await;
    let reverse_ready = reverse_enabled && crate::reverse::has_ready_slot();
    let current = TunnelPath::load(state);
    let next = select_stable_tunnel_path(
        current,
        direct_ready,
        reverse_ready,
        periodic_check,
        direct_recovery_checks,
    );
    publish_tunnel_path(state, next);
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            client: None,
            mux: None,
            consecutive_errors: 0,
            ewma_latency: 500.0,
        }
    }
}

/// A tunnel chosen for one user connection: a Direct pool slot, or a parked Reverse stream.
enum Chosen {
    Direct(
        h2::client::SendRequest<Bytes>,
        Arc<Mutex<ConnectionState>>,
        ActiveNode,
    ),
    /// A Direct pool slot that is connected over WssMux.
    Mux(
        crate::wssmux::MuxClient,
        Arc<Mutex<ConnectionState>>,
        ActiveNode,
    ),
    Reverse(String),
}

#[derive(Debug, Clone)]
pub struct ActiveNode {
    pub location: String,
    pub sni: String,
    pub share_sni: u32,
}

async fn connect_h2_node(
    node: &ActiveNode,
    clean_ips: &[String],
    tls_connector: &TlsConnector,
    // true when another protocol can take over: prove the peer really speaks HTTP/2 (an h2
    // handshake completes locally even if the server closes the connection right away).
    verify: bool,
) -> Result<h2::client::SendRequest<Bytes>, String> {
    let (sni_host, sni_port) = if let Some(idx) = node.sni.rfind(':') {
        (&node.sni[..idx], &node.sni[idx + 1..])
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
            let addrs = tokio::net::lookup_host(&addr_str)
                .await
                .map_err(|e| e.to_string())?
                .collect::<Vec<_>>();
            for addr in addrs {
                if let Ok(stream) =
                    crate::anti_loop::safe_connect(addr, std::time::Duration::from_secs(5)).await
                {
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

    let domain = rustls::pki_types::ServerName::try_from(sni_host)
        .map_err(|e| e.to_string())?
        .to_owned();
    let tls_stream = tls_connector
        .connect(domain, tcp)
        .await
        .map_err(|e| e.to_string())?;

    // Use aggressive HTTP/2 flow control windows (Default 65KB is too slow for WAN)
    let (client, mut conn) = h2::client::Builder::new()
        .initial_window_size(8_388_608) // 8 MB Stream Window (High BDP throughput)
        .initial_connection_window_size(1_073_741_824) // 1 GB Connection Window
        .max_frame_size(65_535) // 64 KB max frame (Prevents HoL blocking on lossy networks)
        .handshake(tls_stream)
        .await
        .map_err(|e| e.to_string())?;

    let mut ping_pong = conn.ping_pong().unwrap();
    let (verify_tx, verify_rx) = tokio::sync::oneshot::channel::<bool>();
    let mut verify_tx = if verify { Some(verify_tx) } else { None };
    tokio::spawn(async move {
        let ping_loop = async move {
            if let Some(tx) = verify_tx.take() {
                let ok = matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        ping_pong.ping(h2::Ping::opaque())
                    )
                    .await,
                    Ok(Ok(_))
                );
                let _ = tx.send(ok);
                if !ok {
                    return;
                }
            }
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    ping_pong.ping(h2::Ping::opaque()),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    _ => {
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
    if verify {
        match tokio::time::timeout(std::time::Duration::from_secs(4), verify_rx).await {
            Ok(Ok(true)) => {}
            _ => return Err("h2 peer did not answer a PING (not an HTTP/2 endpoint?)".to_string()),
        }
    }
    Ok(client)
}

static CLIENT_DEAD_TARGETS: std::sync::OnceLock<
    std::sync::RwLock<std::collections::HashSet<String>>,
> = std::sync::OnceLock::new();

pub fn get_client_dead_targets() -> &'static std::sync::RwLock<std::collections::HashSet<String>> {
    CLIENT_DEAD_TARGETS.get_or_init(|| std::sync::RwLock::new(std::collections::HashSet::new()))
}

// ==========================================================================
// ADMIN PANEL HOOKS (read-only view of the Direct pool for `admin.rs`)
// ==========================================================================

struct AdminHandle {
    pool: Arc<Vec<(Arc<Mutex<ConnectionState>>, ActiveNode)>>,
    path: Arc<AtomicU8>,
    clean_ips: Arc<tokio::sync::RwLock<Vec<String>>>,
    clean_ip_file: String,
    scanner_refresh: Option<Arc<tokio::sync::Notify>>,
    scan_generation: Arc<std::sync::atomic::AtomicU64>,
    cache_lock: Arc<tokio::sync::Mutex<()>>,
    protocols: Vec<Proto>,
}

static ADMIN_HANDLE: std::sync::RwLock<Option<Arc<AdminHandle>>> = std::sync::RwLock::new(None);

fn admin_handle() -> Option<Arc<AdminHandle>> {
    ADMIN_HANDLE.read().unwrap().clone()
}

/// "starting" | "direct" | "reverse" | "unavailable" (None before the client has started).
pub fn admin_path_name() -> Option<&'static str> {
    let h = admin_handle()?;
    Some(match TunnelPath::load(&h.path) {
        TunnelPath::Starting => "starting",
        TunnelPath::Direct => "direct",
        TunnelPath::Reverse => "reverse",
        TunnelPath::Unavailable => "unavailable",
    })
}

/// Number of Direct pool slots currently connected over (HTTP/2, WssMux).
pub async fn admin_pool_counts() -> (usize, usize) {
    let Some(h) = admin_handle() else {
        return (0, 0);
    };
    let (mut h2, mut wss) = (0, 0);
    for (slot, _) in h.pool.iter() {
        if let Ok(g) = tokio::time::timeout(Duration::from_millis(100), slot.lock()).await {
            if g.client.is_some() {
                h2 += 1;
            } else if g.mux.as_ref().is_some_and(crate::wssmux::MuxClient::alive) {
                wss += 1;
            }
        }
    }
    (h2, wss)
}

/// Snapshot of the Direct pool, grouped per node, plus the clean-IP list.
pub async fn admin_snapshot() -> Option<serde_json::Value> {
    let h = admin_handle()?;
    struct Agg {
        location: String,
        sni: String,
        share_sni: u32,
        slots: usize,
        h2: usize,
        wss: usize,
        busy: usize,
        lat_sum: f64,
        lat_n: usize,
        errors: u32,
    }
    let mut nodes: Vec<Agg> = Vec::new();
    for (slot, node) in h.pool.iter() {
        let idx = match nodes
            .iter()
            .position(|a| a.sni == node.sni && a.location == node.location)
        {
            Some(i) => i,
            None => {
                nodes.push(Agg {
                    location: node.location.clone(),
                    sni: node.sni.clone(),
                    share_sni: node.share_sni,
                    slots: 0,
                    h2: 0,
                    wss: 0,
                    busy: 0,
                    lat_sum: 0.0,
                    lat_n: 0,
                    errors: 0,
                });
                nodes.len() - 1
            }
        };
        let a = &mut nodes[idx];
        a.slots += 1;
        match tokio::time::timeout(Duration::from_millis(100), slot.lock()).await {
            Ok(g) => {
                let is_h2 = g.client.is_some();
                let is_ws = !is_h2 && g.mux.as_ref().is_some_and(crate::wssmux::MuxClient::alive);
                if is_h2 {
                    a.h2 += 1;
                } else if is_ws {
                    a.wss += 1;
                }
                if is_h2 || is_ws {
                    a.lat_sum += g.ewma_latency;
                    a.lat_n += 1;
                }
                a.errors = a.errors.max(g.consecutive_errors);
            }
            Err(_) => a.busy += 1,
        }
    }
    let (mut total_h2, mut total_wss, mut total_slots) = (0, 0, 0);
    let nodes_json: Vec<serde_json::Value> = nodes
        .iter()
        .map(|a| {
            total_h2 += a.h2;
            total_wss += a.wss;
            total_slots += a.slots;
            serde_json::json!({
                "location": a.location,
                "sni": a.sni,
                "share_sni": a.share_sni,
                "slots": a.slots,
                "h2": a.h2,
                "wssmux": a.wss,
                "down": a.slots - a.h2 - a.wss,
                "latency_ms": if a.lat_n > 0 { Some((a.lat_sum / a.lat_n as f64).round()) } else { None },
                "errors": a.errors,
                "cooling_h2": crate::transport::is_cooling(&a.sni, Proto::H2),
                "cooling_wssmux": crate::transport::is_cooling(&a.sni, Proto::WssMux),
            })
        })
        .collect();
    let ips = h.clean_ips.read().await;
    let mut dead: Vec<String> = get_client_dead_targets().read().unwrap().iter().cloned().collect();
    dead.sort();
    Some(serde_json::json!({
        "path": admin_path_name(),
        "protocols": h.protocols.iter().map(|p| p.name()).collect::<Vec<_>>(),
        "pool": { "slots": total_slots, "h2": total_h2, "wssmux": total_wss, "down": total_slots - total_h2 - total_wss },
        "nodes": nodes_json,
        "clean_ips": { "count": ips.len(), "list": ips.iter().take(300).collect::<Vec<_>>(), "scanner_running": h.scanner_refresh.is_some() },
        "dead_targets": dead,
    }))
}

/// Clears the active and persisted clean-IP cache, then requests an immediate scanner cycle.
pub async fn admin_clear_clean_ips() -> std::io::Result<usize> {
    let handle = admin_handle().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "client is not initialized",
        )
    })?;
    let refresh = handle.scanner_refresh.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "direct IP scanner is not running",
        )
    })?;

    let _cache_guard = handle.cache_lock.lock().await;
    let mut ips = handle.clean_ips.write().await;
    let cleared = ips.len();
    if let Some(parent) = std::path::Path::new(&handle.clean_ip_file)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    let cache_file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&handle.clean_ip_file)
        .await?;
    cache_file.sync_all().await?;
    handle
        .scan_generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    ips.clear();
    drop(ips);
    drop(_cache_guard);
    refresh.notify_one();
    Ok(cleared)
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
    // Reverse mode (CDN-compatible; runs together with Direct): publish valid locations and context.
    crate::reverse::set_known_locations(
        cfg.remotes
            .iter()
            .map(|l| (l.location.clone(), l.share_sni.unwrap_or(0)))
            .collect(),
    );
    let reverse_ctx = crate::reverse::configure(&cfg);
    let reverse_enabled = reverse_ctx.is_some();
    // Direct tunnel protocol priority (`[client].protocols`): first = preferred, others = fallbacks.
    let protocols = crate::transport::parse_list(cfg.protocols.as_ref(), "client");
    if !flat_remotes.is_empty() {
        debug!(
            "🔀 Direct tunnel protocols (priority): {}",
            protocols
                .iter()
                .map(|p| p.name())
                .collect::<Vec<_>>()
                .join(" > ")
        );
    }

    if flat_remotes.is_empty() {
        if reverse_enabled {
            tracing::info!(
                "No direct remote SNIs defined. Running in reverse-only mode (waiting for servers to connect)."
            );
        } else {
            tracing::info!(
                "No remote servers defined in client config. GhostRPC tunnel will not be established."
            );
        }
    }

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls_config_h2 = rustls::ClientConfig::builder()
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();
    tls_config_h2.alpn_protocols = vec![b"h2".to_vec()];
    let tls_connector = Arc::new(TlsConnector::from(Arc::new(tls_config_h2)));

    let pool_per_node = cfg.pool_size_per_node.unwrap_or(8);
    let total_pool_size = flat_remotes.len() * pool_per_node;

    if !flat_remotes.is_empty() {
        debug!(
            "Initializing Distributed Pool ({} nodes x {} conns = {} total streams)...",
            flat_remotes.len(),
            pool_per_node,
            total_pool_size
        );
    }

    let mut pool: Vec<(Arc<Mutex<ConnectionState>>, ActiveNode)> = Vec::new();
    for _ in 0..pool_per_node {
        for remote in &flat_remotes {
            pool.push((
                Arc::new(Mutex::new(ConnectionState::default())),
                remote.clone(),
            ));
        }
    }
    let pool = Arc::new(pool);

    // Pre-load clean IPs from file BEFORE starting anything
    let clean_ip_file = cfg
        .clean_ip_file
        .clone()
        .unwrap_or_else(|| "ips/clean_ips.txt".to_string());
    let source_ips_file = cfg
        .source_ips_file
        .clone()
        .unwrap_or_else(|| "ips/cloudflare_ip_ranges.txt".to_string());
    let check_interval_minutes = cfg.check_interval_minutes.unwrap_or(60);
    if cfg.tunnel_health_check_interval_minutes == Some(0) {
        warn!("⚠️ tunnel_health_check_interval_minutes must be at least 1; using 1 minute.");
    }
    let tunnel_health_check_interval_minutes =
        effective_tunnel_health_interval(cfg.tunnel_health_check_interval_minutes);
    let max_ping_ms = cfg.max_ping_ms.unwrap_or(150);

    let initial_ips: Vec<String> = match tokio::fs::read_to_string(&clean_ip_file).await {
        Ok(content) => crate::scanner::parse_clean_ips(&content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            tracing::error!("Failed to read clean-IP cache {}: {}", clean_ip_file, e);
            Vec::new()
        }
    };

    let clean_ips_global = Arc::new(tokio::sync::RwLock::new(initial_ips));
    let scan_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let cache_lock = Arc::new(tokio::sync::Mutex::new(()));

    // Start IP Scanner (background periodic refresh)
    let scanner_refresh = if !flat_remotes.is_empty() {
        let refresh = Arc::new(tokio::sync::Notify::new());
        let scanner = crate::scanner::Scanner::new(
            clean_ip_file.clone(),
            source_ips_file,
            check_interval_minutes,
            max_ping_ms,
            clean_ips_global.clone(),
            cfg.remotes
                .iter()
                .filter(|r| !r.sni.is_empty())
                .cloned()
                .collect(),
            tls_connector.clone(),
            cfg.scanner_cdn.clone(),
            cfg.hidden_path.clone(),
            cfg.secret.clone().unwrap_or_default(),
            protocols.clone(),
            refresh.clone(),
            scan_generation.clone(),
            cache_lock.clone(),
        );
        scanner.start(cancel_token.clone());
        Some(refresh)
    } else {
        None
    };

    // Eager Direct Pool Maintainer (Background Connect)
    if !flat_remotes.is_empty() {
        for (slot_arc, remote) in pool.iter() {
            let slot = slot_arc.clone();
            let remote = remote.clone();
            let tls = tls_connector.clone();
            let token = cancel_token.clone();
            let clean_ips = clean_ips_global.clone();
            let protocols = protocols.clone();
            let hidden_path = cfg.hidden_path.clone();
            let secret = cfg.secret.clone().unwrap_or_default();

            tokio::spawn(async move {
                let mut backoff_ms: u64 = 500;
                let max_backoff_ms: u64 = 30000;

                loop {
                    if token.is_cancelled() {
                        break;
                    }

                    let usable = {
                        let mut g = slot.lock().await;
                        if g.mux.as_ref().map_or(false, |m| !m.alive()) {
                            g.mux = None; // the WssMux session ended: reconnect
                        }
                        g.client.is_some() || g.mux.is_some()
                    };
                    if !usable {
                        let start_time = tokio::time::Instant::now();
                        let current_ips = clean_ips.read().await.clone();
                        if !current_ips.is_empty() {
                            // Try the protocols in priority order (a protocol that failed recently
                            // goes last) and switch automatically to the next one on failure.
                            let mut connected = false;
                            for proto in crate::transport::order(&remote.sni, &protocols) {
                                match proto {
                                    Proto::H2 => match connect_h2_node(
                                        &remote,
                                        &current_ips,
                                        &tls,
                                        protocols.len() > 1,
                                    )
                                    .await
                                    {
                                        Ok(new_client) => {
                                            let mut guard = slot.lock().await;
                                            guard.client = Some(new_client);
                                            guard.mux = None;
                                            guard.consecutive_errors = 0;
                                            guard.ewma_latency =
                                                start_time.elapsed().as_millis() as f64;
                                            tracing::trace!(
                                                "🔥 Pool Maintainer: Warmed up h2 connection to {} ({}ms)",
                                                remote.sni,
                                                guard.ewma_latency
                                            );
                                            connected = true;
                                        }
                                        Err(_e) => {
                                            // (h2 is only marked healthy again after a tunnel request succeeded)
                                            crate::transport::record_fail(&remote.sni, Proto::H2);
                                        }
                                    },
                                    Proto::WssMux => {
                                        match crate::wssmux::connect_direct(
                                            &remote.sni,
                                            &current_ips,
                                            &hidden_path,
                                            &secret,
                                        )
                                        .await
                                        {
                                            Ok(mux) => {
                                                let mut guard = slot.lock().await;
                                                guard.mux = Some(mux);
                                                guard.client = None;
                                                guard.consecutive_errors = 0;
                                                guard.ewma_latency =
                                                    start_time.elapsed().as_millis() as f64;
                                                tracing::trace!(
                                                    "🔥 Pool Maintainer: Warmed up wssmux session to {} ({}ms)",
                                                    remote.sni,
                                                    guard.ewma_latency
                                                );
                                                crate::transport::record_ok(
                                                    &remote.sni,
                                                    Proto::WssMux,
                                                );
                                                connected = true;
                                            }
                                            Err(_e) => {
                                                crate::transport::record_fail(
                                                    &remote.sni,
                                                    Proto::WssMux,
                                                );
                                            }
                                        }
                                    }
                                }
                                if connected {
                                    break;
                                }
                            }
                            if connected {
                                // Reset backoff on success
                                backoff_ms = 500;
                            } else {
                                // Exponential Backoff with Jitter (Enterprise Grade)
                                backoff_ms =
                                    std::cmp::min(max_backoff_ms, (backoff_ms as f64 * 1.5) as u64);
                                let jitter = (rand::random::<u64>() % 1000) + 100;
                                backoff_ms = std::cmp::min(max_backoff_ms, backoff_ms + jitter);
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

        // Complete the Direct startup checks before considering Reverse.
        let warmup_start = tokio::time::Instant::now();
        let warmup_timeout = Duration::from_secs(30);
        loop {
            if cancel_token.is_cancelled() {
                return;
            }
            if has_direct_path(&pool).await {
                debug!(
                    "✅ Direct startup check completed in {}ms.",
                    warmup_start.elapsed().as_millis()
                );
                break;
            }
            if warmup_start.elapsed() > warmup_timeout {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    let active_tunnel_path = Arc::new(AtomicU8::new(TunnelPath::Starting as u8));
    let direct_recovery_checks = Arc::new(AtomicUsize::new(0));
    let tunnel_path_update_lock = Arc::new(Mutex::new(()));
    *ADMIN_HANDLE.write().unwrap() = Some(Arc::new(AdminHandle {
        pool: pool.clone(),
        path: active_tunnel_path.clone(),
        clean_ips: clean_ips_global.clone(),
        clean_ip_file,
        scanner_refresh,
        scan_generation,
        cache_lock,
        protocols: protocols.clone(),
    }));
    refresh_tunnel_path(
        &pool,
        reverse_enabled,
        &active_tunnel_path,
        &direct_recovery_checks,
        false,
        &tunnel_path_update_lock,
    )
    .await;
    debug!(
        "🩺 Tunnel path monitor interval: {} minute(s), preference: Direct then Reverse.",
        tunnel_health_check_interval_minutes
    );

    let monitor_pool = pool.clone();
    let monitor_path = active_tunnel_path.clone();
    let monitor_recovery_checks = direct_recovery_checks.clone();
    let monitor_update_lock = tunnel_path_update_lock.clone();
    let monitor_token = cancel_token.clone();
    let monitor_interval =
        Duration::from_secs(tunnel_health_check_interval_minutes.saturating_mul(60));
    tokio::spawn(async move {
        loop {
            let wait =
                tunnel_path_check_interval(TunnelPath::load(&monitor_path), monitor_interval);
            tokio::select! {
                _ = monitor_token.cancelled() => break,
                _ = tokio::time::sleep(wait) => {
                    refresh_tunnel_path(
                        &monitor_pool,
                        reverse_enabled,
                        &monitor_path,
                        &monitor_recovery_checks,
                        true,
                        &monitor_update_lock,
                    ).await;
                }
            }
        }
    });

    let conn_counter = Arc::new(AtomicUsize::new(0));

    // NEW: Load Certificates for Client-Side Web Server Multiplexing
    let mut acceptor_opt = None;
    let mut web_server_routes = Vec::new();
    if let Some(ws_configs) = &cfg.web_server {
        for ws in ws_configs {
            tracing::info!(
                "🚀 Admin Panel / Web Server configured for domain: {}",
                ws.domain
            );
            tracing::info!("👉 Access the panel at: https://{}", ws.domain);
        }
        if !ws_configs.is_empty() {
            web_server_routes = ws_configs.clone();
            let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
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
                                        let certs: Vec<_> = rustls_pemfile::certs(
                                            &mut std::io::BufReader::new(cert_file),
                                        )
                                        .map(|r| r.unwrap())
                                        .collect();
                                        if let Ok(Some(key)) = rustls_pemfile::private_key(
                                            &mut std::io::BufReader::new(key_file),
                                        ) {
                                            if let Ok(sign_key) =
                                                rustls::crypto::ring::sign::any_supported_type(&key)
                                            {
                                                let certified_key = rustls::sign::CertifiedKey::new(
                                                    certs, sign_key,
                                                );
                                                let _ =
                                                    resolver.add(&domain, certified_key.clone());
                                                let _ = resolver.add(
                                                    &format!("*.{}", domain),
                                                    certified_key.clone(),
                                                );
                                                for ws in &web_server_routes {
                                                    if ws.domain.ends_with(&domain) {
                                                        let _ = resolver
                                                            .add(&ws.domain, certified_key.clone());
                                                    }
                                                }
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
                    "⚠️ هیچ گواهینامه‌ای در مسیر certs پیدا نشد! ارتباطات TLS کلاینت ممکن است با خطا مواجه شوند."
                );
            }

            let mut tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(std::sync::Arc::new(resolver));
            tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            acceptor_opt = Some(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
                tls_config,
            )));
        }
    }
    let local_acceptor_global = std::sync::Arc::new(acceptor_opt);
    let local_ws_routes_global = std::sync::Arc::new(web_server_routes);

    let mut mapped_routes = std::collections::HashMap::new();
    for loc in cfg.remotes.iter() {
        crate::routing::parse_port_mappings(
            &loc.port_mappings,
            Some(&loc.location),
            &mut mapped_routes,
        );
    }

    if cfg.web_server.is_some() {
        if !mapped_routes.contains_key("0.0.0.0:443") && !mapped_routes.contains_key("[::]:443") {
            mapped_routes.insert(
                "0.0.0.0:443".to_string(),
                crate::config::Route {
                    default_upstream: None,
                    target_locations: std::collections::HashMap::new(),
                    sni_rules: std::collections::HashMap::new(),
                },
            );
        }
        if !mapped_routes.contains_key("0.0.0.0:80") && !mapped_routes.contains_key("[::]:80") {
            mapped_routes.insert(
                "0.0.0.0:80".to_string(),
                crate::config::Route {
                    default_upstream: None,
                    target_locations: std::collections::HashMap::new(),
                    sni_rules: std::collections::HashMap::new(),
                },
            );
        }
    }
    for (local_bind, route_table) in &mapped_routes {
        if let Some(def) = &route_table.default_upstream {
            tracing::debug!("Mapping {} -> Default Upstream: {}", local_bind, def);
        }
        for (sni, up) in &route_table.sni_rules {
            tracing::debug!("Mapping {} (SNI: {}) -> Upstream: {}", local_bind, sni, up);
        }
    }
    if let Some(ctx) = &reverse_ctx {
        if let Some(bind) = ctx.bind.clone() {
            if mapped_routes.contains_key(&bind) {
                info!(
                    "🔁 Reverse tunnels share {} with the local listener (routed by reverse_tunnel_sni).",
                    bind
                );
            } else {
                let (c, t) = (ctx.clone(), cancel_token.clone());
                tokio::spawn(async move { crate::reverse::run_listener(c, bind, t).await });
            }
        }
    }
    for (local_bind, route_table) in mapped_routes {
        let mut listener_opt = None;
        for i in 0..10 {
            match crate::net_utils::create_reuseport_listener(&local_bind) {
                Ok(l) => {
                    listener_opt = Some(l);
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to bind {} (attempt {}/10): {}. Retrying in 200ms...",
                        local_bind,
                        i + 1,
                        e
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
        let listener = match listener_opt {
            Some(l) => l,
            None => {
                error!("❌ FATAL: Could not bind {} after 10 attempts.", local_bind);
                continue;
            }
        };
        debug!(
            "🚀 Listener active on {} with {} SNI rules",
            local_bind,
            route_table.sni_rules.len()
        );

        let cfg_clone = cfg.clone();

        let pool_clone = pool.clone();
        let active_path_clone = active_tunnel_path.clone();
        let recovery_checks_clone = direct_recovery_checks.clone();
        let path_update_lock_clone = tunnel_path_update_lock.clone();
        let protocol_priority = protocols.clone();

        let counter_clone = conn_counter.clone();
        let token = cancel_token.clone();

        let local_acceptor = local_acceptor_global.clone();
        let local_ws_routes = local_ws_routes_global.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        info!("🛑 Stopping listener on {} due to Hot-Reload", local_bind);
                        break;
                    }
                    accept_res = listener.accept() => {
                        if let Ok((mut local_tcp, peer)) = accept_res {
                            if crate::anti_loop::is_loop(&peer) {
                                crate::net_utils::log_rate_limited(&format!("anti_loop_{}", peer), "🛑 Anti-Loop Firewall: Dropped self-loop connection in client main.");
                                continue;
                            }
                            let _ = local_tcp.set_nodelay(true);
                            crate::net_utils::tune_socket_buffers(&local_tcp);
                            enable_tcp_keepalive(&local_tcp);
                            let c_id = counter_clone.fetch_add(1, Ordering::SeqCst);

                            let route_table = route_table.clone();
                            let pool_clone = pool_clone.clone();
                            let cfg_inner = cfg_clone.clone();
                            let active_path = active_path_clone.clone();
                            let direct_recovery_checks = recovery_checks_clone.clone();
                            let path_update_lock = path_update_lock_clone.clone();
                            let protocol_priority = protocol_priority.clone();
                            let acceptor_clone = local_acceptor.clone();
                            let ws_routes_clone = local_ws_routes.clone();

                            tokio::spawn(async move {
                                let mut extracted_sni = None;
                                let mut initial_buf = [0u8; 8192];
                                let mut initial_len = 0;
                                let _ = tokio::time::timeout(Duration::from_millis(500), async {
                                    loop {
                                        if initial_len >= 8192 { break; }
                                        let n = match local_tcp.read(&mut initial_buf[initial_len..]).await {
                                            Ok(n) if n > 0 => n,
                                            _ => break,
                                        };
                                        initial_len += n;

                                        if initial_buf[0] == 0x16 {
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
                                        } else if crate::routing::is_http_request(&initial_buf[..initial_len]) {
                                            if let Some(host) = crate::routing::extract_http_host(&initial_buf[..initial_len]) {
                                                extracted_sni = Some(host);
                                                break;
                                            } else if initial_buf[..initial_len].windows(4).any(|w| w == b"\r\n\r\n")
                                                || initial_buf[..initial_len].windows(2).any(|w| w == b"\n\n")
                                            {
                                                break;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                }).await;
                                let initial_data = initial_buf[..initial_len].to_vec();

                                // Reverse tunnel dialed by a server on a shared port (matched by SNI)
                                if initial_len > 0 && initial_buf[0] == 0x16 {
                                    if let Some(sni) = &extracted_sni {
                                        if crate::reverse::sni_matches(sni) {
                                            let prefixed = crate::prefixed_stream::PrefixedStream { prefix: initial_data, inner: local_tcp };
                                            crate::reverse::handle_inbound(prefixed, peer).await;
                                            return;
                                        }
                                    }
                                }

                                // L4/L7 Multiplexing Logic: Check if SNI matches Web Server
                                let mut is_web_server = false;
                                let mut is_plaintext_http = false;
                                if let Some(sni) = &extracted_sni {
                                    if ws_routes_clone.iter().any(|c| *sni == c.domain || sni.ends_with(&format!(".{}", c.domain))) {
                                        is_web_server = true;
                                        if initial_buf[0] != 0x16 {
                                            is_plaintext_http = true;
                                        }
                                    }
                                }



                                if is_web_server {
                                    let prefixed_tcp = crate::prefixed_stream::PrefixedStream {
                                        prefix: initial_data,
                                        inner: local_tcp,
                                    };
                                    let sni = extracted_sni.clone().unwrap_or_default();

                                    if is_plaintext_http {
                                        tracing::debug!("🌐 [Client Web Server] Handling direct HTTP/1.1 plaintext connection for domain: {}", sni);
                                        let mut matched_routes: Vec<crate::config::WebServerConfig> = ws_routes_clone.iter()
                                            .filter(|c| *sni == c.domain)
                                            .cloned()
                                            .collect();
                                        if matched_routes.is_empty() {
                                            matched_routes = ws_routes_clone.iter()
                                                .filter(|c| sni.ends_with(&format!(".{}", c.domain)))
                                                .cloned()
                                                .collect();
                                        }
                                        if !matched_routes.is_empty() {
                                            crate::web_server::handle_web_server_connection(prefixed_tcp, ws_routes_clone.to_vec(), Some(peer.ip())).await;
                                        }
                                    } else {
                                        if let Some(acceptor) = &*acceptor_clone {
                                            match tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(prefixed_tcp)).await {
                                                Ok(Ok(tls_stream)) => {
                                                    let tls_sni = tls_stream.get_ref().1.server_name().map(|s| s.to_string()).unwrap_or(sni.clone());
                                                    let mut matched_routes: Vec<crate::config::WebServerConfig> = ws_routes_clone.iter()
                                                        .filter(|c| tls_sni == c.domain)
                                                        .cloned()
                                                        .collect();
                                                    if matched_routes.is_empty() {
                                                        matched_routes = ws_routes_clone.iter()
                                                            .filter(|c| tls_sni.ends_with(&format!(".{}", c.domain)))
                                                            .cloned()
                                                            .collect();
                                                    }
                                                    if !matched_routes.is_empty() {
                                                        crate::web_server::handle_web_server_connection(tls_stream, ws_routes_clone.to_vec(), Some(peer.ip())).await;
                                                    }
                                                },
                                                Ok(Err(e)) => tracing::error!("❌ [Web Server] TLS Handshake failed for {}: {}", sni, e),
                                                Err(_) => tracing::error!("❌ [Web Server] TLS Handshake timed out for {}", sni),
                                            }
                                        }
                                    }
                                    return;
                                }

                                let target_up = if let Some(sni) = &extracted_sni {
                                    trace!("[Conn #{}] Detected SNI: {}", c_id, sni);
                                    route_table.sni_rules.get(sni).cloned().or_else(|| route_table.default_upstream.clone())
                                } else {
                                    route_table.default_upstream.clone()
                                };

                                let target_up = match target_up {
                                    Some(t) => {
                                        if !t.contains(':') && t.parse::<u16>().is_ok() {
                                            if let Some(sni) = &extracted_sni {
                                                format!("{}:{}", sni, t)
                                            } else {
                                                t
                                            }
                                        } else {
                                            t
                                        }
                                    },
                                    None => {
                                        debug!("[Conn #{}] Connection from {} dropped: No matching SNI or default route.", c_id, peer);
                                        return;
                                    }
                                };

                                debug!("[Conn #{}] Accepted {} -> Routed to {}", c_id, peer, target_up);

                                let mut selected_path = TunnelPath::load(&active_path);
                                let path_wait_deadline =
                                    tokio::time::Instant::now() + TUNNEL_PATH_STARTUP_GRACE_PERIOD;
                                while !matches!(
                                    selected_path,
                                    TunnelPath::Direct | TunnelPath::Reverse
                                ) && tokio::time::Instant::now() < path_wait_deadline
                                {
                                    refresh_tunnel_path(
                                        &pool_clone,
                                        reverse_enabled,
                                        &active_path,
                                        &direct_recovery_checks,
                                        false,
                                        &path_update_lock,
                                    )
                                    .await;
                                    selected_path = TunnelPath::load(&active_path);
                                    if !matches!(
                                        selected_path,
                                        TunnelPath::Direct | TunnelPath::Reverse
                                    ) {
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                    }
                                }
                                if !matches!(selected_path, TunnelPath::Direct | TunnelPath::Reverse) {
                                    return;
                                }

                                let (mut local_read, mut local_write) = local_tcp.into_split();

                                let mut final_send_stream = None;
                                let mut final_mux: Option<crate::wssmux::MuxStream> = None;
                                let mut final_body: Option<h2::RecvStream> = None;
                                let mut final_leftover = Bytes::new();
                                let mut global_retries = 0;
                                let mut failed_snis = std::collections::HashSet::new();
                                let mut selected_direct_protocol = None;

                                while global_retries < 5 {
                                    let mut ready_client = None;
                                    let mut retries = 0;
                                    while retries < 5 {
                                        let mut best_client = None;
                                        let mut best_mux: Option<crate::wssmux::MuxClient> = None;
                                        let mut best_slot = None;
                                        let mut best_remote = None;
                                        let mut lowest_latency = f64::MAX;
                                        let mut best_protocol_priority = usize::MAX;
                                        let total_pool_size = pool_clone.len();

                                        for i in 0..total_pool_size {
                                            if selected_path != TunnelPath::Direct {
                                                break;
                                            }
                                            let (pool_slot, target_remote) = &pool_clone[i];

                                            if failed_snis.contains(&target_remote.sni) {
                                                continue;
                                            }

                                            let mut slot_guard = pool_slot.lock().await;

                                            if selected_direct_protocol != Some(Proto::WssMux)
                                                && !crate::transport::is_cooling(
                                                    &target_remote.sni,
                                                    Proto::H2,
                                                )
                                            {
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
                                                        let priority = protocol_priority
                                                            .iter()
                                                            .position(|p| *p == Proto::H2)
                                                            .unwrap_or(usize::MAX - 1);
                                                        if priority < best_protocol_priority
                                                            || (priority == best_protocol_priority && score < lowest_latency)
                                                        {
                                                            lowest_latency = score;
                                                            best_protocol_priority = priority;
                                                            best_client = Some(c_clone);
                                                            best_mux = None;
                                                            best_slot = Some(pool_slot.clone());
                                                            best_remote = Some(target_remote.clone());
                                                        }
                                                    } else {
                                                        slot_guard.client = None;
                                                        crate::transport::record_fail(&target_remote.sni, Proto::H2);
                                                    }
                                                }
                                            }

                                            // WssMux session in this slot (same latency + location scoring as h2)
                                            if selected_direct_protocol != Some(Proto::H2)
                                                && slot_guard.client.is_none()
                                                && !crate::transport::is_cooling(
                                                    &target_remote.sni,
                                                    Proto::WssMux,
                                                )
                                            {
                                                if let Some(m) = slot_guard.mux.clone() {
                                                    if m.alive() {
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
                                                        let priority = protocol_priority
                                                            .iter()
                                                            .position(|p| *p == Proto::WssMux)
                                                            .unwrap_or(usize::MAX - 1);
                                                        if priority < best_protocol_priority
                                                            || (priority == best_protocol_priority && score < lowest_latency)
                                                        {
                                                            lowest_latency = score;
                                                            best_protocol_priority = priority;
                                                            best_client = None;
                                                            best_mux = Some(m);
                                                            best_slot = Some(pool_slot.clone());
                                                            best_remote = Some(target_remote.clone());
                                                        }
                                                    } else {
                                                        slot_guard.mux = None;
                                                        crate::transport::record_fail(&target_remote.sni, Proto::WssMux);
                                                    }
                                                }
                                            }
                                        }

                                        // Use Reverse only when it is the monitored path, or when Direct has
                                        // no ready connection eligible for this target.
                                        let mut best_reverse: Option<(String, f64)> = None;
                                        let allow_reverse = selected_path == TunnelPath::Reverse
                                            || (selected_path == TunnelPath::Direct
                                                && selected_direct_protocol.is_none()
                                                && best_client.is_none()
                                                && best_mux.is_none());
                                        if allow_reverse && reverse_enabled {
                                            for (loc, share, ewma) in crate::reverse::candidates() {
                                                if failed_snis.contains(&format!("rev:{}", loc)) {
                                                    continue;
                                                }
                                                let mut penalty = 0.0;
                                                if let Some(pref) = route_table.target_locations.get(&target_up) {
                                                    match share {
                                                        // Labeled tunnel of another location: only if it shares its SNI.
                                                        Some(share) => {
                                                            if loc != *pref {
                                                                if share == 0 {
                                                                    continue;
                                                                }
                                                                penalty = 10000.0 + (share as f64 * 100.0);
                                                            }
                                                        }
                                                        // Unlabeled tunnel: a pure forwarder usable for every target, but
                                                        // always behind the tunnel of the target's own location.
                                                        None => {
                                                            penalty = 10000.0 + 100.0;
                                                        }
                                                    }
                                                }
                                                let score = ewma + penalty;
                                                if score < lowest_latency && best_reverse.as_ref().map_or(true, |(_, s)| score < *s) {
                                                    best_reverse = Some((loc, score));
                                                }
                                            }
                                        }

                                        if let Some((loc, _)) = best_reverse {
                                            selected_path = TunnelPath::Reverse;
                                            ready_client = Some(Chosen::Reverse(loc));
                                            break;
                                        } else if let Some(m) = best_mux {
                                            ready_client = Some(Chosen::Mux(m, best_slot.unwrap(), best_remote.unwrap()));
                                            break;
                                        } else if let Some(c) = best_client {
                                            ready_client = Some(Chosen::Direct(c, best_slot.unwrap(), best_remote.unwrap()));
                                            break;
                                        } else {
                                            retries += 1;
                                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                        }
                                    }

                                    if ready_client.is_none() {
                                        refresh_tunnel_path(
                                            &pool_clone,
                                            reverse_enabled,
                                            &active_path,
                                            &direct_recovery_checks,
                                            false,
                                            &path_update_lock,
                                        )
                                        .await;
                                        return;
                                    }

                                    let (mut c, pool_slot, target_remote) = match ready_client.unwrap() {
                                        Chosen::Direct(c, slot, remote) => {
                                            selected_direct_protocol = Some(Proto::H2);
                                            (c, slot, remote)
                                        }
                                        Chosen::Mux(m, slot, remote) => {
                                            selected_direct_protocol = Some(Proto::WssMux);
                                            let is_local = target_up.starts_with("127.") || target_up.starts_with("localhost") || target_up.starts_with("[::1]") || target_up.starts_with("10.") || target_up.starts_with("192.168.") || target_up.starts_with("172.");
                                            let mut try_local = false;
                                            if !is_local {
                                                let is_fallback = route_table.target_locations.get(&target_up).map_or(false, |pref| remote.location != *pref);
                                                if !is_fallback {
                                                    try_local = true;
                                                }
                                            }
                                            let t0 = tokio::time::Instant::now();
                                            match m.open_tunnel(&target_up, try_local).await {
                                                Ok(st) => {
                                                    let latency = t0.elapsed().as_millis() as f64;
                                                    {
                                                        let mut sl = slot.lock().await;
                                                        sl.ewma_latency = (0.2 * latency) + (0.8 * sl.ewma_latency);
                                                        sl.consecutive_errors = 0;
                                                    }
                                                    if !failed_snis.is_empty() {
                                                        tracing::debug!("[Conn #{}] TCP Tunnel successfully fell back to alternate SNI (wssmux): {}", c_id, remote.sni);
                                                    }
                                                    debug!("[Conn #{}] 🛣️ Path: DIRECT WssMux via {} ({}ms to open)", c_id, remote.sni, latency as u64);
                                                    final_mux = Some(st);
                                                    break;
                                                }
                                                Err(()) => {
                                                    // Deprioritise this slot so the next connections do not
                                                    // wait for the open timeout on it again.
                                                    slot.lock().await.ewma_latency += 5000.0;
                                                    if !m.alive() {
                                                        // The session itself is broken: drop it so the maintainer
                                                        // reconnects (trying the other protocol first).
                                                        slot.lock().await.mux = None;
                                                        crate::transport::record_fail(&remote.sni, Proto::WssMux);
                                                        tracing::debug!("[Conn #{}] WssMux session to {} is broken; trying another tunnel.", c_id, remote.sni);
                                                    } else {
                                                        tracing::debug!("[Conn #{}] WssMux tunnel via {} failed (target unreachable?); trying another tunnel.", c_id, remote.sni);
                                                    }
                                                    failed_snis.insert(remote.sni.clone());
                                                    global_retries += 1;
                                                    continue;
                                                }
                                            }
                                        }
                                        Chosen::Reverse(loc) => {
                                            let is_local = target_up.starts_with("127.") || target_up.starts_with("localhost") || target_up.starts_with("[::1]") || target_up.starts_with("10.") || target_up.starts_with("192.168.") || target_up.starts_with("172.");
                                            let mut try_local = false;
                                            // `try_local` (connect to 127.0.0.1:<port> on the server) is sent only
                                            // for a LABELED tunnel serving its own location. An unlabeled tunnel, or a
                                            // labeled one used as a fallback for another location, sends
                                            // try_local = false: the server dials the real target host directly.
                                            if !is_local && !loc.is_empty() {
                                                let is_fallback = route_table.target_locations.get(&target_up).map_or(false, |pref| loc != *pref);
                                                if !is_fallback {
                                                    try_local = true;
                                                }
                                            }
                                            match crate::reverse::open_any(&loc, &target_up, try_local).await {
                                                Ok(crate::reverse::ReverseConn::Mux(st)) => {
                                                    if !failed_snis.is_empty() {
                                                        tracing::debug!("[Conn #{}] Tunnel fell back to Reverse WssMux session ({})", c_id, loc);
                                                    }
                                                    debug!("[Conn #{}] 🛣️ Path: REVERSE WssMux (location '{}')", c_id, loc);
                                                    final_mux = Some(st);
                                                    break;
                                                }
                                                Ok(crate::reverse::ReverseConn::H2(ss, body, leftover)) => {
                                                    debug!("[Conn #{}] 🛣️ Path: REVERSE H2 (location '{}')", c_id, loc);
                                                    if !failed_snis.is_empty() {
                                                        tracing::debug!("[Conn #{}] Tunnel fell back to Reverse stream ({})", c_id, loc);
                                                    }
                                                    final_send_stream = Some(ss);
                                                    final_body = Some(body);
                                                    final_leftover = leftover;
                                                    break;
                                                }
                                                Err(()) => {
                                                    tracing::debug!("[Conn #{}] Reverse stream for '{}' failed; trying another tunnel.", c_id, loc);
                                                    failed_snis.insert(format!("rev:{}", loc));
                                                    global_retries += 1;
                                                    continue;
                                                }
                                            }
                                        }
                                    };

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
                                                    crate::transport::record_ok(&target_remote.sni, Proto::H2);

                                                    if !failed_snis.is_empty() {
                                                        tracing::debug!("[Conn #{}] TCP Tunnel successfully fell back to alternate SNI: {}", c_id, target_remote.sni);
                                                    }

                                                    final_send_stream = Some(send_stream);
                                                    final_body = Some(res.into_body());
                                                    break;
                                                }
                                                tracing::debug!("[Conn #{}] Tunnel failed! Remote server {} returned HTTP {}", c_id, target_remote.sni, res.status());
                                                let mut slot = pool_slot.lock().await;
                                                slot.ewma_latency += 5000.0;
                                                slot.client = None;
                                                crate::transport::record_fail(&target_remote.sni, Proto::H2);
                                                failed_snis.insert(target_remote.sni.clone());
                                            } else {
                                                let mut slot = pool_slot.lock().await;
                                                slot.client = None;
                                                crate::transport::record_fail(&target_remote.sni, Proto::H2);
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

                                if let Some(st) = final_mux {
                                    // WssMux tunnel (Direct slot or Reverse session): raw bytes over a yamux stream.
                                    let _stream_guard = crate::metrics::open_stream("user", "wssmux", peer.to_string(), target_up.clone());
                                    crate::wssmux::pipe_user(local_read, local_write, &initial_data, st).await;
                                    return;
                                }

                                if final_send_stream.is_none() {
                                    refresh_tunnel_path(
                                        &pool_clone,
                                        reverse_enabled,
                                        &active_path,
                                        &direct_recovery_checks,
                                        false,
                                        &path_update_lock,
                                    )
                                    .await;
                                    return;
                                }

                                let mut send_stream = final_send_stream.unwrap();
                                let _stream_guard = crate::metrics::open_stream("user", "h2", peer.to_string(), target_up.clone());

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
                                        let mut body = final_body.unwrap();
                                        if !final_leftover.is_empty() {
                                            grpc_buf.extend_from_slice(&final_leftover);
                                            while grpc_buf.len() >= 5 {
                                                let len = u32::from_be_bytes([grpc_buf[1], grpc_buf[2], grpc_buf[3], grpc_buf[4]]) as usize;
                                                if grpc_buf.len() < 5 + len { break; }
                                                if local_write.write_all(&grpc_buf[5..5+len]).await.is_err() { return; }
                                                let _ = grpc_buf.split_to(5 + len);
                                            }
                                        }
                                        while let Some(Ok(mut data)) = body.data().await {
                                            let _ = body.flow_control().release_capacity(data.len());
                                            crate::metrics::add_rx(data.len());

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

    if let Some(sni_configs) = &cfg.sni_proxy {
        let mut client_sni_routes = std::collections::HashMap::new();
        crate::routing::parse_server_sni_proxy(
            sni_configs,
            "0.0.0.0:443", // fallback bind if port not specified
            &mut client_sni_routes,
        );

        let mut unique_targets = std::collections::HashSet::new();
        for (_, rt) in &client_sni_routes {
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

        let hc_cancel = cancel_token.clone();
        if !unique_targets.is_empty() {
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = hc_cancel.cancelled() => break,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                    }
                    let mut targets_to_check = unique_targets.clone();
                    {
                        let dead = get_client_dead_targets().read().unwrap();
                        for t in dead.iter() {
                            targets_to_check.insert(t.clone());
                        }
                    }
                    let mut recovered = Vec::new();
                    let mut newly_dead = Vec::new();
                    for target in &targets_to_check {
                        match crate::anti_loop::safe_connect(
                            target,
                            std::time::Duration::from_secs(2),
                        )
                        .await
                        {
                            Ok(_) => recovered.push(target.clone()),
                            Err(_) => {
                                if unique_targets.contains(target) {
                                    newly_dead.push(target.clone());
                                }
                            }
                        }
                    }
                    let mut dead_guard = get_client_dead_targets().write().unwrap();
                    for t in recovered {
                        dead_guard.remove(&t);
                    }
                    for t in newly_dead {
                        dead_guard.insert(t);
                    }
                }
            });
        }

        for (bind_addr, route_table) in client_sni_routes {
            let mut listener_opt = None;
            for i in 0..10 {
                match crate::net_utils::create_reuseport_listener(&bind_addr) {
                    Ok(l) => {
                        listener_opt = Some(l);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "⚠️ Failed to bind SNI proxy {} (attempt {}/10): {}. Retrying in 200ms...",
                            bind_addr,
                            i + 1,
                            e
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }
            if let Some(listener) = listener_opt {
                tracing::info!("🛡️ Client SNI Proxy listening on {}", bind_addr);
                let rt = std::sync::Arc::new(route_table);
                let l_cancel = cancel_token.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = l_cancel.cancelled() => break,
                            accept_res = listener.accept() => {
                                if let Ok((mut local_tcp, peer)) = accept_res {
                                    if crate::anti_loop::is_loop(&peer) {
                                        crate::net_utils::log_rate_limited(&format!("anti_loop_{}", peer), "🛑 Anti-Loop Firewall: Dropped self-loop connection in client SNI proxy.");
                                        continue;
                                    }
                                    let _ = local_tcp.set_nodelay(true);
                                    crate::net_utils::tune_socket_buffers(&local_tcp);
                                    crate::net_utils::enable_tcp_keepalive(&local_tcp);

                                    let rt_clone = rt.clone();
                                    tokio::spawn(async move {
                                        let mut extracted_sni = None;
                                        let mut initial_buf = [0u8; 8192];
                                        let mut initial_len = 0;
                                        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                                            loop {
                                                if initial_len >= 8192 { break; }
                                                let n = match tokio::io::AsyncReadExt::read(&mut local_tcp, &mut initial_buf[initial_len..]).await {
                                                    Ok(n) if n > 0 => n,
                                                    _ => break,
                                                };
                                                initial_len += n;
                                                if initial_buf[0] == 0x16 {
                                                    if let Some(sni) = crate::routing::extract_sni(&initial_buf[..initial_len]) {
                                                        extracted_sni = Some(sni);
                                                        break;
                                                    }
                                                    if initial_len >= 5 {
                                                        let record_len = ((initial_buf[3] as usize) << 8) | (initial_buf[4] as usize);
                                                        if initial_len >= 5 + record_len { break; }
                                                    }
                                                } else if crate::routing::is_http_request(&initial_buf[..initial_len]) {
                                                    if let Some(host) = crate::routing::extract_http_host(&initial_buf[..initial_len]) {
                                                        extracted_sni = Some(host);
                                                        break;
                                                    } else if initial_buf[..initial_len].windows(4).any(|w| w == b"\r\n\r\n") || initial_buf[..initial_len].windows(2).any(|w| w == b"\n\n") {
                                                        break;
                                                    }
                                                } else {
                                                    break;
                                                }
                                            }
                                        }).await;

                                        let target_up = if let Some(sni) = &extracted_sni {
                                            rt_clone.sni_rules.get(sni).or_else(|| rt_clone.sni_rules.get("*")).cloned().or_else(|| rt_clone.default_upstream.clone())
                                        } else {
                                            rt_clone.sni_rules.get("*").cloned().or_else(|| rt_clone.default_upstream.clone())
                                        };

                                        if let Some(target_list) = target_up {
                                            let mut healthy_targets = Vec::new();
                                            {
                                                let dead = get_client_dead_targets().read().unwrap();
                                                for t in target_list.split(',') {
                                                    let t = t.trim();
                                                    if !dead.contains(t) && !t.is_empty() {
                                                        healthy_targets.push(t.to_string());
                                                    }
                                                }
                                            }

                                            if healthy_targets.is_empty() {
                                                crate::net_utils::log_rate_limited(
                                                    &format!("client_circuit_breaker_{:?}", extracted_sni),
                                                    &format!("Circuit Breaker: All targets for Client SNI {:?} are dead (pool: {}). Dropping.", extracted_sni, target_list)
                                                );
                                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                                return;
                                            }

                                            // Active-Passive priority based routing
                                            let target = healthy_targets[0].clone();
                                            tracing::debug!("🔄 Client SNI Routing triggered for {:?} -> {} (from pool: {})", extracted_sni, target, target_list);

                                            match crate::anti_loop::safe_connect(&target, std::time::Duration::from_secs(10)).await {
                                                Ok(mut upstream_tcp) => {
                                                    let _ = upstream_tcp.set_nodelay(true);
                                                    crate::net_utils::tune_socket_buffers(&upstream_tcp);
                                                    crate::net_utils::enable_tcp_keepalive(&upstream_tcp);

                                                    if initial_len > 0 {
                                                        if tokio::io::AsyncWriteExt::write_all(&mut upstream_tcp, &initial_buf[..initial_len]).await.is_err() {
                                                            return;
                                                        }
                                                    }
                                                    let _ = tokio::io::copy_bidirectional(&mut local_tcp, &mut upstream_tcp).await;
                                                }
                                                Err(e) => crate::net_utils::log_rate_limited(&format!("client_fail_{}", target), &format!("❌ Failed to connect to Client SNI proxy target {}: {}", target, e)),
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }
    }

    cancel_token.cancelled().await;
}
