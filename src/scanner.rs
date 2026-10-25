use std::path::Path;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use ipnet::Ipv4Net;
use rand::RngExt;
use tokio_rustls::TlsConnector;

use std::sync::atomic::{AtomicBool, Ordering};

/// ArvanCloud CDN edge ranges (scanned instead of Cloudflare's when the tunnel SNI is behind Arvan).
const ARVANCLOUD_RANGES: &[&str] = &[
    "185.143.232.0/22",
    "188.229.116.16/30",
    "94.101.182.0/27",
    "2.144.3.128/28",
    "37.32.16.0/27",
    "37.32.17.0/27",
    "37.32.18.0/27",
    "37.32.19.0/27",
    "185.215.232.0/22",
    "178.131.120.48/28",
    "94.101.183.0/28",
    "78.157.36.112/28",
    "95.38.61.80/28",
    "193.24.119.0/29",
];

/// Cloudflare ranges (offline fallback + used to recognise a Cloudflare-fronted SNI).
const CLOUDFLARE_FALLBACK: &[&str] = &[
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cdn {
    Cloudflare,
    ArvanCloud,
}

impl Cdn {
    fn name(self) -> &'static str {
        match self {
            Cdn::Cloudflare => "Cloudflare",
            Cdn::ArvanCloud => "ArvanCloud",
        }
    }
}

fn parse_nets(list: &[&str]) -> Vec<Ipv4Net> {
    list.iter().filter_map(|s| Ipv4Net::from_str(s).ok()).collect()
}

fn parse_ranges(content: &str) -> Vec<Ipv4Net> {
    let mut ranges = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(net) = Ipv4Net::from_str(line) {
            ranges.push(net);
        } else if let Ok(ip) = Ipv4Addr::from_str(line) {
            if let Ok(net) = Ipv4Net::new(ip, 32) {
                ranges.push(net);
            }
        }
    }
    ranges
}

fn arvan_ranges_file_path(source_ips_file: &str) -> String {
    let source_path = Path::new(source_ips_file);
    source_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("arvancloud_ip_ranges.txt")
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn parse_clean_ips(content: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for line in content.lines() {
        let ip = line.trim();
        if !ip.is_empty()
            && !ip.starts_with('#')
            && !ips.iter().any(|existing: &String| existing.as_str() == ip)
        {
            ips.push(ip.to_string());
        }
    }
    ips
}

fn clean_ips_file_content(ips: &[String]) -> Option<String> {
    if ips.is_empty() {
        None
    } else {
        Some(ips.join("\n") + "\n")
    }
}

/// Picks a range at random. `weighted` = proportional to the number of addresses (so a /22 is
/// tried far more often than a /30), otherwise every range has the same chance.
fn pick_range(ranges: &[Ipv4Net], weighted: bool) -> &Ipv4Net {
    let mut rng = rand::rng();
    if weighted {
        let size = |r: &Ipv4Net| 1u64 << (32 - u32::from(r.prefix_len()));
        let total: u64 = ranges.iter().map(size).sum();
        if total > 0 {
            let mut x = rng.random_range(0..total);
            for r in ranges {
                let sz = size(r);
                if x < sz {
                    return r;
                }
                x -= sz;
            }
        }
    }
    &ranges[rng.random_range(0..ranges.len())]
}

/// What the strict test needs to speak the same protocol the tunnel will use.
#[derive(Clone)]
struct ProbeCfg {
    /// First protocol in `protocols` is WssMux: test with TLS(http/1.1) + WebSocket upgrade + ping/pong.
    ws_first: bool,
    hidden_path: String,
    secret: String,
}

pub struct Scanner {
    clean_ip_file: String,
    source_ips_file: String,
    check_interval_minutes: u64,
    max_ping_ms: u64,
    clean_ips_global: Arc<RwLock<Vec<String>>>,
    remotes: Vec<crate::config::RemoteLocation>,
    tls_connector: Arc<TlsConnector>,
    /// `[client].scanner_cdn`: "auto" (default) | "arvancloud" | "cloudflare".
    cdn_pref: Option<String>,
    probe: ProbeCfg,
    /// CDN detected for the current scan cycle (true = ArvanCloud).
    is_arvan: AtomicBool,
    arvan_ranges_cache: tokio::sync::OnceCell<Vec<Ipv4Net>>,
}

impl Scanner {
    pub fn new(
        clean_ip_file: String,
        source_ips_file: String,
        check_interval_minutes: u64,
        max_ping_ms: u64,
        clean_ips_global: Arc<RwLock<Vec<String>>>,
        remotes: Vec<crate::config::RemoteLocation>,
        tls_connector: Arc<TlsConnector>,
        cdn_pref: Option<String>,
        hidden_path: String,
        secret: String,
        protocols: Vec<crate::transport::Proto>,
    ) -> Self {
        let ws_first = protocols.first() == Some(&crate::transport::Proto::WssMux) && !secret.is_empty();
        Self {
            clean_ip_file,
            source_ips_file,
            check_interval_minutes,
            max_ping_ms,
            clean_ips_global,
            remotes,
            tls_connector,
            cdn_pref,
            probe: ProbeCfg { ws_first, hidden_path, secret },
            is_arvan: AtomicBool::new(false),
            arvan_ranges_cache: tokio::sync::OnceCell::new(),
        }
    }

    /// Decides which CDN fronts the Direct tunnel SNI(s): explicit `scanner_cdn`, otherwise the
    /// DNS answers of the SNI domains (an address inside the ArvanCloud / Cloudflare ranges), and
    /// as a last hint the IPs already stored in clean_ips.txt. Unknown = Cloudflare (legacy default).
    async fn detect_cdn(&self, existing: &[String]) -> Cdn {
        if let Some(p) = &self.cdn_pref {
            match p.trim().to_ascii_lowercase().as_str() {
                "arvancloud" | "arvan" => return Cdn::ArvanCloud,
                "cloudflare" | "cf" => return Cdn::Cloudflare,
                _ => {}
            }
        }
        let arvan = parse_nets(ARVANCLOUD_RANGES);
        let cf = parse_nets(CLOUDFLARE_FALLBACK);
        let (mut a, mut c) = (0usize, 0usize);
        for r in &self.remotes {
            for sni in &r.sni {
                let host = sni
                    .rsplit_once(':')
                    .filter(|(_, p)| p.parse::<u16>().is_ok())
                    .map(|(h, _)| h)
                    .unwrap_or(sni.as_str());
                let addrs = match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    tokio::net::lookup_host((host, 443u16)),
                )
                .await
                {
                    Ok(Ok(it)) => it.collect::<Vec<_>>(),
                    _ => continue,
                };
                for addr in addrs {
                    if let std::net::IpAddr::V4(v4) = addr.ip() {
                        Self::tally(v4, &arvan, &cf, &mut a, &mut c);
                    }
                }
            }
        }
        if a == 0 && c == 0 {
            for ip in existing {
                let host = ip.rsplit_once(':').map(|(h, _)| h).unwrap_or(ip.as_str());
                if let Ok(v4) = Ipv4Addr::from_str(host) {
                    Self::tally(v4, &arvan, &cf, &mut a, &mut c);
                }
            }
        }
        if a > 0 && a >= c {
            Cdn::ArvanCloud
        } else {
            Cdn::Cloudflare
        }
    }

    fn tally(ip: Ipv4Addr, arvan: &[Ipv4Net], cf: &[Ipv4Net], a: &mut usize, c: &mut usize) {
        if arvan.iter().any(|n| n.contains(&ip)) {
            *a += 1;
        } else if cf.iter().any(|n| n.contains(&ip)) {
            *c += 1;
        }
    }

    fn arvan_ranges_file(&self) -> String {
        arvan_ranges_file_path(&self.source_ips_file)
    }

    /// Fetches ArvanCloud's official ranges first, using cached or built-in ranges on failure.
    async fn read_arvan_ranges(&self) -> Vec<Ipv4Net> {
        self.arvan_ranges_cache
            .get_or_init(|| async { self.load_arvan_ranges().await })
            .await
            .clone()
    }

    async fn load_arvan_ranges(&self) -> Vec<Ipv4Net> {
        let path = self.arvan_ranges_file();
        let downloaded = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let response = reqwest::get("https://www.arvancloud.ir/en/ips.txt")
                .await?
                .error_for_status()?;
            response.text().await
        })
        .await;
        let fetched_ranges = match downloaded {
            Ok(Ok(content)) => parse_ranges(&content),
            Ok(Err(error)) => {
                tracing::warn!("Failed to fetch ArvanCloud IP ranges: {}", error);
                Vec::new()
            }
            Err(_) => {
                tracing::warn!("Timed out fetching ArvanCloud IP ranges");
                Vec::new()
            }
        };

        if !fetched_ranges.is_empty() {
            tracing::debug!(
                "✅ Fetched {} IPv4 ranges from ArvanCloud",
                fetched_ranges.len()
            );
            self.write_ranges_file(&path, &fetched_ranges).await;
            return fetched_ranges;
        }

        tracing::warn!("⚠️ ArvanCloud IP range download failed or contained no valid IPv4 ranges");
        if let Ok(content) = tokio::fs::read_to_string(&path).await {
            let cached_ranges = parse_ranges(&content);
            if !cached_ranges.is_empty() {
                tracing::warn!(
                    "Using {} cached ArvanCloud IPv4 ranges from {}",
                    cached_ranges.len(),
                    path
                );
                return cached_ranges;
            }
        }

        tracing::warn!("⚠️ No valid cached ArvanCloud ranges; writing the built-in fallback list");
        let fallback_ranges = parse_nets(ARVANCLOUD_RANGES);
        self.write_ranges_file(&path, &fallback_ranges).await;
        fallback_ranges
    }

    async fn write_ranges_file(&self, path: &str, ranges: &[Ipv4Net]) {
        let file_path = Path::new(path);
        if let Some(parent) = file_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            if let Err(error) = tokio::fs::create_dir_all(parent).await {
                tracing::error!("Failed to create directory for {}: {}", path, error);
                return;
            }
        }
        let content = ranges
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        if let Err(error) = tokio::fs::write(path, content).await {
            tracing::error!("Failed to write IP ranges to {}: {}", path, error);
        }
    }

    pub fn start(self, cancel_token: tokio_util::sync::CancellationToken) {
        tokio::spawn(async move {
            tokio::select! {
                _ = self.run_loop() => {}
                _ = cancel_token.cancelled() => {
                    tracing::info!("🛑 Stopping IP Scanner due to Hot-Reload...");
                }
            }
        });
    }

    async fn run_loop(&self) {

        loop {
            tracing::debug!("🔍 Starting IP scanner routine...");
            let mut current_ips = self.read_clean_ips().await;
            let cdn = self.detect_cdn(&current_ips).await;
            self.is_arvan.store(cdn == Cdn::ArvanCloud, Ordering::Relaxed);
            tracing::info!("🛰️ IP scanner: CDN of the Direct tunnel SNI = {} -> scanning {} edge IP ranges", cdn.name(), cdn.name());
            
            if !current_ips.is_empty() {
                let mut w = self.clean_ips_global.write().await;
                *w = current_ips.clone();
            }
            
            // If empty, try to get 1 IP immediately to warm up the client pool
            if current_ips.is_empty() {
                tracing::warn!("⚠️ clean_ips is empty, trying to find 1 initial IP for fast startup...");
                let new_ips = self.find_new_ips(1).await;
                if !new_ips.is_empty() {
                    current_ips.extend(new_ips);
                    self.save_and_update(&current_ips).await;
                }
            }
            
            // If we have less than 10 IPs in total, fill the remaining slots
            if !current_ips.is_empty() && current_ips.len() < 10 {
                let needed = 10 - current_ips.len();
                tracing::debug!("🔄 Finding {} more IPs to reach the full pool size of 10...", needed);
                let new_ips = self.find_new_ips(needed).await;
                if !new_ips.is_empty() {
                    current_ips.extend(new_ips);
                    self.save_and_update(&current_ips).await;
                }
            }

            if !current_ips.is_empty() {
                // Test current IPs
                let mut failed_count = 0;
                let mut healthy_ips = Vec::new();

                for ip in current_ips.iter() {
                    if self.strict_test_ip(ip).await {
                        healthy_ips.push(ip.clone());
                    } else {
                        failed_count += 1;
                        tracing::warn!("❌ IP {} failed strict test, will be replaced.", ip);
                    }
                }

                if failed_count > 0 {
                    tracing::debug!("🔄 Finding {} new IPs to replace disconnected ones...", failed_count);
                    let new_ips = self.find_new_ips(failed_count).await;
                    healthy_ips.extend(new_ips);
                    self.save_and_update(&healthy_ips).await;
                } else {
                    tracing::debug!("✅ All {} IPs in clean_ips are healthy.", healthy_ips.len());
                }
            }

            let interval_secs = self.check_interval_minutes * 60;
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
        }
    }

    async fn save_and_update(&self, ips: &[String]) {
        // Update memory first
        {
            let mut w = self.clean_ips_global.write().await;
            *w = ips.to_vec();
        }

        // Never destroy a useful on-disk cache when a scan has no healthy results.
        let Some(content) = clean_ips_file_content(ips) else {
            tracing::warn!(
                "No clean IPs are available; keeping the existing cache at {}",
                self.clean_ip_file
            );
            return;
        };

        if let Some(parent) = Path::new(&self.clean_ip_file)
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                tracing::error!(
                    "Failed to create directory for {}: {}",
                    self.clean_ip_file,
                    e
                );
                return;
            }
        }

        if let Err(e) = tokio::fs::write(&self.clean_ip_file, content).await {
            tracing::error!("Failed to write to {}: {}", self.clean_ip_file, e);
        } else {
            tracing::debug!("💾 Saved {} IPs to {}", ips.len(), self.clean_ip_file);
        }
    }

    async fn read_clean_ips(&self) -> Vec<String> {
        match tokio::fs::read_to_string(&self.clean_ip_file).await {
            Ok(content) => parse_clean_ips(&content),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(
                    "No clean-IP cache found at {}; starting with an empty cache",
                    self.clean_ip_file
                );
                Vec::new()
            }
            Err(e) => {
                tracing::error!("Failed to read {}: {}", self.clean_ip_file, e);
                Vec::new()
            }
        }
    }

    async fn read_source_ranges(&self) -> Vec<Ipv4Net> {
        let mut ranges = Vec::new();
        if let Ok(content) = tokio::fs::read_to_string(&self.source_ips_file).await {
            ranges = parse_ranges(&content);
        }
        
        if ranges.is_empty() {
            let fallback_list = CLOUDFLARE_FALLBACK.to_vec();
            
            let mut fetch_success = false;
            let mut fetched_cidrs = Vec::new();
            if let Ok(resp) = reqwest::get("https://api.cloudflare.com/client/v4/ips").await {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(ipv4_cidrs) = json.get("result").and_then(|r| r.get("ipv4_cidrs")).and_then(|v| v.as_array()) {
                        for v in ipv4_cidrs {
                            if let Some(s) = v.as_str() {
                                fetched_cidrs.push(s.to_string());
                            }
                        }

                        fetch_success = !fetched_cidrs.is_empty()
                            && fetched_cidrs.iter().all(|range| {
                                Ipv4Net::from_str(range).is_ok()
                            });
                    }
                }
            }

            let final_list = if fetch_success && !fetched_cidrs.is_empty() {
                tracing::debug!("✅ Successfully fetched {} IPv4 ranges from Cloudflare API", fetched_cidrs.len());
                fetched_cidrs
            } else {
                tracing::warn!("⚠️ Failed to fetch from Cloudflare API, using default fallback list");
                fallback_list.iter().map(|s| s.to_string()).collect()
            };

            let content = final_list.join("\n") + "\n";
            let file_path = Path::new(&self.source_ips_file);
            if let Some(parent) = file_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                if let Err(error) = tokio::fs::create_dir_all(parent).await {
                    tracing::error!(
                        "Failed to create directory for {}: {}",
                        self.source_ips_file,
                        error
                    );
                }
            }
            if let Err(error) = tokio::fs::write(&self.source_ips_file, content).await {
                tracing::error!(
                    "Failed to write IP ranges to {}: {}",
                    self.source_ips_file,
                    error
                );
            }
            ranges = parse_ranges(&final_list.join("\n"));
        }
        
        ranges
    }

    async fn find_new_ips(&self, count: usize) -> Vec<String> {
        let weighted = self.is_arvan.load(Ordering::Relaxed);
        let ranges = if weighted {
            self.read_arvan_ranges().await
        } else {
            self.read_source_ranges().await
        };
        if ranges.is_empty() {
            let range_file = if weighted {
                self.arvan_ranges_file()
            } else {
                self.source_ips_file.clone()
            };
            tracing::error!("No valid source IP ranges found in {}", range_file);
            return Vec::new();
        }

        let mut found = Vec::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(count * 5);
        let mut active_tasks = 0;

        let port_to_check = if let Some(r) = self.remotes.first() {
            if let Some(sni) = r.sni.first() {
                if let Some(idx) = sni.rfind(':') {
                    sni[idx+1..].to_string()
                } else {
                    "443".to_string()
                }
            } else { "443".to_string() }
        } else { "443".to_string() };

        let max_ping = std::time::Duration::from_millis(self.max_ping_ms);

        for _ in 0..1000 {
            if found.len() >= count { break; }
            
            // Prevent spawning too many tasks, block until one finishes
            if active_tasks >= count * 3 {
                if let Some(ip) = rx.recv().await {
                    active_tasks -= 1;
                    if !ip.is_empty() {
                        found.push(ip);
                        if found.len() >= count { break; }
                    }
                }
            }

            let ip_str = {
                let range = pick_range(&ranges, weighted);
                self.random_ip_from_subnet(range).to_string()
            };

            let addr_str = format!("{}:{}", ip_str, port_to_check);
            let addrs = tokio::net::lookup_host(&addr_str).await.ok().and_then(|mut it| it.next());
            
            if let Some(addr) = addrs {
                // Ping Phase: TCP Connection with max_ping_ms
                if let Ok(Ok(_)) = tokio::time::timeout(
                    max_ping, 
                    TcpStream::connect(addr)
                ).await {
                    // Ping passed! Start strict test in parallel
                    let tx_clone = tx.clone();
                    let tls = self.tls_connector.clone();
                    let remotes = self.remotes.clone();
                    let probe = self.probe.clone();
                    active_tasks += 1;
                    let ip_clone = ip_str.clone();
                    
                    tokio::spawn(async move {
                        let max_ping_ms_val = max_ping.as_millis() as u64;
                        if Self::strict_test_ip_static(&ip_clone, &remotes, &tls, max_ping_ms_val, &probe).await {
                            let _ = tx_clone.send(ip_clone).await;
                        } else {
                            let _ = tx_clone.send(String::new()).await;
                        }
                    });
                }
            }
            
            // Rate Limiting: Prevent SYN flooding if connections fail immediately
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Drain remaining successful tasks
        while found.len() < count && active_tasks > 0 {
            if let Some(ip) = rx.recv().await {
                active_tasks -= 1;
                if !ip.is_empty() {
                    found.push(ip);
                }
            }
        }

        found
    }

    fn random_ip_from_subnet(&self, subnet: &Ipv4Net) -> Ipv4Addr {
        let prefix = subnet.prefix_len();
        if prefix >= 31 {
            return subnet.network();
        }
        let net_addr = u32::from(subnet.network());
        let host_mask = (1u32 << (32 - prefix)) - 1;
        let mut rng = rand::rng();
        let random_host = rng.random_range(1..host_mask);
        let ip_u32 = net_addr | random_host;
        Ipv4Addr::from(ip_u32)
    }

    async fn strict_test_ip(&self, ip: &str) -> bool {
        Self::strict_test_ip_static(ip, &self.remotes, &self.tls_connector, self.max_ping_ms, &self.probe).await
    }

    async fn strict_test_ip_static(
        ip: &str,
        remotes: &[crate::config::RemoteLocation],
        tls_connector: &TlsConnector,
        max_ping_ms: u64,
        probe: &ProbeCfg,
    ) -> bool {
        // Find a remote location to get SNI
        if remotes.is_empty() {
            return false;
        }
        
        let remote = &remotes[0];
        if remote.sni.is_empty() { return false; }
        let sni = &remote.sni[0];
        
        let (sni_host, sni_port) = if let Some(idx) = sni.rfind(':') {
            (&sni[..idx], &sni[idx+1..])
        } else {
            (sni.as_str(), "443")
        };

        let addr_str = if ip.contains(':') && !ip.starts_with('[') {
            if ip.split(':').count() > 2 {
                format!("[{}]:{}", ip, sni_port)
            } else {
                ip.to_string()
            }
        } else {
            format!("{}:{}", ip, sni_port)
        };

        let connect_timeout = std::time::Duration::from_millis(max_ping_ms);
        
        // Resolve and connect TCP
        let addrs = match tokio::net::lookup_host(&addr_str).await {
            Ok(a) => a.collect::<Vec<_>>(),
            Err(_) => return false,
        };

        let mut tcp_opt = None;
        for addr in addrs {
            if let Ok(Ok(stream)) = tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
                tcp_opt = Some(stream);
                break;
            }
        }

        let tcp = match tcp_opt {
            Some(t) => t,
            None => return false,
        };

        let _ = tcp.set_nodelay(true);
        crate::net_utils::enable_tcp_bbr(&tcp);
        crate::net_utils::tune_socket_buffers(&tcp);
        crate::net_utils::enable_tcp_keepalive(&tcp);

        // WssMux tunnels: test exactly what the tunnel does (TLS http/1.1 + WebSocket upgrade with the
        // secret + ping/pong), so an IP that passes really carries WebSocket frames.
        if probe.ws_first {
            return match crate::wssmux::probe_endpoint(tcp, sni.as_str(), sni_host, &probe.hidden_path, &probe.secret).await {
                Ok(_) => true,
                Err(e) => {
                    tracing::trace!("IP {} failed WssMux test: {}", ip, e);
                    false
                }
            };
        }

        // TLS Handshake
        let domain = match rustls::pki_types::ServerName::try_from(sni_host) {
            Ok(d) => d.to_owned(),
            Err(_) => return false,
        };

        let tls_stream = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tls_connector.connect(domain, tcp)
        ).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        // H2 Handshake
        let mut h2_builder = h2::client::Builder::new();
        h2_builder.initial_window_size(33_554_432)
            .initial_connection_window_size(134_217_728)
            .max_frame_size(1_048_576);

        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            h2_builder.handshake::<_, bytes::Bytes>(tls_stream)
        ).await {
            Ok(Ok(_)) => true, // Successfully did H2 handshake
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{arvan_ranges_file_path, clean_ips_file_content, parse_clean_ips, parse_ranges};
    use std::path::Path;

    #[test]
    fn parses_clean_ip_cache_lines() {
        assert_eq!(
            parse_clean_ips(" 104.16.1.1 \n\n# cached IPs\n104.17.2.2\n104.16.1.1\n"),
            vec!["104.16.1.1", "104.17.2.2"]
        );
    }

    #[test]
    fn empty_scan_does_not_produce_file_content() {
        assert_eq!(clean_ips_file_content(&[]), None);
    }

    #[test]
    fn nonempty_scan_is_saved_as_lines() {
        let ips = vec!["104.16.1.1".to_string(), "104.17.2.2".to_string()];
        assert_eq!(
            clean_ips_file_content(&ips).as_deref(),
            Some("104.16.1.1\n104.17.2.2\n")
        );
    }

    #[test]
    fn arvan_ranges_use_the_standard_filename_in_the_cloudflare_file_directory() {
        assert_eq!(
            arvan_ranges_file_path("ips/cloudflare_ip_ranges.txt"),
            Path::new("ips")
                .join("arvancloud_ip_ranges.txt")
                .to_string_lossy()
                .into_owned()
        );
        assert_eq!(
            arvan_ranges_file_path("cloudflare_ip_ranges.txt"),
            Path::new(".")
                .join("arvancloud_ip_ranges.txt")
                .to_string_lossy()
                .into_owned()
        );
    }

    #[test]
    fn parses_ipv4_ranges_from_downloaded_text() {
        let ranges = parse_ranges(
            "# IPv4 ranges\n185.143.232.0/22\n185.215.232.1\n2001:db8::/32\ninvalid\n",
        );
        assert_eq!(
            ranges.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec![
                "185.143.232.0/22".to_string(),
                "185.215.232.1/32".to_string()
            ]
        );
    }
}
