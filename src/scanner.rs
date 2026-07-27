use std::sync::Arc;
use std::str::FromStr;
use tokio::sync::RwLock;
use tokio::net::TcpStream;
use rand::RngExt;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

use tokio_rustls::TlsConnector;

pub struct Scanner {
    clean_ip_file: String,
    source_ips_file: String,
    check_interval_minutes: u64,
    max_ping_ms: u64,
    clean_ips_global: Arc<RwLock<Vec<String>>>,
    remotes: Vec<crate::config::RemoteLocation>,
    tls_connector: Arc<TlsConnector>,
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
    ) -> Self {
        Self {
            clean_ip_file,
            source_ips_file,
            check_interval_minutes,
            max_ping_ms,
            clean_ips_global,
            remotes,
            tls_connector,
        }
    }

    pub fn start(self) {
        tokio::spawn(async move {
            self.run_loop().await;
        });
    }

    async fn run_loop(&self) {

        loop {
            tracing::debug!("🔍 Starting IP scanner routine...");
            let mut current_ips = self.read_clean_ips().await;
            
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
        // Update file
        let content = ips.join("\n");
        if let Err(e) = tokio::fs::write(&self.clean_ip_file, content).await {
            tracing::error!("Failed to write to {}: {}", self.clean_ip_file, e);
        } else {
            tracing::debug!("💾 Saved {} IPs to {}", ips.len(), self.clean_ip_file);
        }
    }

    async fn read_clean_ips(&self) -> Vec<String> {
        if let Ok(content) = tokio::fs::read_to_string(&self.clean_ip_file).await {
            content.lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            Vec::new()
        }
    }

    async fn read_source_ranges(&self) -> Vec<Ipv4Net> {
        let mut ranges = Vec::new();
        if let Ok(content) = tokio::fs::read_to_string(&self.source_ips_file).await {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                if let Ok(net) = Ipv4Net::from_str(line) {
                    ranges.push(net);
                } else if let Ok(ip) = Ipv4Addr::from_str(line) {
                    if let Ok(net) = Ipv4Net::new(ip, 32) {
                        ranges.push(net);
                    }
                }
            }
        }
        
        if ranges.is_empty() {
            let fallback_list = vec![
                "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
                "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
                "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
                "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
            ];
            
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
                        fetch_success = true;
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
            let _ = tokio::fs::write(&self.source_ips_file, content).await;

            for line in final_list {
                if let Ok(net) = Ipv4Net::from_str(&line) {
                    ranges.push(net);
                }
            }
        }
        
        ranges
    }

    async fn find_new_ips(&self, count: usize) -> Vec<String> {
        let ranges = self.read_source_ranges().await;
        if ranges.is_empty() {
            tracing::error!("No valid source IPs found in {}", self.source_ips_file);
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
                let mut rng = rand::rng();
                let range_idx = rng.random_range(0..ranges.len());
                let range = &ranges[range_idx];
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
                    active_tasks += 1;
                    let ip_clone = ip_str.clone();
                    
                    tokio::spawn(async move {
                        let max_ping_ms_val = max_ping.as_millis() as u64;
                        if Self::strict_test_ip_static(&ip_clone, &remotes, &tls, max_ping_ms_val).await {
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
        Self::strict_test_ip_static(ip, &self.remotes, &self.tls_connector, self.max_ping_ms).await
    }

    async fn strict_test_ip_static(
        ip: &str,
        remotes: &[crate::config::RemoteLocation],
        tls_connector: &TlsConnector,
        max_ping_ms: u64
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
