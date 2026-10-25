use serde::Deserialize;
use std::collections::HashMap;

// ==========================================
// 1. CONFIGURATION (TOML)
// ==========================================

#[derive(Deserialize, Debug, Clone)]
pub struct WebServerConfig {
    pub domain: String,
    #[serde(default = "default_path")]
    pub path: String,
    pub r#type: String, // "static", "fastcgi", "reverse_proxy"
    pub root: Option<String>,
    pub target: Option<String>,
    pub block_hidden_files: Option<bool>,
    #[serde(default)]
    pub rewrites: Option<HashMap<String, String>>,
    #[serde(flatten)]
    pub extra: HashMap<String, String>,
}

fn default_path() -> String {
    "/".to_string()
}

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub log_level: Option<String>,
    pub server: Option<ServerConfig>,
    pub client: Option<ClientConfig>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SniProxyConfig {
    #[serde(default)]
    pub incoming_sni: Vec<String>,
    #[serde(default)]
    pub target: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ServerConfig {
    pub log_level: Option<String>,
    #[serde(default)]
    pub bind_addr: String,
    #[serde(default)]
    pub hidden_path: String,
    pub sni_proxy: Option<Vec<SniProxyConfig>>,
    pub web_server: Option<Vec<WebServerConfig>>,
    pub camouflage_target: Option<String>,
    pub cloudflare_api_token: Option<String>,
    pub arvancloud_api_token: Option<String>,
    pub tunnel_sni: Option<Vec<String>>,
    pub secret: Option<String>,
    pub copy_certs_to: Option<Vec<String>>,
    /// Reverse mode: this server dials OUT to the client (Iran side) in addition to
    /// accepting direct connections. See `[[server.reverse]]` in server.toml.
    #[serde(default)]
    pub reverse: Option<Vec<ReverseDialConfig>>,
    /// Ordered protocol priority for the tunnel: "h2" (HTTP/2 gRPC) and/or "wssmux" (WebSocket+yamux).
    /// The first entry is preferred, the rest are automatic fallbacks (Direct listener accepts all
    /// listed protocols; reverse dialers switch to the next one when a protocol cannot connect).
    /// Default (omitted): ["h2", "wssmux"].
    #[serde(default)]
    pub protocols: Option<Vec<String>>,
}

/// One reverse-tunnel target (the server dials OUT to the client, optionally through a CDN).
/// `secret` / `hidden_path` are taken from the enclosing `[server]` section; TLS certificates are
/// always validated (exactly like the Direct tunnel).
#[derive(Deserialize, Debug, Clone)]
pub struct ReverseDialConfig {
    /// Clean IPs: candidate addresses to connect to: clean CDN IPs (e.g. Cloudflare) and/or domains. Entries
    /// without a port use the port of `sni` (default 443). Every new connection races all of them.
    /// May be omitted when `sni` is a domain (then the domain itself is used).
    #[serde(default)]
    pub clean_ip: Vec<String>,
    /// Domain presented as TLS SNI and HTTP Host, optionally "domain:port" (like Direct's `sni`).
    /// Defaults to the host of the first `clean_ip` entry when that is a domain.
    pub sni: Option<String>,
    /// Number of parallel HTTP/2 connections (default 8, each keeps 4 ready streams = 32 parked streams).
    pub pool_size: Option<usize>,
    /// Optional label: attaches this reverse tunnel to a `[[client.remotes]]` location so that
    /// `share_sni` rules apply and the server connects to localhost for that location's own targets
    /// (`try_local`). Without it the tunnel is a pure forwarder: usable for every target (after the
    /// target's own location) and the server always dials the real target host directly.
    pub location: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RemoteLocation {
    pub location: String,
    /// May be empty for a reverse-only location.
    #[serde(default)]
    pub sni: Vec<String>,
    pub port_mappings: Vec<String>,
    pub share_sni: Option<u32>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ClientConfig {
    pub log_level: Option<String>,
    pub clean_ip_file: Option<String>,
    /// Cloudflare IP range file (default: `ips/cloudflare_ip_ranges.txt`); ArvanCloud ranges use
    /// the sibling file `arvancloud_ip_ranges.txt`.
    pub source_ips_file: Option<String>,
    /// CDN whose IP ranges the clean-IP scanner uses: "auto" (default: detected from the DNS of the
    /// Direct SNI), "arvancloud" or "cloudflare".
    pub scanner_cdn: Option<String>,
    pub check_interval_minutes: Option<u64>,
    /// Background tunnel path health check interval in minutes (default: 1).
    pub tunnel_health_check_interval_minutes: Option<u64>,
    pub max_ping_ms: Option<u64>,
    pub web_server: Option<Vec<WebServerConfig>>,
    pub cloudflare_api_token: Option<String>,
    pub arvancloud_api_token: Option<String>,
    pub acme_domains: Option<Vec<String>>,
    #[serde(default)]
    pub remotes: Vec<RemoteLocation>,
    #[serde(default)]
    pub hidden_path: String,
    pub pool_size_per_node: Option<usize>,
    pub secret: Option<String>,
    pub copy_certs_to: Option<Vec<String>>,
    pub sni_proxy: Option<Vec<SniProxyConfig>>,
    /// Reverse mode: address on which the client accepts tunnels dialed by the server.
    pub reverse_bind_addr: Option<String>,
    /// Domain(s) of the reverse tunnel. They (1) identify reverse tunnels on ANY client listener
    /// (e.g. 443 shared with port_mappings / web_server) and (2) get a Wildcard SSL certificate
    /// via ACME, exactly like the server's `tunnel_sni`. Supports "*.example.com".
    pub reverse_tunnel_sni: Option<Vec<String>>,
    /// Ordered protocol priority: "h2" (HTTP/2 gRPC) and/or "wssmux" (WebSocket+yamux). The first
    /// entry is preferred, the rest are automatic fallbacks for Direct dialing and Reverse
    /// acceptance. Default (omitted): ["h2", "wssmux"].
    #[serde(default)]
    pub protocols: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct Route {
    pub target_locations: HashMap<String, String>,
    pub default_upstream: Option<String>,
    pub sni_rules: HashMap<String, String>,
}

impl ClientConfig {
    /// Domains for which the client must hold a Wildcard certificate: `acme_domains` plus the
    /// reverse tunnel domains (`reverse_tunnel_sni`), mirroring the server's `tunnel_sni` handling.
    pub fn acme_domain_list(&self) -> Option<Vec<String>> {
        let mut all: Vec<String> = self.acme_domains.clone().unwrap_or_default();
        for d in self.reverse_tunnel_sni.clone().unwrap_or_default() {
            let d = d.trim().to_string();
            if !d.is_empty() && !all.contains(&d) {
                all.push(d);
            }
        }
        if all.is_empty() { None } else { Some(all) }
    }
}

#[cfg(test)]
mod reverse_config_tests {
    use super::*;

    #[derive(Deserialize)]
    struct Root {
        server: Option<ServerConfig>,
        client: Option<ClientConfig>,
    }

    #[test]
    fn new_names_parse_and_feed_acme() {
        let r: Root = toml::from_str(
            r#"
[server]
bind_addr = "0.0.0.0:443"
[[server.reverse]]
clean_ip = ["104.16.1.1", "104.17.2.2"]
sni = "respina.example.com:2083"

[client]
reverse_bind_addr = "0.0.0.0:2083"
reverse_tunnel_sni = ["*.example.com", "respina.example.com"]
acme_domains = ["*.example.com", "other.org"]
"#,
        )
        .unwrap();
        let rv = &r.server.unwrap().reverse.unwrap()[0];
        assert_eq!(rv.clean_ip, vec!["104.16.1.1", "104.17.2.2"]);
        let c = r.client.unwrap();
        assert_eq!(c.reverse_bind_addr.as_deref(), Some("0.0.0.0:2083"));
        // union, de-duplicated, order preserved
        assert_eq!(
            c.acme_domain_list().unwrap(),
            vec!["*.example.com", "other.org", "respina.example.com"]
        );
    }

    #[test]
    fn legacy_names_are_no_longer_accepted() {
        // The old alias names (`connect`, `reverse_bind`, `reverse_sni`) were removed: only the
        // current names (`clean_ip`, `reverse_bind_addr`, `reverse_tunnel_sni`) are valid.
        let r: Root = toml::from_str(
            r#"
[server]
[[server.reverse]]
connect = ["1.2.3.4"]
[client]
reverse_bind = "0.0.0.0:2083"
reverse_sni = ["a.example.com"]
"#,
        )
        .unwrap();
        assert!(r.server.unwrap().reverse.unwrap()[0].clean_ip.is_empty());
        let c = r.client.unwrap();
        assert!(c.reverse_bind_addr.is_none());
        assert!(c.reverse_tunnel_sni.is_none());
        assert!(c.acme_domain_list().is_none());
    }

    #[test]
    fn protocols_key_parses_on_both_sides() {
        let r: Root = toml::from_str(
            r#"
[server]
protocols = ["wssmux", "h2"]
[client]
protocols = ["h2"]
"#,
        )
        .unwrap();
        assert_eq!(r.server.unwrap().protocols.unwrap(), vec!["wssmux", "h2"]);
        assert_eq!(r.client.unwrap().protocols.unwrap(), vec!["h2"]);
        let r: Root = toml::from_str("[client]\n[server]\n").unwrap();
        assert!(r.client.unwrap().protocols.is_none());
    }

    #[test]
    fn tunnel_health_interval_is_optional_and_parsed_in_minutes() {
        let r: Root =
            toml::from_str("[client]\ntunnel_health_check_interval_minutes = 7\n[server]\n")
                .unwrap();
        assert_eq!(
            r.client.unwrap().tunnel_health_check_interval_minutes,
            Some(7)
        );

        let r: Root = toml::from_str("[client]\n[server]\n").unwrap();
        assert_eq!(r.client.unwrap().tunnel_health_check_interval_minutes, None);
    }

    #[test]
    fn no_reverse_keys_means_no_acme_domains() {
        let r: Root = toml::from_str("[client]\n").unwrap();
        assert!(r.client.unwrap().acme_domain_list().is_none());
    }
}
