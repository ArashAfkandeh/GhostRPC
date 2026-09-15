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

}

#[derive(Deserialize, Debug, Clone)]
pub struct RemoteLocation {
    pub location: String,
    pub sni: Vec<String>,
    pub port_mappings: Vec<String>,
    pub share_sni: Option<u32>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ClientConfig {
    pub log_level: Option<String>,
    pub clean_ip_file: Option<String>,
    pub source_ips_file: Option<String>,
    pub check_interval_minutes: Option<u64>,
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
}

#[derive(Debug, Clone, Default)]
pub struct Route {
    pub target_locations: HashMap<String, String>,
    pub default_upstream: Option<String>,
    pub sni_rules: HashMap<String, String>,
}
