use serde::Deserialize;
use std::collections::HashMap;

// ==========================================
// 1. CONFIGURATION (TOML)
// ==========================================

#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub log_level: Option<String>,
    pub server: Option<ServerConfig>,
    pub client: Option<ClientConfig>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub secret: String,
    pub hidden_path: String,
    // این دامنه‌ی پوششی (مثلاً "www.ubuntu.com") همانی است که ترافیک
    // غیرمجاز/اسکنرها به صورت خام (Layer-4 Splice) به آن هدایت می‌شوند.
    pub camouflage_domain: Option<String>,
    // آدرس IP:Port واقعی سرور هدف که در صورت عدم احراز هویت، اتصال TCP
    // به صورت کاملاً خام (بدون دخالت در محتوا) به آن Forward می‌شود.
    pub reality_target_addr: Option<String>,
    
    // فیلدهای قدیمی جهت سازگاری با نسخه‌های قبل
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub reality_fallback_url: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RemoteNode {
    pub addr: String,
    pub sni: String,
    pub host: String,
    pub protocol: Option<String>, // "h2" or "quic"
}

fn default_pool_size() -> usize { 5 }

#[derive(Deserialize, Debug, Clone)]
pub struct ClientConfig {
    pub port_mappings: Vec<String>,
    pub remotes: Vec<RemoteNode>,
    pub hidden_path: String,
    pub secret: String,
    #[serde(default = "default_pool_size")]
    pub pool_size_per_node: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Route {
    pub default_upstream: Option<String>,
    pub sni_rules: HashMap<String, String>,
}
