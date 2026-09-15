mod acme;
mod client;
mod config;
mod scanner;

mod dynamic_proxy;
mod net_utils;
mod anti_loop;
mod prefixed_stream;

mod routing;
mod server;
mod web_server;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use client::run_client;
use config::AppConfig;
use server::run_server;

use std::{fs, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

// ==========================================
// 7. HOT-RELOAD & ENTRY POINT
// ==========================================
use std::path::Path;

async fn gather_and_provision_acme(
    cf_token: Option<&str>,
    arvan_token: Option<&str>,
    tunnel_sni: Option<&Vec<String>>,
    web_server: Option<&Vec<crate::config::WebServerConfig>>,
    copy_certs_to: Option<&Vec<String>>,
) -> bool {
    let mut all_snis = Vec::new();
    if let Some(snis) = tunnel_sni {
        all_snis.extend(snis.clone());
    }
    if let Some(ws_configs) = web_server {
        for ws in ws_configs {
            if let Some(domain) = ws.domain.split(':').next() {
                all_snis.push(domain.to_string());
            }
        }
    }
    if all_snis.is_empty() {
        return false;
    }

    let mut renewed = false;
    if let Ok(zones) = crate::acme::extract_zone_names(cf_token, arvan_token, &all_snis).await {
        for zone in zones {
            if crate::acme::needs_renewal(&zone) {
                tracing::info!(
                    "🔄 Certificate for {} needs renewal. Starting ACME...",
                    zone
                );
                if let Err(e) =
                    crate::acme::provision_acme_cert(cf_token, arvan_token, &zone, copy_certs_to)
                        .await
                {
                    tracing::error!("❌ ACME Provisioning failed for zone {}: {}", zone, e);
                } else {
                    renewed = true;
                }
            } else {
                crate::acme::copy_existing_certs(&zone, copy_certs_to);
            }
        }
    }
    renewed
}

fn resolve_file_path(path_str: &str, default_filename: &str) -> String {
    let p = path_str.trim();
    let p = if p.is_empty() { default_filename } else { p };
    let path = Path::new(p);

    let full_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let exe_dir = std::env::current_exe()
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
            .parent()
            .unwrap_or(Path::new(""))
            .to_path_buf();
        exe_dir.join(p)
    };

    if let Some(parent) = full_path.parent() {
        if !parent.exists() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    if !full_path.exists() {
        let _ = std::fs::File::create(&full_path);
    }

    full_path.to_string_lossy().to_string()
}

#[tokio::main]
async fn main() {
    #[cfg(unix)]
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
            rlim.rlim_cur = 65535.max(rlim.rlim_cur);
            rlim.rlim_max = 65535.max(rlim.rlim_max);
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
        }
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    let initial_content = fs::read_to_string(&config_path).expect("Failed to read config");
    let initial_config: AppConfig = toml::from_str(&initial_content).unwrap();

    let log_level = initial_config
        .log_level
        .clone()
        .or_else(|| {
            initial_config
                .client
                .as_ref()
                .and_then(|c| c.log_level.clone())
        })
        .or_else(|| {
            initial_config
                .server
                .as_ref()
                .and_then(|s| s.log_level.clone())
        })
        .unwrap_or_else(|| "info".to_string());

    let filter_str = format!(
        "h2=warn,rustls=warn,tokio_rustls=warn,GhostRPC={}",
        log_level
    );
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter_str));
    fmt()
        .with_env_filter(env_filter)
        .with_thread_ids(true)
        .with_target(false)
        .init();

    info!("🚀 Starting GhostRPC with SNI Routing & Hot-Reload");

    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    initial_content.hash(&mut hasher);
    let mut last_hash = hasher.finish();
    let mut current_cancel_token = CancellationToken::new();

    let token = current_cancel_token.clone();
    let cfg_initial = initial_config.clone();
    let config_path_main = config_path.clone();
    let _ = tokio::spawn(async move {
        if let Some(server_cfg) = cfg_initial.server {
            if server_cfg.cloudflare_api_token.is_some()
                || server_cfg.arvancloud_api_token.is_some()
            {
                let s_cfg = server_cfg.clone();
                let config_path_clone = config_path_main.clone();
                tokio::spawn(async move {
                    loop {
                        if s_cfg.cloudflare_api_token.is_some()
                            || s_cfg.arvancloud_api_token.is_some()
                        {
                            if gather_and_provision_acme(
                                s_cfg.cloudflare_api_token.as_deref(),
                                s_cfg.arvancloud_api_token.as_deref(),
                                s_cfg.tunnel_sni.as_ref(),
                                s_cfg.web_server.as_ref(),
                                s_cfg.copy_certs_to.as_ref(),
                            )
                            .await
                            {
                                if let Ok(mut f) = std::fs::OpenOptions::new()
                                    .append(true)
                                    .open(&config_path_clone)
                                {
                                    use std::io::Write;
                                    let _ = f.write_all(b"\n# ACME Auto-Renewed\n");
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(86400)).await; // 24 hours
                    }
                });
            }

            run_server(
                server_cfg,
                token,
            )
            .await;
        } else if let Some(mut client_cfg) = cfg_initial.client {
            if !client_cfg.remotes.is_empty() {
                client_cfg.clean_ip_file = Some(resolve_file_path(
                    &client_cfg.clean_ip_file.clone().unwrap_or_default(),
                    "ips/clean_ips.txt",
                ));
                client_cfg.source_ips_file = Some(resolve_file_path(
                    &client_cfg.source_ips_file.clone().unwrap_or_default(),
                    "ips/source_ips.txt",
                ));
            } else {
                client_cfg.clean_ip_file = None;
                client_cfg.source_ips_file = None;
            }

            if client_cfg.cloudflare_api_token.is_some()
                || client_cfg.arvancloud_api_token.is_some()
            {
                let c_cfg = client_cfg.clone();
                let config_path_clone = config_path_main.clone();
                tokio::spawn(async move {
                    loop {
                        if c_cfg.cloudflare_api_token.is_some()
                            || c_cfg.arvancloud_api_token.is_some()
                        {
                            if gather_and_provision_acme(
                                c_cfg.cloudflare_api_token.as_deref(),
                                c_cfg.arvancloud_api_token.as_deref(),
                                c_cfg.acme_domains.as_ref(),
                                c_cfg.web_server.as_ref(),
                                c_cfg.copy_certs_to.as_ref(),
                            )
                            .await
                            {
                                if let Ok(mut f) = std::fs::OpenOptions::new()
                                    .append(true)
                                    .open(&config_path_clone)
                                {
                                    use std::io::Write;
                                    let _ = f.write_all(b"\n# ACME Auto-Renewed Client\n");
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(86400)).await;
                    }
                });
            }

            run_client(
                client_cfg,
                token,
            )
            .await;
        } else {
            error!("❌ Neither [server] nor [client] configuration found!");
        }
    });

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                if let Ok(new_content) = fs::read_to_string(&config_path) {
                    let mut hasher = DefaultHasher::new();
                    new_content.hash(&mut hasher);
                    let new_hash = hasher.finish();
                    if new_hash != last_hash {
                        last_hash = new_hash;
                        info!("🔄 Config file changed! Initiating Zero-Downtime Hot-Reload...");

                        if let Ok(new_config) = toml::from_str::<AppConfig>(&new_content) {
                            if new_config.server.is_none() && new_config.client.is_none() {
                                error!("❌ Neither [server] nor [client] configuration found! Ignoring hot-reload.");
                                continue;
                            }
                            let token_new = CancellationToken::new();
                            let token_new_clone = token_new.clone();
                            let config_path_clone_reload = config_path.clone();


                            let _ = tokio::spawn(async move {
                                if let Some(server_cfg) = new_config.server {
                                    if server_cfg.cloudflare_api_token.is_some() || server_cfg.arvancloud_api_token.is_some() {
                                        let cf = server_cfg.cloudflare_api_token.clone();
                                        let arv = server_cfg.arvancloud_api_token.clone();
                                        let sni = server_cfg.tunnel_sni.clone();
                                        let proxy = server_cfg.web_server.clone();
                                        let certs = server_cfg.copy_certs_to.clone();
                                        tokio::spawn(async move {
                                            if gather_and_provision_acme(cf.as_deref(), arv.as_deref(), sni.as_ref(), proxy.as_ref(), certs.as_ref()).await {
                                                if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&config_path_clone_reload) {
                                                    use std::io::Write;
                                                    let _ = f.write_all(b"\n# ACME Reloaded\n");
                                                }
                                            }
                                        });
                                    }
                                    run_server(server_cfg, token_new_clone).await;
                                } else if let Some(mut client_cfg) = new_config.client {
                                    if !client_cfg.remotes.is_empty() {
                                        client_cfg.clean_ip_file = Some(resolve_file_path(&client_cfg.clean_ip_file.clone().unwrap_or_default(), "ips/clean_ips.txt"));
                                        client_cfg.source_ips_file = Some(resolve_file_path(&client_cfg.source_ips_file.clone().unwrap_or_default(), "ips/source_ips.txt"));
                                    } else {
                                        client_cfg.clean_ip_file = None;
                                        client_cfg.source_ips_file = None;
                                    }

                                    if client_cfg.cloudflare_api_token.is_some() || client_cfg.arvancloud_api_token.is_some() {
                                        let cf = client_cfg.cloudflare_api_token.clone();
                                        let arv = client_cfg.arvancloud_api_token.clone();
                                        let sni = client_cfg.acme_domains.clone();
                                        let proxy = client_cfg.web_server.clone();
                                        let certs = client_cfg.copy_certs_to.clone();
                                        tokio::spawn(async move {
                                            if gather_and_provision_acme(cf.as_deref(), arv.as_deref(), sni.as_ref(), proxy.as_ref(), certs.as_ref()).await {
                                                if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&config_path_clone_reload) {
                                                    use std::io::Write;
                                                    let _ = f.write_all(b"\n# ACME Reloaded\n");
                                                }
                                            }
                                        });
                                    }
                                    run_client(client_cfg, token_new_clone).await;
                                } else {
                                    error!("❌ Neither [server] nor [client] configuration found!");
                                }
                            });

                            // Wait 100ms for the new listener to bind and be ready via SO_REUSEPORT
                            tokio::time::sleep(Duration::from_millis(100)).await;

                            // Stop the old listener (active connections remain alive)
                            current_cancel_token.cancel();

                            current_cancel_token = token_new;
                            info!("✅ Reload successful. Traffic is now routing through the new settings.");
                        } else {
                            error!("❌ TOML Parse Error. Ignoring changes...");
                        }
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("🛑 Received signal (Ctrl+C). Initiating Graceful Shutdown...");
                // Signal listeners to stop accepting new connections
                current_cancel_token.cancel();

                info!("⏳ Waiting 3 seconds for active connections and pending operations to finish...");
                tokio::time::sleep(Duration::from_secs(3)).await;

                info!("👋 Graceful Shutdown complete. Exiting GhostRPC.");
                std::process::exit(0);
            }
        }
    }
}
