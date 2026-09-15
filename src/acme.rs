use rcgen::{CertificateParams, KeyPair};
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

// --- Arvancloud API Functions ---

async fn get_arvancloud_zone_info(api_token: &str, domain: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let mut base_domain = domain.to_string();
    if base_domain.starts_with("*.") {
        base_domain = base_domain[2..].to_string();
    }
    
    let url = "https://napi.arvancloud.ir/cdn/4.0/domains";
    let res = client.get(url)
        .header("Authorization", format!("Apikey {}", api_token))
        .send()
        .await.map_err(|e| e.to_string())?;

    let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    
    if let Some(data) = body["data"].as_array() {
        for zone in data {
            let name = zone["name"].as_str().unwrap_or("");
            if base_domain.ends_with(name) {
                return Ok(name.to_string());
            }
        }
    } else {
        return Err(format!("Arvancloud API error: {:?}", body));
    }
    Err(format!("Zone not found for domain: {}", base_domain))
}

async fn set_arvancloud_dns_record(api_token: &str, zone_name: &str, name: &str, content: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let url = format!("https://napi.arvancloud.ir/cdn/4.0/domains/{}/dns-records", zone_name);
    
    // Arvancloud API requires name relative to zone (or '@')
    let rel_name = if name.ends_with(zone_name) {
        let n = name.trim_end_matches(zone_name).trim_end_matches('.');
        if n.is_empty() { "@".to_string() } else { n.to_string() }
    } else {
        name.to_string()
    };

    let payload = serde_json::json!({
        "type": "txt",
        "name": rel_name,
        "value": {
            "text": content
        },
        "ttl": 120,
        "cloud": false
    });

    let res = client.post(&url)
        .header("Authorization", format!("Apikey {}", api_token))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await.map_err(|e| e.to_string())?;

    let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    
    if let Some(id) = body["data"]["id"].as_str() {
        Ok(id.to_string())
    } else {
        Err(format!("Arvancloud API error: {:?}", body))
    }
}

async fn delete_arvancloud_dns_record(api_token: &str, zone_name: &str, record_id: &str) {
    let client = reqwest::Client::new();
    let url = format!("https://napi.arvancloud.ir/cdn/4.0/domains/{}/dns-records/{}", zone_name, record_id);
    
    let _ = client.delete(&url)
        .header("Authorization", format!("Apikey {}", api_token))
        .send()
        .await;
}

// --- Cloudflare API Functions ---

async fn set_cloudflare_dns_record(zone_id: &str, api_token: &str, name: &str, content: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let url = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records", zone_id);
    
    let payload = serde_json::json!({
        "type": "TXT",
        "name": name,
        "content": content,
        "ttl": 60
    });

    let res = client.post(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await.map_err(|e| e.to_string())?;

    let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    
    if body["success"].as_bool() == Some(true) {
        let record_id = body["result"]["id"].as_str().unwrap_or("").to_string();
        Ok(record_id)
    } else {
        Err(format!("Cloudflare API error: {:?}", body["errors"]))
    }
}

async fn delete_cloudflare_dns_record(zone_id: &str, api_token: &str, record_id: &str) {
    let client = reqwest::Client::new();
    let url = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}", zone_id, record_id);
    
    let _ = client.delete(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await;
}

async fn get_cloudflare_zone_info(api_token: &str, domain: &str) -> Result<(String, String), String> {
    let client = reqwest::Client::new();
    let mut base_domain = domain.to_string();
    if base_domain.starts_with("*.") {
        base_domain = base_domain[2..].to_string();
    }
    
    let url = "https://api.cloudflare.com/client/v4/zones";
    let res = client.get(url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await.map_err(|e| e.to_string())?;

    let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    
    if body["success"].as_bool() != Some(true) {
        return Err(format!("Cloudflare API error: {:?}", body["errors"]));
    }
    
    let zones = body["result"].as_array().ok_or("No zones found")?;
    for zone in zones {
        let name = zone["name"].as_str().unwrap_or("");
        if base_domain.ends_with(name) {
            return Ok((zone["id"].as_str().unwrap().to_string(), name.to_string()));
        }
    }
    Err(format!("Zone not found for domain: {}", base_domain))
}

pub async fn extract_zone_names(cf_token: Option<&str>, arvan_token: Option<&str>, domains: &[String]) -> Result<Vec<String>, String> {
    let mut zones = Vec::new();
    for d in domains {
        let mut found = false;
        if let Some(token) = cf_token {
            if let Ok((_, zone_name)) = get_cloudflare_zone_info(token, d).await {
                if !zones.contains(&zone_name) {
                    zones.push(zone_name);
                }
                found = true;
            }
        }
        if !found {
            if let Some(token) = arvan_token {
                if let Ok(zone_name) = get_arvancloud_zone_info(token, d).await {
                    if !zones.contains(&zone_name) {
                        zones.push(zone_name);
                    }
                }
            }
        }
    }
    Ok(zones)
}

enum Provider {
    Cloudflare(String, String),
    Arvancloud(String),
}

pub async fn provision_acme_cert(cf_token: Option<&str>, arvan_token: Option<&str>, zone_name: &str, copy_certs_to: Option<&Vec<String>>) -> Result<(), String> {
    let domains = vec![zone_name.to_string(), format!("*.{}", zone_name)];
    let email = format!("admin@{}", zone_name);

    info!("Starting ACME DNS-01 provisioning for domain: {}", zone_name);
    
    let mut provider = None;
    if let Some(token) = cf_token {
        if let Ok((zone_id, _)) = get_cloudflare_zone_info(token, zone_name).await {
            provider = Some(Provider::Cloudflare(token.to_string(), zone_id));
        }
    }
    if provider.is_none() {
        if let Some(token) = arvan_token {
            if let Ok(_) = get_arvancloud_zone_info(token, zone_name).await {
                provider = Some(Provider::Arvancloud(token.to_string()));
            }
        }
    }
    let provider = provider.ok_or_else(|| format!("Zone not found in configured providers for domain: {}", zone_name))?;

    let new_account = instant_acme::NewAccount {
        contact: &[&format!("mailto:{}", email)],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let (account, _creds) = instant_acme::Account::builder().map_err(|e| e.to_string())?
        .create(&new_account, instant_acme::LetsEncrypt::Production.url().to_string(), None).await.map_err(|e| e.to_string())?;
    
    let identifiers: Vec<instant_acme::Identifier> = domains.iter().map(|d| instant_acme::Identifier::Dns(d.clone())).collect();
    let new_order = instant_acme::NewOrder::new(&identifiers);
    let mut order = account.new_order(&new_order).await.map_err(|e| e.to_string())?;
    let mut dns_records = Vec::new();

    let mut auths = order.authorizations();
    while let Some(Ok(mut auth)) = auths.next().await {
        let domain = format!("{}", auth.identifier());
        let record_name = format!("_acme-challenge.{}", domain.replace("*.", ""));
        
        let challenge = auth.challenge(instant_acme::ChallengeType::Dns01).ok_or("No DNS-01 challenge found")?;
        let txt_value = challenge.key_authorization().dns_value();
        
        info!("Setting DNS record for {}...", domain);
        let record_id = match &provider {
            Provider::Cloudflare(token, zone_id) => {
                set_cloudflare_dns_record(zone_id, token, &record_name, &txt_value).await?
            }
            Provider::Arvancloud(token) => {
                set_arvancloud_dns_record(token, zone_name, &record_name, &txt_value).await?
            }
        };
        dns_records.push(record_id);
    }

    info!("Waiting 30 seconds for DNS propagation...");
    sleep(Duration::from_secs(30)).await;

    let mut auths = order.authorizations();
    while let Some(Ok(mut auth)) = auths.next().await {
        let mut challenge = auth.challenge(instant_acme::ChallengeType::Dns01).unwrap();
        challenge.set_ready().await.map_err(|e| e.to_string())?;
    }

    loop {
        let state = order.state();
        if let instant_acme::OrderStatus::Ready | instant_acme::OrderStatus::Invalid | instant_acme::OrderStatus::Valid = state.status {
            break;
        }
        sleep(Duration::from_secs(3)).await;
        order.refresh().await.map_err(|e| e.to_string())?;
    }

    // Cleanup DNS records
    for rec_id in dns_records {
        match &provider {
            Provider::Cloudflare(token, zone_id) => {
                delete_cloudflare_dns_record(zone_id, token, &rec_id).await;
            }
            Provider::Arvancloud(token) => {
                delete_arvancloud_dns_record(token, zone_name, &rec_id).await;
            }
        }
    }

    if order.state().status == instant_acme::OrderStatus::Invalid {
        return Err("ACME Order failed".to_string());
    }

    // rcgen 0.14 KeyPair generation
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let mut params = CertificateParams::new(domains.to_vec()).map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new(); 
    let csr = params.serialize_request(&key_pair).map_err(|e| e.to_string())?;

    order.finalize_csr(csr.der()).await.map_err(|e| e.to_string())?;

    loop {
        if order.state().status == instant_acme::OrderStatus::Valid { break; }
        sleep(Duration::from_secs(3)).await;
        order.refresh().await.map_err(|e| e.to_string())?;
    }

    let cert_chain = order.certificate().await.map_err(|e| e.to_string())?.unwrap_or_default();
    
    let exe_dir = std::env::current_exe()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
        .parent()
        .unwrap_or(std::path::Path::new(""))
        .to_path_buf();
    let certs_dir = exe_dir.join("certs");
    
    let tls_cert = certs_dir.join(zone_name).join("fullchain.pem");
    let tls_key = certs_dir.join(zone_name).join("privkey.pem");
    
    if let Some(parent) = std::path::Path::new(&tls_cert).parent() {
    let _ = std::fs::create_dir_all(parent);
    }
    
    let cert_content = cert_chain.clone();
    let key_content = key_pair.serialize_pem();
    
    std::fs::write(&tls_cert, &cert_content).map_err(|e| e.to_string())?;
    std::fs::write(&tls_key, &key_content).map_err(|e| e.to_string())?;
    
    info!("✅ ACME Certificate successfully provisioned and saved to {} and {}", tls_cert.display(), tls_key.display());
    
    // Copy certs to custom paths if configured
    if let Some(paths) = copy_certs_to {
        for path_str in paths {
            let base_path = std::path::Path::new(path_str);
            if !base_path.exists() {
                tracing::debug!("⚠️ Base path {} does not exist. Skipping cert copy.", path_str);
                continue;
            }
            
            let target_dir = base_path.join("certs").join(zone_name);
            if !target_dir.exists() {
                if let Err(e) = std::fs::create_dir_all(&target_dir) {
                    tracing::error!("❌ Failed to create certificate copy directory {}: {}", target_dir.display(), e);
                    continue;
                }
            }
            
            let target_cert = target_dir.join("fullchain.pem");
            let target_key = target_dir.join("privkey.pem");
            
            if let Err(e) = std::fs::write(&target_cert, &cert_content) {
                tracing::error!("❌ Failed to copy cert to {}: {}", target_cert.display(), e);
            }
            if let Err(e) = std::fs::write(&target_key, &key_content) {
                tracing::error!("❌ Failed to copy key to {}: {}", target_key.display(), e);
            }
            
            info!("✅ Copied ACME Certificate to {}", target_dir.display());
        }
    }
    
    Ok(())
}

pub fn needs_renewal(zone_name: &str) -> bool {
    let exe_dir = std::env::current_exe()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
        .parent()
        .unwrap_or(std::path::Path::new(""))
        .to_path_buf();
    let cert_path = exe_dir.join("certs").join(zone_name).join("fullchain.pem");
    
    let _cert_data = match std::fs::read(&cert_path) {
        Ok(d) => d,
        Err(_) => return true,
    };
    // A simple check: if file is older than 60 days, renew.
    if let Ok(metadata) = std::fs::metadata(cert_path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                if elapsed.as_secs() > 60 * 24 * 3600 {
                    return true;
                }
            }
        }
    }
    false
}

pub fn copy_existing_certs(zone_name: &str, copy_certs_to: Option<&Vec<String>>) {
    if let Some(paths) = copy_certs_to {
        let exe_dir = std::env::current_exe()
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
            .parent()
            .unwrap_or(std::path::Path::new(""))
            .to_path_buf();
        let certs_dir = exe_dir.join("certs");
        let tls_cert = certs_dir.join(zone_name).join("fullchain.pem");
        let tls_key = certs_dir.join(zone_name).join("privkey.pem");
        
        if !tls_cert.exists() || !tls_key.exists() {
            return;
        }
        
        let cert_content = std::fs::read(&tls_cert).unwrap_or_default();
        let key_content = std::fs::read(&tls_key).unwrap_or_default();
        
        for path_str in paths {
            let base_path = std::path::Path::new(path_str);
            if !base_path.exists() {
                tracing::debug!("⚠️ Base path {} does not exist. Skipping cert copy.", path_str);
                continue;
            }
            
            let target_dir = base_path.join("certs").join(zone_name);
            if !target_dir.exists() {
                if let Err(e) = std::fs::create_dir_all(&target_dir) {
                    tracing::error!("❌ Failed to create certificate copy directory {}: {}", target_dir.display(), e);
                    continue;
                }
            }
            
            let target_cert = target_dir.join("fullchain.pem");
            let target_key = target_dir.join("privkey.pem");
            
            if let Err(e) = std::fs::write(&target_cert, &cert_content) {
                tracing::error!("❌ Failed to copy cert to {}: {}", target_cert.display(), e);
            }
            if let Err(e) = std::fs::write(&target_key, &key_content) {
                tracing::error!("❌ Failed to copy key to {}: {}", target_key.display(), e);
            }
            
            tracing::info!("✅ Copied existing ACME Certificate to {}", target_dir.display());
        }
    }
}
