use hickory_resolver::{
    TokioResolver,
    proto::rr::{RData, RecordType},
};
use rcgen::{CertificateParams, KeyPair};
use std::time::{Duration, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::info;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsProvider {
    Cloudflare,
    Arvancloud,
}

impl DnsProvider {
    fn label(self) -> &'static str {
        match self {
            Self::Cloudflare => "Cloudflare",
            Self::Arvancloud => "ArvanCloud",
        }
    }
}

pub struct AcmeZone {
    pub name: String,
    pub provider: DnsProvider,
}

#[derive(Debug, PartialEq, Eq)]
enum DnsDetectionError {
    Lookup(String),
    ConflictingProviders,
}

fn normalize_domain(domain: &str) -> String {
    domain
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn domain_matches_zone(domain: &str, zone: &str) -> bool {
    let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    !zone.is_empty() && (domain == zone || domain.ends_with(&format!(".{}", zone)))
}

fn certificate_covers_domain(domain: &str, zone: &str) -> bool {
    let domain = normalize_domain(domain);
    let zone = normalize_domain(zone);
    if domain == zone {
        return true;
    }

    domain
        .strip_suffix(&format!(".{zone}"))
        .is_some_and(|subdomain| !subdomain.is_empty() && !subdomain.contains('.'))
}

fn provider_from_nameservers(
    nameservers: &[String],
) -> Result<Option<DnsProvider>, DnsDetectionError> {
    let mut cloudflare = false;
    let mut arvancloud = false;

    for nameserver in nameservers {
        let nameserver = nameserver.trim_end_matches('.').to_ascii_lowercase();
        // Provider-assigned NS host labels vary by zone; identify the operator by its DNS suffix.
        cloudflare |=
            nameserver == "ns.cloudflare.com" || nameserver.ends_with(".ns.cloudflare.com");
        arvancloud |= [
            ".arvancdn.ir",
            ".arvancloud.ir",
            ".arvancloud.com",
            ".arvancloud.net",
        ]
        .iter()
        .any(|suffix| nameserver.ends_with(suffix));
    }

    match (cloudflare, arvancloud) {
        (true, true) => Err(DnsDetectionError::ConflictingProviders),
        (true, false) => Ok(Some(DnsProvider::Cloudflare)),
        (false, true) => Ok(Some(DnsProvider::Arvancloud)),
        (false, false) => Ok(None),
    }
}

async fn detect_dns_provider(domain: &str) -> Result<Option<DnsProvider>, DnsDetectionError> {
    let domain = normalize_domain(domain);
    if domain.is_empty()
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    {
        return Err(DnsDetectionError::Lookup(
            "domain contains characters that cannot be used in a DNS lookup".to_string(),
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| DnsDetectionError::Lookup(error.to_string()))?;
    let mut errors = Vec::new();
    let system_resolver = match TokioResolver::builder_tokio() {
        Ok(mut builder) => {
            builder.options_mut().timeout = Duration::from_secs(3);
            builder.options_mut().attempts = 1;
            match builder.build() {
                Ok(resolver) => Some(resolver),
                Err(error) => {
                    errors.push(format!("could not initialize system DNS resolver: {error}"));
                    None
                }
            }
        }
        Err(error) => {
            errors.push(format!("could not read system DNS configuration: {error}"));
            None
        }
    };
    let resolvers = [
        "https://dns.google/resolve",
        "https://cloudflare-dns.com/dns-query",
    ];
    let mut attempted_lookups = 0;
    let mut failed_lookups = 0;
    let labels = domain.split('.').collect::<Vec<_>>();

    for start in 0..labels.len().saturating_sub(1) {
        let candidate = labels[start..].join(".");
        let mut system_dns_returned_nameservers = false;
        if let Some(resolver) = &system_resolver {
            attempted_lookups += 1;
            match tokio::time::timeout(
                Duration::from_secs(4),
                resolver.lookup(format!("{candidate}."), RecordType::NS),
            )
            .await
            {
                Ok(Ok(response)) => {
                    let nameservers = response
                        .answers()
                        .iter()
                        .chain(response.authorities())
                        .filter_map(|record| match &record.data {
                            RData::NS(nameserver) => Some(nameserver.0.to_string()),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    if !nameservers.is_empty() {
                        system_dns_returned_nameservers = true;
                        if let Some(provider) = provider_from_nameservers(&nameservers)? {
                            return Ok(Some(provider));
                        }
                    }
                }
                Ok(Err(error)) => {
                    failed_lookups += 1;
                    errors.push(format!("system DNS lookup for {candidate} failed: {error}"))
                }
                Err(_) => {
                    failed_lookups += 1;
                    errors.push(format!("system DNS lookup for {candidate} timed out"))
                }
            }
        }
        if !system_dns_returned_nameservers {
            for resolver in resolvers {
                attempted_lookups += 1;
                let url = format!("{resolver}?name={candidate}&type=NS");
                let response = match client
                    .get(url)
                    .header("Accept", "application/dns-json")
                    .send()
                    .await
                {
                    Ok(response) if response.status().is_success() => response,
                    Ok(response) => {
                        failed_lookups += 1;
                        errors.push(format!("{} returned HTTP {}", resolver, response.status()));
                        continue;
                    }
                    Err(error) => {
                        failed_lookups += 1;
                        errors.push(format!("{}: {}", resolver, error));
                        continue;
                    }
                };
                let body: serde_json::Value = match response.json().await {
                    Ok(body) => body,
                    Err(error) => {
                        failed_lookups += 1;
                        errors.push(format!("{} returned invalid DNS JSON: {}", resolver, error));
                        continue;
                    }
                };
                let nameservers = body["Answer"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|answer| answer["type"].as_u64() == Some(2))
                    .filter_map(|answer| answer["data"].as_str().map(str::to_string))
                    .collect::<Vec<_>>();
                if nameservers.is_empty() {
                    continue;
                }
                return provider_from_nameservers(&nameservers);
            }
        }
    }

    if attempted_lookups > 0 && failed_lookups == attempted_lookups {
        return Err(DnsDetectionError::Lookup(format!(
            "system DNS and DNS-over-HTTPS lookups failed: {}",
            errors.join("; ")
        )));
    }
    Ok(None)
}

// --- Arvancloud API Functions ---

async fn get_arvancloud_zone_info(api_token: &str, domain: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let base_domain = normalize_domain(domain);
    
    let url = "https://napi.arvancloud.ir/cdn/4.0/domains";
    let res = client.get(url)
        .header("Authorization", format!("Apikey {}", api_token))
        .send()
        .await.map_err(|e| e.to_string())?;

    let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    
    if let Some(data) = body["data"].as_array() {
        for zone in data {
            let name = zone["name"].as_str().unwrap_or("");
            if domain_matches_zone(&base_domain, name) {
                return Ok(name.to_ascii_lowercase());
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
    let base_domain = normalize_domain(domain);
    
    let url = "https://api.cloudflare.com/client/v4/zones";
    let mut page = 1u64;
    let mut best_match: Option<(String, String)> = None;
    loop {
        let page_url = format!("{url}?page={page}&per_page=50");
        let res = client.get(page_url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await.map_err(|e| e.to_string())?;

        let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    
        if body["success"].as_bool() != Some(true) {
            return Err(format!("Cloudflare API error: {:?}", body["errors"]));
        }

        let zones = body["result"].as_array().ok_or("No zones found")?;
        for zone in zones {
            let name = zone["name"].as_str().unwrap_or("").trim_end_matches('.');
            if domain_matches_zone(&base_domain, name)
                && best_match
                    .as_ref()
                    .map_or(true, |(_, current_name)| name.len() > current_name.len())
            {
                let id = zone["id"]
                    .as_str()
                    .ok_or("Cloudflare zone response omitted the zone ID")?;
                best_match = Some((id.to_string(), name.to_ascii_lowercase()));
            }
        }
        let total_pages = body["result_info"]["total_pages"].as_u64().unwrap_or(page);
        if page >= total_pages {
            break;
        }
        page += 1;
    }
    best_match.ok_or_else(|| format!("Zone not found for domain: {}", base_domain))
}

async fn resolve_zone(
    cf_token: Option<&str>,
    arvan_token: Option<&str>,
    domain: &str,
) -> Result<AcmeZone, String> {
    let detected_provider = match detect_dns_provider(domain).await {
        Ok(Some(provider)) => {
            info!(
                "DNS provider for {} detected from authoritative NS records: {}",
                domain,
                provider.label()
            );
            Some(provider)
        }
        Ok(None) => {
            tracing::debug!(
                "No supported authoritative NS provider detected for {}; checking configured DNS APIs",
                domain
            );
            None
        }
        Err(DnsDetectionError::ConflictingProviders) => {
            return Err(format!(
                "conflicting Cloudflare/ArvanCloud NS records were found for {}",
                domain
            ));
        }
        Err(DnsDetectionError::Lookup(error)) => {
            tracing::warn!(
                "Could not detect DNS provider from NS records for {}: {}; checking configured DNS APIs",
                domain,
                error
            );
            None
        }
    };

    if let Some(provider) = detected_provider {
        return match provider {
            DnsProvider::Cloudflare => {
                let token = cf_token.ok_or_else(|| {
                    format!(
                        "NS records identify Cloudflare for {}, but cloudflare_api_token is not configured",
                        domain
                    )
                })?;
                let (_, name) = get_cloudflare_zone_info(token, domain).await?;
                Ok(AcmeZone {
                    name,
                    provider: DnsProvider::Cloudflare,
                })
            }
            DnsProvider::Arvancloud => {
                let token = arvan_token.ok_or_else(|| {
                    format!(
                        "NS records identify ArvanCloud for {}, but arvancloud_api_token is not configured",
                        domain
                    )
                })?;
                let name = get_arvancloud_zone_info(token, domain).await?;
                Ok(AcmeZone {
                    name,
                    provider: DnsProvider::Arvancloud,
                })
            }
        };
    }

    let mut errors = Vec::new();
    if let Some(token) = cf_token {
        match get_cloudflare_zone_info(token, domain).await {
            Ok((_, name)) => {
                return Ok(AcmeZone {
                    name,
                    provider: DnsProvider::Cloudflare,
                });
            }
            Err(error) => errors.push(format!("Cloudflare: {}", error)),
        }
    }
    if let Some(token) = arvan_token {
        match get_arvancloud_zone_info(token, domain).await {
            Ok(name) => {
                return Ok(AcmeZone {
                    name,
                    provider: DnsProvider::Arvancloud,
                });
            }
            Err(error) => errors.push(format!("ArvanCloud: {}", error)),
        }
    }
    if errors.is_empty() {
        Err("no DNS provider token is configured".to_string())
    } else {
        Err(errors.join("; "))
    }
}

pub async fn extract_zone_names(
    cf_token: Option<&str>,
    arvan_token: Option<&str>,
    domains: &[String],
) -> Result<Vec<AcmeZone>, String> {
    let mut zones = Vec::new();
    let mut processed_domains = Vec::new();
    for domain in domains {
        let normalized_domain = normalize_domain(domain);
        if processed_domains.contains(&normalized_domain) {
            continue;
        }
        processed_domains.push(normalized_domain);
        match resolve_zone(cf_token, arvan_token, domain).await {
            Ok(zone) => {
                if !zones.iter().any(|existing: &AcmeZone| existing.name == zone.name) {
                    zones.push(zone);
                }
            }
            Err(error) => tracing::warn!(
                "Could not resolve ACME provider zone for '{}': {}",
                domain,
                error
            ),
        }
    }
    Ok(zones)
}

enum Provider {
    Cloudflare(String, String),
    Arvancloud(String),
}

pub async fn provision_acme_cert(
    cf_token: Option<&str>,
    arvan_token: Option<&str>,
    zone_name: &str,
    dns_provider: DnsProvider,
    copy_certs_to: Option<&Vec<String>>,
) -> Result<(), String> {
    let domains = vec![zone_name.to_string(), format!("*.{}", zone_name)];
    let email = format!("admin@{}", zone_name);

    info!("Starting ACME DNS-01 provisioning for domain: {}", zone_name);
    
    let provider = match dns_provider {
        DnsProvider::Cloudflare => {
            let token = cf_token.ok_or_else(|| {
                format!(
                    "NS records identify Cloudflare for {}, but cloudflare_api_token is not configured",
                    zone_name
                )
            })?;
            let (zone_id, _) = get_cloudflare_zone_info(token, zone_name).await?;
            Provider::Cloudflare(token.to_string(), zone_id)
        }
        DnsProvider::Arvancloud => {
            let token = arvan_token.ok_or_else(|| {
                format!(
                    "NS records identify ArvanCloud for {}, but arvancloud_api_token is not configured",
                    zone_name
                )
            })?;
            get_arvancloud_zone_info(token, zone_name).await?;
            Provider::Arvancloud(token.to_string())
        }
    };

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
    let Ok(file) = std::fs::File::open(&cert_path) else {
        return true;
    };
    let mut reader = std::io::BufReader::new(file);
    let Some(Ok(cert)) = rustls_pemfile::certs(&mut reader).next() else {
        tracing::warn!(
            "Certificate for {} is missing or unreadable; renewal is required",
            zone_name
            
        );
        return true;
    };
    let Some(validity) = crate::certinfo::validity(cert.as_ref()) else {
        tracing::warn!(
            "Certificate validity for {} could not be parsed; renewal is required",
            zone_name
        );
        return true;
    };
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(i64::MAX);
    renewal_due(validity.not_after, now)
}

fn renewal_due(not_after: i64, now: i64) -> bool {
    not_after <= now.saturating_add(30 * 24 * 60 * 60)
}

pub fn valid_certificate_zone_for_domain(domain: &str) -> Option<String> {
    let domain = normalize_domain(domain);
    let valid_zones = existing_cert_zone_names()
        .into_iter()
        .filter(|zone| !needs_renewal(zone))
        .collect::<Vec<_>>();
    most_specific_zone_for_domain(&domain, &valid_zones)
}

fn most_specific_zone_for_domain(domain: &str, zones: &[String]) -> Option<String> {
    zones
        .iter()
        .filter(|zone| certificate_covers_domain(domain, zone))
        .max_by_key(|zone| zone.len())
        .cloned()
}

pub fn existing_cert_zone_names() -> Vec<String> {
    let exe_dir = std::env::current_exe()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default())
        .parent()
        .unwrap_or(std::path::Path::new(""))
        .to_path_buf();
    let certs_dir = exe_dir.join("certs");
    let mut zones = Vec::new();
    let entries = match std::fs::read_dir(&certs_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return zones,
        Err(error) => {
            tracing::warn!(
                "Could not read certificate directory {}: {}",
                certs_dir.display(),
                error
            );
            return zones;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!("Could not inspect a certificate entry: {}", error);
                continue;
            }
        };
        let path = entry.path();
        if path.is_dir()
            && path.join("fullchain.pem").is_file()
            && path.join("privkey.pem").is_file()
        {
            zones.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    zones.sort();
    zones
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

#[cfg(test)]
mod tests {
    use super::{
        DnsProvider, certificate_covers_domain, domain_matches_zone,
        most_specific_zone_for_domain, normalize_domain, provider_from_nameservers, renewal_due,
    };

    #[test]
    fn provider_detection_accepts_varying_nameserver_hosts() {
        assert_eq!(
            provider_from_nameservers(&[
                "alpha.ns.cloudflare.com.".to_string(),
                "omega.ns.cloudflare.com.".to_string(),
            ]),
            Ok(Some(DnsProvider::Cloudflare))
        );
        assert_eq!(
            provider_from_nameservers(&[
                "dns-17.arvancdn.ir.".to_string(),
                "dns-42.arvancdn.ir.".to_string(),
            ]),
            Ok(Some(DnsProvider::Arvancloud))
        );
        assert_eq!(
            provider_from_nameservers(&[
                "ns01.arvancloud.ir.".to_string(),
                "ns02.arvancloud.ir.".to_string(),
            ]),
            Ok(Some(DnsProvider::Arvancloud))
        );
        assert_eq!(
            provider_from_nameservers(&["ns1.example.net.".to_string()]),
            Ok(None)
        );
        assert!(provider_from_nameservers(&[
            "fred.ns.cloudflare.com.".to_string(),
            "t.ns.arvancdn.ir.".to_string(),
        ])
        .is_err());
    }

    #[test]
    fn zone_matching_requires_a_dns_label_boundary() {
        assert!(domain_matches_zone(
            &normalize_domain("*.api.example.com."),
            "example.com"
        ));
        assert!(domain_matches_zone("example.com", "example.com"));
        assert!(!domain_matches_zone("notexample.com", "example.com"));
    }

    #[test]
    fn wildcard_certificate_only_covers_one_subdomain_label() {
        assert!(certificate_covers_domain("api.example.com", "example.com"));
        assert!(certificate_covers_domain("example.com", "example.com"));
        assert!(!certificate_covers_domain(
            "v1.api.example.com",
            "example.com"
        ));
    }

    #[test]
    fn valid_certificate_lookup_prefers_the_most_specific_zone() {
        let zones = vec![
            "example.com".to_string(),
            "api.example.com".to_string(),
            "unrelated.net".to_string(),
        ];
        assert_eq!(
            most_specific_zone_for_domain("v1.api.example.com", &zones),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            most_specific_zone_for_domain("other.example.com", &zones),
            Some("example.com".to_string())
        );
        assert_eq!(
            most_specific_zone_for_domain("v1.api.example.com", &zones),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            most_specific_zone_for_domain("v1.api.example.com", &zones[..1]),
            None
        );
        assert_eq!(most_specific_zone_for_domain("example.net", &zones), None);
    }

    #[test]
    fn renewal_uses_certificate_expiry_not_file_age() {
        let now = 1_800_000_000;
        assert!(renewal_due(now - 1, now));
        assert!(renewal_due(now + 30 * 24 * 60 * 60, now));
        assert!(!renewal_due(now + 31 * 24 * 60 * 60, now));
    }
}
