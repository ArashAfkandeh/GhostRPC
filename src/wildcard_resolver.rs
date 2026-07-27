use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::Arc;

pub struct WildcardResolver {
    certs: HashMap<String, Arc<CertifiedKey>>,
}

impl WildcardResolver {
    pub fn new() -> Self {
        Self {
            certs: HashMap::new(),
        }
    }

    pub fn add(&mut self, name: String, cert: Arc<CertifiedKey>) {
        self.certs.insert(name, cert);
    }
}

impl ResolvesServerCert for WildcardResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        
        // Exact match
        if let Some(cert) = self.certs.get(sni) {
            return Some(cert.clone());
        }
        
        // Wildcard match
        if let Some(idx) = sni.find('.') {
            let wildcard = format!("*{}", &sni[idx..]);
            if let Some(cert) = self.certs.get(&wildcard) {
                return Some(cert.clone());
            }
        }
        
        None
    }
}
