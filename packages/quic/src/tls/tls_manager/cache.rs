//! Pre-validation cache for async certificate validation results
//!
//! Provides caching for OCSP and CRL validation results to avoid blocking operations
//! during TLS handshakes.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Pre-validation cache for async certificate validation results
#[derive(Debug, Clone)]
pub struct ValidationCache {
    ocsp_results: Arc<RwLock<HashMap<String, crate::tls::ocsp::OcspStatus>>>,
    crl_results: Arc<RwLock<HashMap<String, crate::tls::crl_cache::CrlStatus>>>,
}

impl ValidationCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ocsp_results: Arc::new(RwLock::new(HashMap::new())),
            crl_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn get_ocsp_status(&self, cert_key: &str) -> Option<crate::tls::ocsp::OcspStatus> {
        self.ocsp_results.read().ok()?.get(cert_key).copied()
    }

    pub fn set_ocsp_status(&self, cert_key: String, status: crate::tls::ocsp::OcspStatus) {
        if let Ok(mut cache) = self.ocsp_results.write() {
            cache.insert(cert_key, status);
        }
    }

    #[must_use]
    pub fn get_crl_status(&self, cert_key: &str) -> Option<crate::tls::crl_cache::CrlStatus> {
        self.crl_results.read().ok()?.get(cert_key).copied()
    }

    pub fn set_crl_status(&self, cert_key: String, status: crate::tls::crl_cache::CrlStatus) {
        if let Ok(mut cache) = self.crl_results.write() {
            cache.insert(cert_key, status);
        }
    }
}
