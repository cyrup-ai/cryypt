//! Core types and structures for TLS management

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use zeroize::ZeroizeOnDrop;

// PBKDF2 iteration count constant (OWASP 2024 minimum)
#[allow(dead_code)]
pub const PBKDF2_ITERATIONS: std::num::NonZeroU32 = match std::num::NonZeroU32::new(600_000) {
    Some(n) => n,
    None => unreachable!(), // 600_000 is never zero
};

/// Certificate usage types for `KeyUsage` validation
#[derive(Debug, Clone, Copy)]
pub enum CertificateUsage {
    /// CA certificate usage
    CertificateAuthority,
    /// Server certificate usage (TLS server authentication)
    ServerAuth,
    /// Client certificate usage (TLS client authentication)
    /// This is library code intended for future client authentication support
    #[allow(dead_code)]
    ClientAuth,
}

/// Parsed certificate information extracted from X.509
#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    pub subject: HashMap<String, String>,
    pub issuer: HashMap<String, String>,
    pub san_dns_names: Vec<String>,
    pub san_ip_addresses: Vec<std::net::IpAddr>,
    pub is_ca: bool,
    pub key_usage: Vec<String>,
    pub not_before: std::time::SystemTime,
    pub not_after: std::time::SystemTime,
    pub serial_number: Vec<u8>,
    pub ocsp_urls: Vec<String>,
    pub crl_urls: Vec<String>,
    /// Raw DER-encoded subject for OCSP
    pub subject_der: Vec<u8>,
    /// Raw DER-encoded public key for OCSP
    pub public_key_der: Vec<u8>,
    /// Key algorithm name (RSA, ECDSA, Ed25519, Ed448, etc.)
    pub key_algorithm: String,
    /// Key size in bits (if determinable)
    pub key_size: Option<u32>,
}

/// CRL cache entry for performance optimization
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CrlCacheEntry {
    pub revoked_serials: HashSet<Vec<u8>>,
    pub cached_at: SystemTime,
    pub next_update: Option<SystemTime>,
}

/// CRL download and validation cache
#[allow(dead_code)]
#[derive(Clone)]
pub struct CrlCache {
    pub cache: std::sync::Arc<std::sync::RwLock<HashMap<String, CrlCacheEntry>>>,
    pub http_client: super::http_client::TlsHttpClient,
}

/// Secure key material that zeroes on drop
#[derive(ZeroizeOnDrop)]
pub struct SecureKeyMaterial {
    data: Vec<u8>,
}

impl SecureKeyMaterial {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}
