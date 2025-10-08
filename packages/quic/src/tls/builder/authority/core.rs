//! Core certificate authority domain types and logic
//!
//! This module contains the core domain objects and business logic for
//! certificate authorities, including validation, metadata, and the main
//! builder entry point.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::tls::errors::TlsError;

/// Convert a `HashMap` of distinguished name components to a string representation
pub(super) fn dn_hashmap_to_string(dn_map: &std::collections::HashMap<String, String>) -> String {
    if dn_map.is_empty() {
        return "Unknown".to_string();
    }

    dn_map
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Convert Vec<u8> serial number to hex string representation
pub(super) fn serial_to_string(serial: &[u8]) -> String {
    serial
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Certificate Authority domain object with serialization support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    pub name: String,
    pub certificate_pem: String,
    /// Private key PEM. None for validation-only CAs (e.g., remote CAs)
    pub private_key_pem: Option<String>,
    pub metadata: CaMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaMetadata {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub valid_from: SystemTime,
    pub valid_until: SystemTime,
    pub key_algorithm: String,
    pub key_size: Option<u32>,
    pub created_at: SystemTime,
    pub source: CaSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaSource {
    Filesystem { path: PathBuf },
    Keychain,
    Remote { url: String },
    Generated,
}

impl CertificateAuthority {
    /// Check if the certificate authority is currently valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now();
        now >= self.metadata.valid_from && now <= self.metadata.valid_until
    }

    /// Get duration until expiry
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate authority has already expired
    /// - System time calculation fails
    /// - Certificate validity period is invalid
    pub fn expires_in(&self) -> Result<Duration, TlsError> {
        let now = SystemTime::now();
        self.metadata.valid_until.duration_since(now).map_err(|_| {
            TlsError::CertificateExpired("Certificate authority has expired".to_string())
        })
    }

    /// Check if this CA can sign certificates for the given domain
    pub fn can_sign_for_domain(&self, domain: &str) -> bool {
        use crate::tls::certificate::parsing::{parse_certificate_from_pem, verify_hostname};

        if !self.is_valid() {
            return false;
        }

        // Parse CA certificate to check constraints
        let ca_cert = match parse_certificate_from_pem(&self.certificate_pem) {
            Ok(cert) => cert,
            Err(e) => {
                tracing::error!(
                    "Failed to parse CA certificate for domain validation: {}",
                    e
                );
                return false;
            }
        };

        // Check if this is a proper CA
        if !ca_cert.is_ca {
            tracing::warn!(
                "Certificate is not marked as CA, cannot sign for domain: {}",
                domain
            );
            return false;
        }

        // Delegate to existing hostname verification logic
        // If the CA certificate itself can validate this domain, then it can sign for it
        match verify_hostname(&ca_cert, domain) {
            Ok(()) => {
                tracing::debug!(
                    "CA can sign for domain '{}' - matches CA constraints",
                    domain
                );
                true
            }
            Err(_) => {
                tracing::warn!(
                    "CA certificate cannot sign for domain '{}' - no matching constraints",
                    domain
                );
                false
            }
        }
    }
}

/// Builder for certificate authority operations
#[derive(Debug, Clone)]
pub struct AuthorityBuilder {
    name: String,
}

impl AuthorityBuilder {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    /// Work with filesystem-based certificate authority
    #[must_use]
    pub fn path<P: AsRef<Path>>(self, path: P) -> super::filesystem::AuthorityFilesystemBuilder {
        super::filesystem::AuthorityFilesystemBuilder::new(self.name, path.as_ref().to_path_buf())
    }

    /// Work with keychain-based certificate authority (macOS/Windows)
    #[must_use]
    pub fn keychain(self) -> super::keychain::AuthorityKeychainBuilder {
        super::keychain::AuthorityKeychainBuilder::new(self.name)
    }

    /// Work with remote certificate authority
    pub fn url(self, url: &str) -> super::remote::AuthorityRemoteBuilder {
        super::remote::AuthorityRemoteBuilder::new(self.name, url.to_string())
    }
}
