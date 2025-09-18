//! Basic certificate validation operations
//!
//! This module handles basic certificate validation including:
//! - Certificate validator builder
//! - Input source handling
//! - Basic parsing and time validation

use super::super::super::authority::CertificateAuthority;
use super::super::types::InputSource;

/// Certificate validator builder
#[derive(Debug, Clone)]
pub struct CertificateValidator {
    // Internal state for validation configuration
}

impl CertificateValidator {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Load certificate from file
    #[must_use]
    pub fn from_file<P: AsRef<std::path::Path>>(self, path: P) -> CertificateValidatorWithInput {
        CertificateValidatorWithInput {
            input_source: InputSource::File(path.as_ref().to_path_buf()),
            domain: None,
            domains: None,
            authority: None,
        }
    }

    /// Load certificate from PEM string
    #[must_use]
    pub fn from_string(self, pem: &str) -> CertificateValidatorWithInput {
        CertificateValidatorWithInput {
            input_source: InputSource::String(pem.to_string()),
            domain: None,
            domains: None,
            authority: None,
        }
    }

    /// Load certificate from bytes
    #[must_use]
    pub fn from_bytes(self, bytes: &[u8]) -> CertificateValidatorWithInput {
        CertificateValidatorWithInput {
            input_source: InputSource::Bytes(bytes.to_vec()),
            domain: None,
            domains: None,
            authority: None,
        }
    }
}

/// Certificate validator with input source configured
#[derive(Debug, Clone)]
pub struct CertificateValidatorWithInput {
    pub(crate) input_source: InputSource,
    pub(crate) domain: Option<String>,
    pub(crate) domains: Option<Vec<String>>,
    pub(crate) authority: Option<CertificateAuthority>,
}

impl CertificateValidatorWithInput {
    /// Validate certificate for specific domain
    #[must_use]
    pub fn domain(self, domain: &str) -> Self {
        Self {
            domain: Some(domain.to_string()),
            ..self
        }
    }

    /// Validate certificate for multiple domains
    #[must_use]
    pub fn domains(self, domains: &[&str]) -> Self {
        Self {
            domains: Some(domains.iter().map(|d| d.to_string()).collect()),
            ..self
        }
    }

    /// Validate certificate against specific authority
    #[must_use]
    pub fn authority(self, ca: &CertificateAuthority) -> Self {
        Self {
            authority: Some(ca.clone()),
            ..self
        }
    }

    /// Execute validation with all security checks enabled by default
    pub async fn validate(self) -> super::super::super::responses::CertificateValidationResponse {
        super::security::perform_full_validation(self).await
    }
}
