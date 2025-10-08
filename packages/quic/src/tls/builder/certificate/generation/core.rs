//! Core certificate generation operations
//!
//! This module handles basic certificate generation setup including:
//! - Certificate generator builder
//! - Domain configuration
//! - Basic parameter setup

use std::path::Path;

/// Certificate generator builder
#[derive(Debug, Clone)]
pub struct CertificateGenerator {
    // Internal state for generation configuration
}

impl CertificateGenerator {
    pub fn new() -> Self {
        Self {}
    }

    /// Generate certificate for single domain
    #[must_use]
    pub fn domain(self, domain: &str) -> CertificateGeneratorWithDomain {
        CertificateGeneratorWithDomain {
            domains: vec![domain.to_string()],
            is_wildcard: false,
            authority: None,
            self_signed: false,
            valid_for_days: 90,
            save_path: None,
        }
    }

    /// Generate certificate for multiple domains
    #[must_use]
    pub fn domains(self, domains: &[&str]) -> CertificateGeneratorWithDomain {
        CertificateGeneratorWithDomain {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            is_wildcard: false,
            authority: None,
            self_signed: false,
            valid_for_days: 90,
            save_path: None,
        }
    }

    /// Generate wildcard certificate for domain
    #[must_use]
    pub fn wildcard(self, domain: &str) -> CertificateGeneratorWithDomain {
        CertificateGeneratorWithDomain {
            domains: vec![format!("*.{}", domain)],
            is_wildcard: true,
            authority: None,
            self_signed: false,
            valid_for_days: 90,
            save_path: None,
        }
    }
}

/// Certificate generator with domain configured
#[derive(Debug, Clone)]
pub struct CertificateGeneratorWithDomain {
    pub(crate) domains: Vec<String>,
    pub(crate) is_wildcard: bool,
    pub(crate) authority: Option<super::super::super::authority::CertificateAuthority>,
    pub(crate) self_signed: bool,
    pub(crate) valid_for_days: u32,
    pub(crate) save_path: Option<std::path::PathBuf>,
}

impl CertificateGeneratorWithDomain {
    /// Sign certificate with certificate authority
    #[must_use]
    pub fn authority(self, ca: &super::super::super::authority::CertificateAuthority) -> Self {
        Self {
            authority: Some(ca.clone()),
            self_signed: false,
            ..self
        }
    }

    /// Generate self-signed certificate
    #[must_use]
    pub fn self_signed(self) -> Self {
        Self {
            self_signed: true,
            authority: None,
            ..self
        }
    }

    /// Set validity period in days
    #[must_use]
    pub fn valid_for_days(self, days: u32) -> Self {
        Self {
            valid_for_days: days,
            ..self
        }
    }

    /// Save generated certificate to path
    #[must_use]
    pub fn save_to<P: AsRef<Path>>(self, path: P) -> Self {
        Self {
            save_path: Some(path.as_ref().to_path_buf()),
            ..self
        }
    }

    /// Execute certificate generation
    pub async fn generate(self) -> super::super::super::responses::CertificateGenerationResponse {
        super::signing::perform_certificate_generation(self).await
    }
}
