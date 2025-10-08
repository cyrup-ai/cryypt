//! Filesystem certificate authority operations
//!
//! This module handles certificate authority operations that involve filesystem
//! I/O, including creating new CAs and loading existing ones from disk.

use std::path::PathBuf;
use std::time::SystemTime;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

use super::core::{
    CaMetadata, CaSource, CertificateAuthority, dn_hashmap_to_string, serial_to_string,
};

/// Builder for filesystem certificate authority operations
#[derive(Debug, Clone)]
pub struct AuthorityFilesystemBuilder {
    name: String,
    path: PathBuf,
    common_name: Option<String>,
    valid_for_years: u32,
    key_size: u32,
}

impl AuthorityFilesystemBuilder {
    pub(super) fn new(name: String, path: PathBuf) -> Self {
        Self {
            name,
            path,
            common_name: None,
            valid_for_years: 10,
            key_size: 2048,
        }
    }

    /// Set common name for certificate authority creation
    pub fn common_name(self, cn: &str) -> Self {
        Self {
            common_name: Some(cn.to_string()),
            ..self
        }
    }

    /// Set validity period in years for certificate authority creation
    pub fn valid_for_years(self, years: u32) -> Self {
        Self {
            valid_for_years: years,
            ..self
        }
    }

    /// Set key size for certificate authority creation
    pub fn key_size(self, bits: u32) -> Self {
        Self {
            key_size: bits,
            ..self
        }
    }

    /// Create a new certificate authority
    pub async fn create(self) -> super::super::responses::CertificateAuthorityResponse {
        // Create directory if it doesn't exist
        if let Err(e) = tokio::fs::create_dir_all(&self.path).await {
            return super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::responses::CaOperation::CreateFailed,
                issues: vec![format!("Failed to create directory: {e}")],
                files_created: vec![],
            };
        }

        // Generate CA certificate
        let mut params = match CertificateParams::new(vec![]) {
            Ok(params) => params,
            Err(e) => {
                return super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::responses::CaOperation::CreateFailed,
                    issues: vec![format!("Failed to create certificate parameters: {e}")],
                    files_created: vec![],
                };
            }
        };
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let mut distinguished_name = DistinguishedName::new();
        let common_name = self.common_name.unwrap_or_else(|| self.name.clone());
        distinguished_name.push(DnType::CommonName, &common_name);
        params.distinguished_name = distinguished_name;

        // Set validity period
        let now = SystemTime::now();
        params.not_before = now.into();
        params.not_after = (now
            + std::time::Duration::from_secs(365 * 24 * 3600 * self.valid_for_years as u64))
        .into();

        // Generate key pair
        let key_pair = KeyPair::generate().map_err(|e| format!("Failed to generate key pair: {e}"));

        let key_pair = match key_pair {
            Ok(kp) => kp,
            Err(e) => {
                return super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::responses::CaOperation::CreateFailed,
                    issues: vec![e],
                    files_created: vec![],
                };
            }
        };

        let cert = match params.self_signed(&key_pair) {
            Ok(c) => c,
            Err(e) => {
                return super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::responses::CaOperation::CreateFailed,
                    issues: vec![format!("Failed to generate certificate: {e}")],
                    files_created: vec![],
                };
            }
        };

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Both cert_pem and key_pem are now direct String results
        let (cert_pem, key_pem) = (cert_pem, key_pem);

        // Save files
        let cert_path = self.path.join("ca.crt");
        let key_path = self.path.join("ca.key");
        let mut files_created = vec![];

        if let Err(e) = tokio::fs::write(&cert_path, &cert_pem).await {
            return super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::responses::CaOperation::CreateFailed,
                issues: vec![format!("Failed to write certificate: {e}")],
                files_created,
            };
        }
        files_created.push(cert_path);

        if let Err(e) = tokio::fs::write(&key_path, &key_pem).await {
            return super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::responses::CaOperation::CreateFailed,
                issues: vec![format!("Failed to write private key: {e}")],
                files_created,
            };
        }
        files_created.push(key_path);

        // Create authority object
        let authority = CertificateAuthority {
            name: self.name.clone(),
            certificate_pem: cert_pem,
            private_key_pem: Some(key_pem),
            metadata: CaMetadata {
                subject: common_name.clone(),
                issuer: common_name,
                serial_number: "1".to_string(), // CA serial number
                valid_from: now,
                valid_until: now
                    + std::time::Duration::from_secs(365 * 24 * 3600 * self.valid_for_years as u64),
                key_algorithm: "RSA".to_string(),
                key_size: Some(self.key_size),
                created_at: now,
                source: CaSource::Generated,
            },
        };

        super::super::responses::CertificateAuthorityResponse {
            success: true,
            authority: Some(authority),
            operation: super::super::responses::CaOperation::Created,
            issues: vec![],
            files_created,
        }
    }

    /// Load existing certificate authority from filesystem
    pub async fn load(self) -> super::super::responses::CertificateAuthorityResponse {
        use crate::tls::certificate::parsing::parse_certificate_from_pem;

        let cert_path = self.path.join("ca.crt");
        let key_path = self.path.join("ca.key");

        // Check if both files exist
        if !tokio::fs::try_exists(&cert_path).await.unwrap_or(false)
            || !tokio::fs::try_exists(&key_path).await.unwrap_or(false)
        {
            return super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::responses::CaOperation::LoadFailed,
                issues: vec![format!("CA files not found at {:?}", self.path)],
                files_created: vec![],
            };
        }

        // Read certificate and key files
        let cert_pem = match tokio::fs::read_to_string(&cert_path).await {
            Ok(content) => content,
            Err(e) => {
                return super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to read certificate: {e}")],
                    files_created: vec![],
                };
            }
        };

        let key_pem = match tokio::fs::read_to_string(&key_path).await {
            Ok(content) => content,
            Err(e) => {
                return super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to read private key: {e}")],
                    files_created: vec![],
                };
            }
        };

        // Parse certificate to extract metadata
        let parsed_cert = match parse_certificate_from_pem(&cert_pem) {
            Ok(cert) => cert,
            Err(e) => {
                return super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to parse certificate: {e}")],
                    files_created: vec![],
                };
            }
        };

        let authority = CertificateAuthority {
            name: self.name.clone(),
            certificate_pem: cert_pem,
            private_key_pem: Some(key_pem),
            metadata: CaMetadata {
                subject: dn_hashmap_to_string(&parsed_cert.subject),
                issuer: dn_hashmap_to_string(&parsed_cert.issuer),
                serial_number: serial_to_string(&parsed_cert.serial_number),
                valid_from: parsed_cert.not_before,
                valid_until: parsed_cert.not_after,
                key_algorithm: parsed_cert.key_algorithm.clone(),
                key_size: parsed_cert.key_size,
                created_at: SystemTime::now(),
                source: CaSource::Filesystem {
                    path: self.path.clone(),
                },
            },
        };

        super::super::responses::CertificateAuthorityResponse {
            success: true,
            authority: Some(authority),
            operation: super::super::responses::CaOperation::Loaded,
            issues: vec![],
            files_created: vec![],
        }
    }
}
