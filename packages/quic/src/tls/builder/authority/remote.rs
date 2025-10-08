//! Remote certificate authority operations
//!
//! This module handles certificate authority operations that involve fetching
//! certificates from remote URLs via HTTP(S), for validation-only purposes.

use std::time::{Duration, SystemTime};

use super::core::{
    CaMetadata, CaSource, CertificateAuthority, dn_hashmap_to_string, serial_to_string,
};

/// Builder for remote certificate authority operations
#[derive(Debug, Clone)]
pub struct AuthorityRemoteBuilder {
    name: String,
    url: String,
    timeout: Duration,
}

impl AuthorityRemoteBuilder {
    pub(super) fn new(name: String, url: String) -> Self {
        Self {
            name,
            url,
            timeout: Duration::from_secs(30),
        }
    }

    /// Set timeout for remote operations
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    /// Load certificate authority from remote URL
    pub async fn load(self) -> super::super::responses::CertificateAuthorityResponse {
        use crate::tls::certificate::parse_certificate_from_pem;
        use crate::tls::http_client::TlsHttpClient;

        let http_client = match TlsHttpClient::new() {
            Ok(client) => client,
            Err(e) => {
                return super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to create HTTP client: {e}")],
                    files_created: vec![],
                };
            }
        };

        // Download certificate from remote URL with configured timeout
        let cert_pem =
            match tokio::time::timeout(self.timeout, http_client.get_ca_certificate(&self.url))
                .await
            {
                Ok(Ok(pem)) => pem,
                Ok(Err(e)) => {
                    return super::super::responses::CertificateAuthorityResponse {
                        success: false,
                        authority: None,
                        operation: super::super::responses::CaOperation::LoadFailed,
                        issues: vec![format!(
                            "Failed to download CA certificate from {}: {}",
                            self.url, e
                        )],
                        files_created: vec![],
                    };
                }
                Err(_) => {
                    return super::super::responses::CertificateAuthorityResponse {
                        success: false,
                        authority: None,
                        operation: super::super::responses::CaOperation::LoadFailed,
                        issues: vec![format!(
                            "Timeout after {:?} downloading CA certificate from {}",
                            self.timeout, self.url
                        )],
                        files_created: vec![],
                    };
                }
            };

        // Parse the certificate to extract metadata
        let parsed_cert = match parse_certificate_from_pem(&cert_pem) {
            Ok(cert) => cert,
            Err(e) => {
                return super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to parse downloaded certificate: {e}")],
                    files_created: vec![],
                };
            }
        };

        // Validate that this is actually a CA certificate
        if !parsed_cert.is_ca {
            return super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::responses::CaOperation::LoadFailed,
                issues: vec![
                    "Downloaded certificate is not a Certificate Authority (CA bit not set)"
                        .to_string(),
                ],
                files_created: vec![],
            };
        }

        // Check if certificate is still valid
        let now = SystemTime::now();
        if now < parsed_cert.not_before || now > parsed_cert.not_after {
            return super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::responses::CaOperation::LoadFailed,
                issues: vec!["Downloaded CA certificate is expired or not yet valid".to_string()],
                files_created: vec![],
            };
        }

        // Note: We cannot load the private key from a remote URL for security reasons
        // This is intentional - remote CA loading only provides the public certificate
        // for validation purposes, not the private key for signing
        let authority = CertificateAuthority {
            name: self.name,
            certificate_pem: cert_pem.to_string(),
            private_key_pem: None, // No private key for validation-only remote CAs
            metadata: CaMetadata {
                subject: dn_hashmap_to_string(&parsed_cert.subject),
                issuer: dn_hashmap_to_string(&parsed_cert.issuer),
                serial_number: serial_to_string(&parsed_cert.serial_number),
                valid_from: parsed_cert.not_before,
                valid_until: parsed_cert.not_after,
                key_algorithm: parsed_cert.key_algorithm,
                key_size: parsed_cert.key_size,
                created_at: SystemTime::now(),
                source: CaSource::Remote { url: self.url },
            },
        };

        super::super::responses::CertificateAuthorityResponse {
            success: true,
            authority: Some(authority),
            operation: super::super::responses::CaOperation::Loaded,
            issues: vec![
                "Private key not available for remote CA - can only be used for validation"
                    .to_string(),
            ],
            files_created: vec![],
        }
    }
}
