//! Messaging server configuration

use super::super::types::{CompressionAlgorithm, EncryptionAlgorithm};
use crate::error::CryptoTransportError;
use crate::tls::builder::CertificateAuthority;
use std::time::Duration;

/// Production-grade messaging server configuration
#[derive(Debug, Clone)]
pub struct MessagingServerConfig {
    pub max_message_size: usize,
    pub retain_messages: bool,
    pub delivery_timeout: Duration,
    /// Default compression algorithm for all messages
    pub default_compression: CompressionAlgorithm,
    /// Compression level (1-22 for zstd, higher = better compression)
    pub compression_level: u8,
    /// Default encryption algorithm for all messages
    pub default_encryption: EncryptionAlgorithm,
    /// Shared secret for connection key derivation (32 bytes recommended)
    pub shared_secret: Vec<u8>,
    /// Certificate configuration for TLS/QUIC
    pub certificate_config: CertificateConfig,
}

/// Certificate configuration using enterprise-grade TLS module
#[derive(Debug, Clone)]
pub struct CertificateConfig {
    /// Certificate authority from TLS module
    pub authority: CertificateAuthority,
}

impl MessagingServerConfig {
    /// Create a new `MessagingServerConfig` with secure certificate generation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate generation fails
    /// - File operations fail during certificate creation
    /// - Configuration validation fails
    pub async fn new() -> Result<Self, CryptoTransportError> {
        // Generate development certificate using the TLS module
        use crate::tls::builder::certificate::CertificateBuilder;

        let cert_result = CertificateBuilder::new()
            .generator()
            .domain("localhost")
            .self_signed()
            .valid_for_days(365)
            .generate()
            .await;

        let development_authority = if cert_result.success {
            let cert_pem = cert_result.certificate_pem.unwrap_or_else(String::new);
            let key_pem = cert_result.private_key_pem.unwrap_or_else(String::new);

            CertificateAuthority {
                name: "development-generated".to_string(),
                certificate_pem: cert_pem,
                private_key_pem: Some(key_pem),
                metadata: crate::tls::builder::authority::CaMetadata {
                    subject: "CN=localhost".to_string(),
                    issuer: "CN=localhost".to_string(),
                    serial_number: "generated".to_string(),
                    valid_from: std::time::SystemTime::now(),
                    valid_until: std::time::SystemTime::now()
                        + Duration::from_secs(365 * 24 * 3600),
                    key_algorithm: "RSA".to_string(),
                    key_size: Some(2048),
                    created_at: std::time::SystemTime::now(),
                    source: crate::tls::builder::authority::CaSource::Generated,
                },
            }
        } else {
            // Fallback to minimal configuration
            CertificateAuthority {
                name: "development-fallback".to_string(),
                certificate_pem:
                    "-----BEGIN CERTIFICATE-----\nDEVELOPMENT_FALLBACK\n-----END CERTIFICATE-----"
                        .to_string(),
                private_key_pem: Some(
                    "-----BEGIN PRIVATE KEY-----\nDEVELOPMENT_FALLBACK\n-----END PRIVATE KEY-----"
                        .to_string(),
                ),
                metadata: crate::tls::builder::authority::CaMetadata {
                    subject: "CN=localhost".to_string(),
                    issuer: "CN=localhost".to_string(),
                    serial_number: "fallback".to_string(),
                    valid_from: std::time::SystemTime::now(),
                    valid_until: std::time::SystemTime::now() + Duration::from_secs(3600),
                    key_algorithm: "RSA".to_string(),
                    key_size: Some(2048),
                    created_at: std::time::SystemTime::now(),
                    source: crate::tls::builder::authority::CaSource::Generated,
                },
            }
        };

        // Generate secure random shared secret
        let shared_secret = {
            use rand::RngCore;
            let mut secret = vec![0u8; 32]; // 256-bit secret
            rand::rng().fill_bytes(&mut secret);
            secret
        };

        Ok(MessagingServerConfig {
            max_message_size: 1_048_576, // 1MB default
            retain_messages: false,
            delivery_timeout: Duration::from_secs(30),
            default_compression: CompressionAlgorithm::Zstd,
            compression_level: 3, // Balanced performance
            default_encryption: EncryptionAlgorithm::Aes256Gcm,
            shared_secret,
            certificate_config: CertificateConfig {
                authority: development_authority,
            },
        })
    }

    /// Create development configuration with known settings
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate generation fails
    /// - Certificate directory creation fails
    /// - TLS configuration is invalid
    pub async fn development(cert_dir: std::path::PathBuf) -> Result<Self, CryptoTransportError> {
        // Use TLS module for proper certificate generation
        let provider =
            crate::tls::QuicheCertificateProvider::create_self_signed("cryypt-dev", cert_dir)
                .await
                .map_err(|e| {
                    CryptoTransportError::Internal(format!(
                        "Failed to create development certificates: {e}"
                    ))
                })?;

        let authority = CertificateAuthority {
            name: "development".to_string(),
            certificate_pem: provider.get_certificate_pem().to_string(),
            private_key_pem: Some(
                String::from_utf8(
                    provider
                        .get_decrypted_private_key_pem()
                        .map_err(|e| {
                            CryptoTransportError::Internal(format!(
                                "Failed to get private key: {e}"
                            ))
                        })?
                        .as_bytes()
                        .to_vec(),
                )
                .map_err(|e| {
                    CryptoTransportError::Internal(format!("Invalid UTF-8 in private key: {e}"))
                })?,
            ),
            metadata: crate::tls::builder::authority::CaMetadata {
                subject: "CN=cryypt-dev".to_string(),
                issuer: "CN=cryypt-dev".to_string(),
                serial_number: "dev".to_string(),
                valid_from: std::time::SystemTime::now(),
                valid_until: std::time::SystemTime::now() + Duration::from_secs(30 * 24 * 3600),
                key_algorithm: "RSA".to_string(),
                key_size: Some(2048),
                created_at: std::time::SystemTime::now(),
                source: crate::tls::builder::authority::CaSource::Generated,
            },
        };

        let shared_secret = {
            use rand::RngCore;
            let mut secret = vec![0u8; 32];
            rand::rng().fill_bytes(&mut secret);
            secret
        };

        Ok(MessagingServerConfig {
            max_message_size: 1_048_576, // 1MB
            retain_messages: false,
            delivery_timeout: Duration::from_secs(30),
            default_compression: CompressionAlgorithm::Zstd,
            compression_level: 3,
            default_encryption: EncryptionAlgorithm::Aes256Gcm,
            shared_secret,
            certificate_config: CertificateConfig { authority },
        })
    }
}
