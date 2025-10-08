//! QUIC crypto configuration builder
use super::error::{CryptoTransportError, Result};
use super::quic::config::Auth;
use std::sync::Arc;

/// QUIC crypto configuration
pub struct QuicCryptoConfig {
    // Store builder params instead of built config
    pub alpn_protocols: Vec<Vec<u8>>,
    pub auth_config: Option<Auth>,
    pub security: SecurityConfig,
    pub max_idle_timeout: u64,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub cc_algorithm: quiche::CongestionControlAlgorithm,
}

impl QuicCryptoConfig {
    /// Create a new crypto config with defaults
    #[must_use]
    pub fn new() -> Self {
        Self {
            alpn_protocols: vec![b"cryypt/1".to_vec()],
            auth_config: None,
            security: SecurityConfig::default(),
            max_idle_timeout: 30_000,
            max_udp_payload_size: 1350,
            initial_max_data: 10_000_000,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            cc_algorithm: quiche::CongestionControlAlgorithm::BBR,
        }
    }

    /// Set certificate chain
    pub fn set_cert_chain(&mut self, cert: Vec<u8>) {
        self.auth_config = Some(Auth::MutualTLS {
            cert,
            key: self
                .auth_config
                .as_ref()
                .and_then(|auth| {
                    if let Auth::MutualTLS { key, .. } = auth {
                        Some(key.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default(),
        });
    }

    /// Set private key
    pub fn set_private_key(&mut self, key: Vec<u8>) {
        self.auth_config = Some(Auth::MutualTLS {
            cert: self
                .auth_config
                .as_ref()
                .and_then(|auth| {
                    if let Auth::MutualTLS { cert, .. } = auth {
                        Some(cert.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default(),
            key,
        });
    }
    /// Create a new `quiche::Config`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - QUIC protocol version is unsupported
    /// - Configuration parameters are invalid
    /// - ALPN protocol setup fails
    /// - Certificate or key loading fails
    pub fn build_config(&self) -> Result<quiche::Config> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        // Apply settings
        config.set_max_idle_timeout(self.max_idle_timeout);
        #[allow(clippy::cast_possible_truncation)]
        config.set_max_recv_udp_payload_size(self.max_udp_payload_size as usize);
        config.set_initial_max_data(self.initial_max_data);
        config.set_initial_max_stream_data_bidi_local(self.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(self.initial_max_stream_data_bidi_remote);
        config.set_initial_max_streams_bidi(self.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(self.initial_max_streams_uni);
        config.set_ack_delay_exponent(self.ack_delay_exponent);
        config.set_max_ack_delay(self.max_ack_delay);
        config.set_disable_active_migration(self.security.connection.disable_active_migration);
        config.set_cc_algorithm(self.cc_algorithm);
        let alpn_refs: Vec<&[u8]> = self
            .alpn_protocols
            .iter()
            .map(std::vec::Vec::as_slice)
            .collect();
        config.set_application_protos(&alpn_refs)?;

        // Server-specific
        if let Some(Auth::MutualTLS { cert, key }) = &self.auth_config {
            // Write certificates to secure temporary files for quiche API
            use std::fs;
            use std::io::Write;
            use std::os::unix::fs::PermissionsExt;
            use tempfile::NamedTempFile;

            let mut cert_file = NamedTempFile::new().map_err(|e| {
                CryptoTransportError::CertificateInvalid(format!(
                    "Failed to create temp cert file: {e}"
                ))
            })?;
            let mut key_file = NamedTempFile::new().map_err(|e| {
                CryptoTransportError::CertificateInvalid(format!(
                    "Failed to create temp key file: {e}"
                ))
            })?;

            // Set restrictive permissions (600)
            fs::set_permissions(cert_file.path(), fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    CryptoTransportError::CertificateInvalid(format!(
                        "Failed to set cert permissions: {e}"
                    ))
                },
            )?;
            fs::set_permissions(key_file.path(), fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    CryptoTransportError::CertificateInvalid(format!(
                        "Failed to set key permissions: {e}"
                    ))
                },
            )?;

            // Write certificate and key data
            cert_file.write_all(cert).map_err(|e| {
                CryptoTransportError::CertificateInvalid(format!("Failed to write cert: {e}"))
            })?;
            key_file.write_all(key).map_err(|e| {
                CryptoTransportError::CertificateInvalid(format!("Failed to write key: {e}"))
            })?;

            cert_file.flush().map_err(|e| {
                CryptoTransportError::CertificateInvalid(format!("Failed to flush cert: {e}"))
            })?;
            key_file.flush().map_err(|e| {
                CryptoTransportError::CertificateInvalid(format!("Failed to flush key: {e}"))
            })?;

            let cert_path = cert_file.path().to_str().ok_or_else(|| {
                CryptoTransportError::CertificateInvalid(
                    "Certificate temp file path contains non-UTF-8 characters".to_string(),
                )
            })?;
            config
                .load_cert_chain_from_pem_file(cert_path)
                .map_err(|e| CryptoTransportError::CertificateInvalid(e.to_string()))?;

            let key_path = key_file.path().to_str().ok_or_else(|| {
                CryptoTransportError::CertificateInvalid(
                    "Key temp file path contains non-UTF-8 characters".to_string(),
                )
            })?;
            config
                .load_priv_key_from_pem_file(key_path)
                .map_err(|e| CryptoTransportError::CertificateInvalid(e.to_string()))?;

            // Files will be automatically cleaned up when NamedTempFile is dropped
        }

        // Client-specific
        if !self.security.tls.verify_peer {
            config.verify_peer(false);
        }

        Ok(config)
    }
}

impl Default for QuicCryptoConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS verification configuration for QUIC connections
#[derive(Debug, Clone)]
pub struct TlsVerificationConfig {
    pub verify_peer: bool,
    pub certificate_verification: bool,
    pub hostname_verification: bool,
}

impl Default for TlsVerificationConfig {
    fn default() -> Self {
        Self {
            verify_peer: true,
            certificate_verification: true,
            hostname_verification: true,
        }
    }
}

/// Connection behavior configuration for QUIC
#[derive(Debug, Clone, Default)]
pub struct ConnectionConfig {
    pub disable_active_migration: bool,
}

/// Security and verification configuration for QUIC connections
#[derive(Debug, Clone, Default)]
pub struct SecurityConfig {
    pub tls: TlsVerificationConfig,
    pub connection: ConnectionConfig,
}

/// Builder for QUIC crypto configuration
pub struct QuicCryptoBuilder {
    alpn_protocols: Vec<Vec<u8>>,
    security: SecurityConfig,
    server_name: Option<String>,
    root_certificates: Vec<rustls::pki_types::CertificateDer<'static>>,
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
    max_idle_timeout: u64,
    max_udp_payload_size: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    ack_delay_exponent: u64,
    max_ack_delay: u64,
    cc_algorithm: quiche::CongestionControlAlgorithm,
}

impl Default for QuicCryptoBuilder {
    fn default() -> Self {
        Self {
            alpn_protocols: vec![b"cryypt/1".to_vec()],
            security: SecurityConfig::default(),
            server_name: None,
            root_certificates: Vec::new(),
            client_cert_path: None,
            client_key_path: None,
            max_idle_timeout: 30_000,
            max_udp_payload_size: 1350,
            initial_max_data: 10_000_000,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            cc_algorithm: quiche::CongestionControlAlgorithm::BBR,
        }
    }
}

impl QuicCryptoBuilder {
    /// Create a new builder with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set ALPN protocols
    #[must_use]
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Set whether to verify peer certificates
    #[must_use]
    pub fn with_verify_peer(mut self, verify: bool) -> Self {
        self.security.tls.verify_peer = verify;
        self
    }

    /// Set maximum idle timeout in milliseconds
    #[must_use]
    pub fn with_max_idle_timeout(mut self, timeout_ms: u64) -> Self {
        self.max_idle_timeout = timeout_ms;
        self
    }

    /// Set maximum UDP payload size
    #[must_use]
    pub fn with_max_udp_payload_size(mut self, size: u64) -> Self {
        self.max_udp_payload_size = size;
        self
    }

    /// Set initial maximum data
    #[must_use]
    pub fn with_initial_max_data(mut self, max_data: u64) -> Self {
        self.initial_max_data = max_data;
        self
    }

    /// Set congestion control algorithm
    #[must_use]
    pub fn with_congestion_control(mut self, cc: quiche::CongestionControlAlgorithm) -> Self {
        self.cc_algorithm = cc;
        self
    }

    /// Set server name for SNI (Server Name Indication)
    #[must_use]
    pub fn with_server_name(mut self, server_name: &str) -> Self {
        self.server_name = Some(server_name.to_string());
        self
    }

    /// Enable or disable certificate verification
    #[must_use]
    pub fn with_certificate_verification(mut self, verify: bool) -> Self {
        self.security.tls.certificate_verification = verify;
        self
    }

    /// Enable or disable hostname verification
    #[must_use]
    pub fn with_hostname_verification(mut self, verify: bool) -> Self {
        self.security.tls.hostname_verification = verify;
        self
    }

    /// Add a root certificate to the trust store
    #[must_use]
    pub fn add_root_certificate(
        mut self,
        cert: rustls::pki_types::CertificateDer<'static>,
    ) -> Self {
        self.root_certificates.push(cert);
        self
    }

    /// Set client certificate file path for mutual TLS
    #[must_use]
    pub fn with_client_certificate_file(mut self, cert_path: &str) -> Self {
        self.client_cert_path = Some(cert_path.to_string());
        self
    }

    /// Set client private key file path for mutual TLS
    #[must_use]
    pub fn with_client_private_key_file(mut self, key_path: &str) -> Self {
        self.client_key_path = Some(key_path.to_string());
        self
    }

    /// Build server configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate file cannot be read or is invalid
    /// - Private key file cannot be read or is invalid
    /// - QUIC protocol version is unsupported
    /// - Configuration parameter validation fails
    /// - Certificate chain loading fails
    pub fn build_server(self, cert_path: &str, key_path: &str) -> Result<Arc<QuicCryptoConfig>> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        // Load certificate and key
        config
            .load_cert_chain_from_pem_file(cert_path)
            .map_err(|e| CryptoTransportError::CertificateInvalid(e.to_string()))?;
        config
            .load_priv_key_from_pem_file(key_path)
            .map_err(|e| CryptoTransportError::CertificateInvalid(e.to_string()))?;

        // Apply all settings
        self.apply_settings(&mut config);
        let alpn_refs: Vec<&[u8]> = self
            .alpn_protocols
            .iter()
            .map(std::vec::Vec::as_slice)
            .collect();
        config.set_application_protos(&alpn_refs)?;

        // Create auth config from cert/key files
        let cert = std::fs::read(cert_path)
            .map_err(|e| CryptoTransportError::CertificateInvalid(e.to_string()))?;
        let key = std::fs::read(key_path)
            .map_err(|e| CryptoTransportError::CertificateInvalid(e.to_string()))?;
        let auth_config = Some(Auth::MutualTLS { cert, key });

        Ok(Arc::new(QuicCryptoConfig {
            alpn_protocols: self.alpn_protocols,
            auth_config,
            security: self.security.clone(),
            max_idle_timeout: self.max_idle_timeout,
            max_udp_payload_size: self.max_udp_payload_size,
            initial_max_data: self.initial_max_data,
            initial_max_stream_data_bidi_local: self.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: self.initial_max_stream_data_bidi_remote,
            initial_max_streams_bidi: self.initial_max_streams_bidi,
            initial_max_streams_uni: self.initial_max_streams_uni,
            ack_delay_exponent: self.ack_delay_exponent,
            max_ack_delay: self.max_ack_delay,
            cc_algorithm: self.cc_algorithm,
        }))
    }

    /// Build client configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - QUIC protocol version is unsupported
    /// - ALPN protocol configuration fails
    /// - Certificate verification setup fails
    /// - Configuration parameter validation fails
    pub fn build_client(self) -> Result<Arc<QuicCryptoConfig>> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

        // Apply all settings
        self.apply_settings(&mut config);
        let alpn_refs: Vec<&[u8]> = self
            .alpn_protocols
            .iter()
            .map(std::vec::Vec::as_slice)
            .collect();
        config.set_application_protos(&alpn_refs)?;

        // Client-specific settings
        if !self.security.tls.verify_peer || !self.security.tls.certificate_verification {
            config.verify_peer(false);
        }

        // Set up client certificate authentication if provided
        let auth_config = if let (Some(cert_path), Some(key_path)) =
            (&self.client_cert_path, &self.client_key_path)
        {
            let cert = std::fs::read(cert_path)
                .map_err(|e| CryptoTransportError::CertificateInvalid(e.to_string()))?;
            let key = std::fs::read(key_path)
                .map_err(|e| CryptoTransportError::CertificateInvalid(e.to_string()))?;
            Some(Auth::MutualTLS { cert, key })
        } else {
            None
        };

        Ok(Arc::new(QuicCryptoConfig {
            alpn_protocols: self.alpn_protocols,
            auth_config,
            security: self.security.clone(),
            max_idle_timeout: self.max_idle_timeout,
            max_udp_payload_size: self.max_udp_payload_size,
            initial_max_data: self.initial_max_data,
            initial_max_stream_data_bidi_local: self.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: self.initial_max_stream_data_bidi_remote,
            initial_max_streams_bidi: self.initial_max_streams_bidi,
            initial_max_streams_uni: self.initial_max_streams_uni,
            ack_delay_exponent: self.ack_delay_exponent,
            max_ack_delay: self.max_ack_delay,
            cc_algorithm: self.cc_algorithm,
        }))
    }

    /// Apply common settings to configuration
    fn apply_settings(&self, config: &mut quiche::Config) {
        config.set_max_idle_timeout(self.max_idle_timeout);
        #[allow(clippy::cast_possible_truncation)]
        config.set_max_recv_udp_payload_size(self.max_udp_payload_size as usize);
        config.set_initial_max_data(self.initial_max_data);
        config.set_initial_max_stream_data_bidi_local(self.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(self.initial_max_stream_data_bidi_remote);
        config.set_initial_max_streams_bidi(self.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(self.initial_max_streams_uni);
        config.set_ack_delay_exponent(self.ack_delay_exponent);
        config.set_max_ack_delay(self.max_ack_delay);
        config.set_disable_active_migration(self.security.connection.disable_active_migration);
        config.set_cc_algorithm(self.cc_algorithm);
    }
}
