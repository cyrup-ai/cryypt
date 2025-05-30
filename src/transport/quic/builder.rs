//! QUIC crypto configuration builder
use std::sync::Arc;
use crate::error::{CryptoTransportError, Result};

/// QUIC crypto configuration
pub struct QuicCryptoConfig {
    pub quiche_config: quiche::Config,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

/// Builder for QUIC crypto configuration
pub struct QuicCryptoBuilder {
    alpn_protocols: Vec<Vec<u8>>,
    verify_peer: bool,
    max_idle_timeout: u64,
    max_udp_payload_size: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    ack_delay_exponent: u64,
    max_ack_delay: u64,
    disable_active_migration: bool,
    cc_algorithm: quiche::CongestionControlAlgorithm,
}

impl Default for QuicCryptoBuilder {
    fn default() -> Self {
        Self {
            alpn_protocols: vec![b"cryypt/1".to_vec()],
            verify_peer: true,
            max_idle_timeout: 30_000,
            max_udp_payload_size: 1350,
            initial_max_data: 10_000_000,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: true,
            cc_algorithm: quiche::CongestionControlAlgorithm::BBR,
        }
    }
}

impl QuicCryptoBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set ALPN protocols
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Set whether to verify peer certificates
    pub fn with_verify_peer(mut self, verify: bool) -> Self {
        self.verify_peer = verify;
        self
    }

    /// Set maximum idle timeout in milliseconds
    pub fn with_max_idle_timeout(mut self, timeout_ms: u64) -> Self {
        self.max_idle_timeout = timeout_ms;
        self
    }

    /// Set maximum UDP payload size
    pub fn with_max_udp_payload_size(mut self, size: u64) -> Self {
        self.max_udp_payload_size = size;
        self
    }

    /// Set initial maximum data
    pub fn with_initial_max_data(mut self, max_data: u64) -> Self {
        self.initial_max_data = max_data;
        self
    }

    /// Set congestion control algorithm
    pub fn with_congestion_control(mut self, cc: quiche::CongestionControlAlgorithm) -> Self {
        self.cc_algorithm = cc;
        self
    }

    /// Build server configuration
    pub fn build_server(self, cert_path: &str, key_path: &str) -> Result<Arc<QuicCryptoConfig>> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        
        // Load certificate and key
        config.load_cert_chain_from_pem_file(cert_path)
            .map_err(|e| CryptoTransportError::CertificateInvalid(e.to_string()))?;
        config.load_priv_key_from_pem_file(key_path)
            .map_err(|e| CryptoTransportError::CertificateInvalid(e.to_string()))?;
        
        // Apply all settings
        self.apply_settings(&mut config);
        config.set_application_protos(&self.alpn_protocols)?;
        
        Ok(Arc::new(QuicCryptoConfig {
            quiche_config: config,
            cert_path: Some(cert_path.to_string()),
            key_path: Some(key_path.to_string()),
        }))
    }

    /// Build client configuration
    pub fn build_client(self) -> Result<Arc<QuicCryptoConfig>> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        
        // Apply all settings
        self.apply_settings(&mut config);
        config.set_application_protos(&self.alpn_protocols)?;
        
        // Client-specific settings
        if !self.verify_peer {
            config.verify_peer(false);
        }
        
        Ok(Arc::new(QuicCryptoConfig {
            quiche_config: config,
            cert_path: None,
            key_path: None,
        }))
    }

    /// Apply common settings to configuration
    fn apply_settings(&self, config: &mut quiche::Config) {
        config.set_max_idle_timeout(self.max_idle_timeout);
        config.set_max_recv_udp_payload_size(self.max_udp_payload_size);
        config.set_initial_max_data(self.initial_max_data);
        config.set_initial_max_stream_data_bidi_local(self.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(self.initial_max_stream_data_bidi_remote);
        config.set_initial_max_streams_bidi(self.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(self.initial_max_streams_uni);
        config.set_ack_delay_exponent(self.ack_delay_exponent);
        config.set_max_ack_delay(self.max_ack_delay);
        config.set_disable_active_migration(self.disable_active_migration);
        config.set_cc_algorithm(self.cc_algorithm);
    }
}