//! QUIC configuration types
//!
//! Defines transport, authentication, and protocol configuration options
//! for QUIC connections.

/// Transport layer specification
#[derive(Debug, Clone, Copy)]
pub enum Transport {
    /// UDP transport (QUIC protocol)
    UDP,
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub enum Auth {
    /// Mutual TLS with certificate and private key
    MutualTLS {
        /// TLS certificate in DER or PEM format
        cert: Vec<u8>,
        /// Private key in DER or PEM format
        key: Vec<u8>,
    },
    /// Pre-shared key authentication
    PSK {
        /// Pre-shared key bytes
        key: Vec<u8>,
    },
    /// Anonymous connection (for testing only)
    Anonymous,
}

/// Application protocol types
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    /// File transfer protocol with progress tracking
    FileTransfer,
    /// Real-time messaging protocol
    Messaging,
    /// Remote procedure call protocol
    Rpc,
}
