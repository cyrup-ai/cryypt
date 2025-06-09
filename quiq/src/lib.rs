//! Encrypted transport protocols
//!
//! This module provides encrypted transport implementations including QUIC streams

pub mod quic;

// Export the beautiful new Quique API
pub use quic::{Auth, Protocol, Quique, Transport};

// Export legacy QUIC APIs for backwards compatibility
pub use quic::{
    connect_quic_client, run_quic_server, QuicConnectionEvent, QuicConnectionHandle,
    QuicCryptoBuilder, QuicCryptoConfig, QuicServerConfig,
};
