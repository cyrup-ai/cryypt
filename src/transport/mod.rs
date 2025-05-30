//! Encrypted transport protocols
//!
//! This module provides encrypted transport implementations including QUIC streams

pub mod quic;

pub use quic::{
    QuicConnectionEvent, QuicConnectionHandle, QuicCryptoBuilder, QuicCryptoConfig,
    QuicServerConfig, connect_quic_client, run_quic_server,
};
