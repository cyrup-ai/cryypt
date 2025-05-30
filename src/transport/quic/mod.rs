//! QUIC encrypted transport protocol implementation
//!
//! This module provides encrypted transport using QUIC protocol with quantum-resistant
//! key exchange and post-quantum TLS configurations.

pub mod builder;
pub mod client;
pub mod error;
pub mod keys;
pub mod quic_conn;
pub mod server;

pub use builder::{QuicCryptoBuilder, QuicCryptoConfig};
pub use client::connect_quic_client;
pub use error::{CryptoTransportError, Result};
pub use quic_conn::{QuicConnectionEvent, QuicConnectionHandle};
pub use server::{run_quic_server, QuicServerConfig};
