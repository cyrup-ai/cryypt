#![feature(negative_impls)]
#![feature(marker_trait_attr)]

//! QUIC encrypted transport protocol implementation
//!
//! This module provides encrypted transport using QUIC protocol with quantum-resistant
//! key exchange and post-quantum TLS configurations.

// New beautiful QUIC API (primary public API)
pub mod quic;

// New cryypt-pattern API
pub mod api;
mod quic_result;

// Re-export result types
pub use quic_result::{
    QuicClientResult, QuicResult, QuicServerResult, QuicStreamResult, QuicWriteResult,
};

// Legacy high-level protocol builders
pub mod protocols;

// Low-level QUIC primitives (internal implementation)
mod builder;
mod client;
pub mod error;
mod keys;
mod quic_conn;
mod server;
pub mod tls;

// Export the new cryypt-pattern API (primary)
pub use api::{QuicClient, QuicMasterBuilder, QuicRecv, QuicSend, QuicServer, quic};

// Re-export common handlers from cryypt_common
pub use cryypt_common::{on_error, on_result};

// Implement NotResult for QUIC types to support on_result handlers
use cryypt_common::traits::NotResult;
impl NotResult for QuicServer {}
impl NotResult for QuicClient {}
impl NotResult for QuicSend {}
impl NotResult for QuicRecv {}

/// Main entry point - README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Master builder for QUIC operations - README.md pattern
    pub fn quic() -> QuicMasterBuilder {
        QuicMasterBuilder
    }
}

// Export protocol builders
pub use protocols::{
    FileTransferProgress, MessageDelivery, QuicFileTransfer, QuicMessaging, TransferResult,
};

// Export low-level primitives for advanced users
pub use builder::{QuicCryptoBuilder, QuicCryptoConfig};
pub use client::{Client, connect_quic_client};
pub use error::{CryptoTransportError, Result};
pub use quic_conn::{QuicConnectionEvent, QuicConnectionHandle};
pub use server::{QuicServerConfig, Server, run_quic_server};
