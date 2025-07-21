#![feature(negative_impls)]
#![feature(marker_trait_attr)]

//! QUIC encrypted transport protocol implementation
//!
//! This module provides encrypted transport using QUIC protocol with quantum-resistant
//! key exchange and post-quantum TLS configurations.

// New beautiful QUIC API (primary public API)
// TODO: Fix to use new patterns
// pub mod quic;

// New cryypt-pattern API
pub mod api;
mod quic_result;

// Re-export result types
pub use quic_result::{QuicResult, QuicClientResult, QuicServerResult, QuicStreamResult, QuicWriteResult};

// Legacy high-level protocol builders
pub mod protocols;

// Low-level QUIC primitives (internal implementation)
mod builder;
mod client;
pub mod error;
mod keys;
mod quic_conn;
mod server;

// Export the new beautiful QUIC API (what users should use)
// TODO: Fix to use new patterns
// pub use quic::{Auth, Protocol, Quic as QuicOld, Transport};

// Export the new cryypt-pattern API
pub use api::{quic, Quic, QuicServer, QuicClient, QuicSend, QuicRecv, QuicMasterBuilder};

// Re-export common handlers from cryypt_common
pub use cryypt_common::{on_result, on_chunk, on_error};

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

// Export legacy protocol builders for backwards compatibility
pub use protocols::{
    FileTransferProgress, MessageDelivery, QuicFileTransfer, QuicMessaging, QuicRpc, RpcCall,
    RpcResponse, TransferResult,
};

// Export low-level primitives for advanced users
pub use builder::{QuicCryptoBuilder, QuicCryptoConfig};
pub use client::{connect_quic_client, Client};
pub use error::{CryptoTransportError, Result};
pub use quic_conn::{QuicConnectionEvent, QuicConnectionHandle};
pub use server::{run_quic_server, QuicServerConfig, Server};
