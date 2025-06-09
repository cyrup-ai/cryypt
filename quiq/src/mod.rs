//! QUIC encrypted transport protocol implementation
//!
//! This module provides encrypted transport using QUIC protocol with quantum-resistant
//! key exchange and post-quantum TLS configurations.
//!
//! ## Quique - Beautiful QUIC API (Recommended)
//!
//! For most users, use the new Quique API with persistent connections and multiplexed protocols:
//! - [`Quique::client()`] - Establish persistent QUIC client connections
//! - [`Quique::server()`] - Create QUIC servers with protocol dispatch
//!
//! ## Legacy High-Level Protocol Builders
//!
//! Legacy protocol builders (deprecated, use Quique instead):
//! - [`QuicFileTransfer`] - Complete file transfer with resume, checksums, compression
//! - [`QuicMessaging`] - Real-time messaging with delivery guarantees
//! - [`QuicRpc`] - Request/response patterns with timeouts and retries
//!
//! ## Low-Level QUIC Primitives (Advanced)
//!
//! For advanced users who need direct QUIC control:
//! - [`QuicCryptoBuilder`] - Low-level QUIC configuration
//! - [`connect_quic_client`], [`run_quic_server`] - Raw connection management

// New beautiful Quique API (primary public API)
pub mod quique;

// Legacy high-level protocol builders
pub mod protocols;

// Low-level QUIC primitives (internal implementation)
mod builder;
mod client;
pub mod error;
mod keys;
mod quic_conn;
mod server;

// Export the new beautiful Quique API (what users should use)
pub use quique::{Auth, Protocol, Quique, Transport};

// Export legacy protocol builders for backwards compatibility
pub use protocols::{
    FileTransferProgress, MessageDelivery, QuicFileTransfer, QuicMessaging, QuicRpc, RpcCall,
    RpcResponse, TransferResult,
};

// Export low-level primitives for advanced users
pub use builder::{QuicCryptoBuilder, QuicCryptoConfig};
pub use client::connect_quic_client;
pub use error::{CryptoTransportError, Result};
pub use quic_conn::{QuicConnectionEvent, QuicConnectionHandle};
pub use server::{run_quic_server, QuicServerConfig};

/// Trait for async QUIC results that can be awaited
pub trait AsyncQuicResult<T = ()>:
    std::future::Future<Output = Result<T>> + Send + 'static
{
}

// Blanket implementation for any type that meets the bounds
impl<F, T> AsyncQuicResult<T> for F where F: std::future::Future<Output = Result<T>> + Send + 'static
{}
