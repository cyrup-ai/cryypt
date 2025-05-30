//! QUIC encrypted transport protocol implementation
//!
//! This module provides encrypted transport using QUIC protocol with quantum-resistant
//! key exchange and post-quantum TLS configurations.
//!
//! ## High-Level Protocol Builders (Recommended)
//!
//! For most users, start with the high-level protocol builders:
//! - [`QuicFileTransfer`] - Complete file transfer with resume, checksums, compression
//! - [`QuicMessaging`] - Real-time messaging with delivery guarantees
//! - [`QuicRpc`] - Request/response patterns with timeouts and retries
//!
//! ## Low-Level QUIC Primitives (Advanced)
//!
//! For advanced users who need direct QUIC control:
//! - [`QuicCryptoBuilder`] - Low-level QUIC configuration
//! - [`connect_quic_client`], [`run_quic_server`] - Raw connection management

// High-level protocol builders (primary public API)
pub mod protocols;

// Low-level QUIC primitives (internal implementation)
mod builder;
mod client;
pub mod error;
mod keys;
mod quic_conn;
mod server;

// Export high-level protocol builders (what users should use)
pub use protocols::{
    QuicFileTransfer, FileTransferProgress, TransferResult,
    QuicMessaging, MessageDelivery,
    QuicRpc, RpcCall, RpcResponse,
};

// Export low-level primitives for advanced users
pub use builder::{QuicCryptoBuilder, QuicCryptoConfig};
pub use client::connect_quic_client;
pub use error::{CryptoTransportError, Result};
pub use quic_conn::{QuicConnectionEvent, QuicConnectionHandle};
pub use server::{QuicServerConfig, run_quic_server};

/// Trait for async QUIC results that can be awaited
pub trait AsyncQuicResult<T = ()>: std::future::Future<Output = Result<T>> + Send + 'static {}

// Blanket implementation for any type that meets the bounds  
impl<F, T> AsyncQuicResult<T> for F where F: std::future::Future<Output = Result<T>> + Send + 'static {}
