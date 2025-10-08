//! QUIC API Implementation
//!
//! This module provides a complete QUIC API implementation following cryypt patterns,
//! with builder patterns, result handlers, and streaming operations.

pub mod client;
pub mod core;
pub mod server;
pub mod streams;

// Re-export public types for easy access
pub use client::{QuicClientBuilder, QuicClientWithConfig, QuicClientWithConfigAndHandler};
pub use core::{Quic, QuicClient, QuicMasterBuilder, QuicServer, quic};
pub use server::{QuicServerBuilder, QuicServerWithConfig, QuicServerWithConfigAndHandler};
pub use streams::{QuicClientWithHandler, QuicRecv, QuicRecvStream, QuicSend, QuicSendWithHandler};
