//! QUIC entry points following cryypt dual API pattern

// Re-export from the main API implementation
pub use crate::api::quic_api::{Quic, quic};

// Additional compatibility exports if needed
pub use crate::api::quic_api::{QuicClient, QuicServer};

// Export config module
pub mod config;

// Export server module for certificate functions
pub mod server;

// Export stream dispatcher module
pub mod stream_dispatcher;

// Export protocol modules
pub mod connection;
pub mod file_transfer;
pub mod messaging;
pub mod rpc;
