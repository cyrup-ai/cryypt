//! QUIC transport module with decomposed implementations
//!
//! Provides a fluent, type-safe API for establishing persistent QUIC connections
//! and multiplexing different application protocols over the same connection.


// Import individual implementations
mod client;
mod config;
mod connection;
mod server;
mod stream;

// Re-export configuration types
pub use config::{Auth, Protocol, Transport};

// Re-export client types
pub use client::ClientBuilder;

// Re-export server types
pub use server::{ServerBuilder, ServerListenerBuilder};

// Re-export connection types
pub use connection::QuicConnection;

// Re-export stream types
pub use stream::{
    FileProgress, FileTransferBuilder, FileTransferProtocol, FileTransferResult,
    MessageBuilder, MessagingProtocol, QuicStream, QuicStreamDispatcher,
    RpcBuilder, RpcProtocol,
};

/// Main entry point for QUIC transport
pub struct Quic;

impl Quic {
    /// Create a QUIC client with specified transport
    pub fn client(transport: Transport) -> ClientBuilder {
        ClientBuilder::new(transport)
    }

    /// Create a QUIC server with specified transport
    pub fn server(transport: Transport) -> ServerBuilder {
        ServerBuilder::new(transport)
    }
}