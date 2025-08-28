//! Core QUIC API entry points and main structures

/// Main entry point - following cryypt pattern
pub struct Quic;

impl Quic {
    /// Create a QUIC server builder
    pub fn server() -> super::server::QuicServerBuilder {
        super::server::QuicServerBuilder::new()
    }

    /// Create a QUIC client builder
    pub fn client() -> super::client::QuicClientBuilder {
        super::client::QuicClientBuilder::new()
    }
}

/// Direct entry point for QUIC functionality
pub fn quic() -> Quic {
    Quic
}

/// QUIC master builder for dual API entry points
pub struct QuicMasterBuilder;

impl QuicMasterBuilder {
    /// Create a QUIC server builder
    pub fn server(self) -> super::server::QuicServerBuilder {
        super::server::QuicServerBuilder::new()
    }

    /// Create a QUIC client builder
    pub fn client(self) -> super::client::QuicClientBuilder {
        super::client::QuicClientBuilder::new()
    }
}
