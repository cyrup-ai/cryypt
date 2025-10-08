//! QUIC Master Builder
//!
//! Master builder for QUIC operations (server, client)

/// Master builder for QUIC operations
#[cfg(feature = "quic")]
pub struct QuicMasterBuilder;

#[cfg(feature = "quic")]
impl QuicMasterBuilder {
    /// Create a QUIC server - README.md pattern
    #[must_use]
    pub fn server(self) -> cryypt_quic::api::QuicServerBuilder {
        cryypt_quic::api::QuicServerBuilder::new()
    }

    /// Create a QUIC client - README.md pattern
    #[must_use]
    pub fn client(self) -> cryypt_quic::api::QuicClientBuilder {
        cryypt_quic::api::QuicClientBuilder::new()
    }
}
