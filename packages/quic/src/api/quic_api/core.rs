//! Core QUIC API Types and Entry Points
//!
//! This module provides the main entry points and core types for the QUIC API,
//! following the cryypt patterns for builder-based configuration.

use crate::quic_conn::QuicConnectionHandle;
use std::net::SocketAddr;

/// Main entry point - following cryypt pattern
pub struct Quic;

impl Quic {
    /// Create a QUIC server builder
    #[must_use]
    pub fn server() -> super::server::QuicServerBuilder {
        super::server::QuicServerBuilder::new()
    }

    /// Create a QUIC client builder
    #[must_use]
    pub fn client() -> super::client::QuicClientBuilder {
        super::client::QuicClientBuilder::new()
    }

    /// Create a file transfer protocol instance
    #[must_use]
    pub fn file_transfer(
        addr: SocketAddr,
    ) -> crate::quic::file_transfer::types::FileTransferProtocol {
        crate::quic::file_transfer::types::FileTransferProtocol::new(addr)
    }
}

/// Direct entry point for QUIC functionality
#[must_use]
pub fn quic() -> Quic {
    Quic
}

/// QUIC master builder for dual API entry points
pub struct QuicMasterBuilder;

impl QuicMasterBuilder {
    /// Create a QUIC server builder
    #[must_use]
    pub fn server(self) -> super::server::QuicServerBuilder {
        super::server::QuicServerBuilder::new()
    }

    /// Create a QUIC client builder
    #[must_use]
    pub fn client(self) -> super::client::QuicClientBuilder {
        super::client::QuicClientBuilder::new()
    }

    /// Create a file transfer protocol instance
    #[must_use]
    pub fn file_transfer(
        self,
        addr: SocketAddr,
    ) -> crate::quic::file_transfer::types::FileTransferProtocol {
        crate::quic::file_transfer::types::FileTransferProtocol::new(addr)
    }
}

/// QUIC server instance
pub struct QuicServer {
    pub(crate) addr: SocketAddr,
    pub(crate) bound: bool,
    pub(crate) _handle:
        Option<tokio::task::JoinHandle<Result<(), crate::error::CryptoTransportError>>>,
}

impl Default for QuicServer {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicServer {
    /// Create unbound server (for error cases)
    #[must_use]
    pub fn new() -> Self {
        Self {
            addr: "0.0.0.0:0".parse().unwrap_or_else(|_| {
                use std::net::{IpAddr, Ipv4Addr, SocketAddr};
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            }),
            bound: false,
            _handle: None,
        }
    }

    /// Get the server's bound address
    #[must_use]
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    /// Check if the server is bound
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.bound
    }
}

/// QUIC client instance
pub struct QuicClient {
    pub(crate) addr: SocketAddr,
    pub(crate) connected: bool,
    pub(crate) handle: Option<QuicConnectionHandle>,
}

impl Default for QuicClient {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicClient {
    /// Create unconnected client (for error cases)
    #[must_use]
    pub fn new() -> Self {
        Self {
            addr: "0.0.0.0:0".parse().unwrap_or_else(|_| {
                use std::net::{IpAddr, Ipv4Addr, SocketAddr};
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            }),
            connected: false,
            handle: None,
        }
    }

    /// Get the client's remote address
    #[must_use]
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    /// Check if the client is connected
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}
