//! QUIC master builder for polymorphic API

use super::quic_api::QuicServerBuilder;

/// Master builder for QUIC operations following cryypt patterns
/// 
/// Provides a unified entry point for all QUIC functionality including:
/// - Server creation and configuration
/// - Client connections and operations  
/// - Messaging protocol support
/// - File transfer capabilities
/// - TLS/certificate management
#[derive(Debug, Default)]
pub struct QuicMasterBuilder;

impl QuicMasterBuilder {
    /// Create a new QUIC master builder
    pub fn new() -> Self {
        Self
    }

    /// Create a QUIC server builder with comprehensive protocol support
    pub fn server(self) -> QuicServerBuilder {
        QuicServerBuilder::new()
    }

    /// Create a messaging server builder with enterprise-grade TLS
    pub fn messaging(self) -> crate::protocols::messaging::MessagingServerBuilder {
        crate::protocols::messaging::MessagingServerBuilder::default()
    }

    /// Create a file transfer server builder
    pub fn file_transfer(self) -> crate::protocols::file_transfer::sender::FileTransferServerBuilder {
        crate::protocols::file_transfer::sender::FileTransferServerBuilder::default()
    }

    /// Access TLS builder API for certificate operations
    pub fn tls(self) -> crate::tls::builder::Tls {
        crate::tls::builder::Tls
    }

    /// Create a development-optimized messaging server
    pub fn development_messaging(self) -> crate::protocols::messaging::MessagingServerBuilder {
        crate::protocols::messaging::MessagingServerBuilder::development()
    }

    /// Create a production-optimized messaging server
    pub fn production_messaging(self) -> crate::protocols::messaging::MessagingServerBuilder {
        crate::protocols::messaging::MessagingServerBuilder::production()
    }

    /// Create a low-latency messaging server
    pub fn low_latency_messaging(self) -> crate::protocols::messaging::MessagingServerBuilder {
        crate::protocols::messaging::MessagingServerBuilder::low_latency()
    }

    /// Create a high-throughput messaging server
    pub fn high_throughput_messaging(self) -> crate::protocols::messaging::MessagingServerBuilder {
        crate::protocols::messaging::MessagingServerBuilder::high_throughput()
    }
}