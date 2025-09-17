//! High-level messaging protocol API

use super::client_builder::MessagingClientBuilder;
use super::server_builder::MessagingServerBuilder;

/// High-level messaging protocol builder
pub struct QuicMessaging;

impl QuicMessaging {
    /// Create a messaging server
    pub fn server() -> MessagingServerBuilder {
        MessagingServerBuilder::default()
    }

    /// Connect to a messaging server
    pub fn connect(server_addr: &str) -> MessagingClientBuilder {
        MessagingClientBuilder::new(server_addr.to_string())
    }

    /// Convenience: Create a development messaging server with self-signed certificates
    pub fn development_server() -> MessagingServerBuilder {
        MessagingServerBuilder::development()
    }

    /// Convenience: Create a production messaging server with file-based certificates
    pub fn production_server() -> MessagingServerBuilder {
        MessagingServerBuilder::production()
    }

    /// Convenience: Create a low-latency messaging server optimized for speed
    pub fn low_latency_server() -> MessagingServerBuilder {
        MessagingServerBuilder::low_latency()
    }

    /// Convenience: Create a high-throughput messaging server optimized for large payloads
    pub fn high_throughput_server() -> MessagingServerBuilder {
        MessagingServerBuilder::high_throughput()
    }

    /// Convenience: Create a testing messaging server with temporary certificates
    pub fn testing_server() -> MessagingServerBuilder {
        MessagingServerBuilder::testing()
    }
}
