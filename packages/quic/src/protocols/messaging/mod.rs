//! High-level messaging protocol over QUIC
//!
//! Provides reliable, ordered message delivery with acknowledgments,
//! delivery guarantees, and automatic retry logic.
//!
//! This module has been decomposed into discrete separation of concerns submodules:
//! - `types`: Core data structures, enums, and type definitions
//! - `builders`: Builder patterns for server and client construction
//! - `server`: Server implementation with connection management
//! - `message_processing`: Compression, encryption, and streaming pipelines
//! - `protocol_core`: Core protocol utilities and constants
//!
//! Each submodule is kept under 400 lines for maintainability and follows
//! the single responsibility principle.

// Import the modular submodules
mod builders;
mod message_processing;
mod protocol_core;
mod server;
mod types;

// Re-export main types and builders for convenience
pub use types::{
    CompressionAlgorithm, CompressionMetadata, ConnectionState, DistributionStrategy,
    EncryptionAlgorithm, EncryptionMetadata, LoadBalancer, MessageDelivery, MessageEnvelope,
    MessagePriority, PriorityMessageQueue,
};

pub use builders::{MessagingClientBuilder, MessagingServerBuilder, QuicMessaging};

pub use server::{
    ConnectionHealth, MessagingServer, MessagingServerConfig, ServerConnectionState,
    TopicSubscriptions,
};

pub use message_processing::{
    calculate_authenticated_checksum, calculate_checksum, calculate_checksum_64,
    compress_payload_stream, decompress_payload_stream, decrypt_payload_stream,
    derive_connection_key, encrypt_payload_stream, process_payload_forward,
    process_payload_reverse, verify_authenticated_checksum,
};

pub use protocol_core::{
    APPLICATION_PROTOCOL, CONNECTION_TIMEOUT, ConnectionHealthChecker, FlowController,
    MessageValidator, MetricsCollector, PerformanceMonitor, QUIC_PROTOCOL_VERSION, RetryManager,
    create_client_quic_config, create_quic_config, generate_connection_id,
};
