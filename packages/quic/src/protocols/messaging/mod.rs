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
mod types;
mod builders;
mod server;
mod message_processing;
mod protocol_core;

// Re-export main types and builders for convenience
pub use types::{
    CompressionAlgorithm, EncryptionAlgorithm, MessageEnvelope, MessageDelivery,
    DistributionStrategy, MessagePriority, CompressionMetadata, EncryptionMetadata,
    PriorityMessageQueue, LoadBalancer, ConnectionState,
};

pub use builders::{QuicMessaging, MessagingServerBuilder, MessagingClientBuilder};

pub use server::{
    MessagingServer, MessagingServerConfig, TopicSubscriptions, 
    ConnectionHealth, ServerConnectionState
};

pub use message_processing::{
    calculate_checksum, calculate_checksum_64, calculate_authenticated_checksum, verify_authenticated_checksum,
    derive_connection_key, compress_payload_stream, decompress_payload_stream,
    encrypt_payload_stream, decrypt_payload_stream,
    process_payload_forward, process_payload_reverse,
};

pub use protocol_core::{
    PerformanceMonitor, ConnectionHealthChecker, FlowController,
    RetryManager, MessageValidator, MetricsCollector,
    QUIC_PROTOCOL_VERSION, APPLICATION_PROTOCOL, CONNECTION_TIMEOUT,
    generate_connection_id, create_quic_config, create_client_quic_config,
};