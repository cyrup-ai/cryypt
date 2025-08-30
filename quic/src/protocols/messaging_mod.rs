//! Modular QUIC messaging protocol implementation
//!
//! This module provides a high-performance, lock-free messaging protocol over QUIC
//! with reliable delivery, topic-based routing, and advanced distribution strategies.

pub mod types;
pub mod builders;
pub mod server;
pub mod message_processing;
pub mod protocol_core;

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
    derive_connection_key, compress_payload_stream,
    decompress_payload_stream, encrypt_payload_stream, decrypt_payload_stream,
    process_payload_forward, process_payload_reverse,
};

pub use protocol_core::{
    PerformanceMonitor, ConnectionHealthChecker, FlowController,
    RetryManager, MessageValidator, MetricsCollector,
    QUIC_PROTOCOL_VERSION, APPLICATION_PROTOCOL, CONNECTION_TIMEOUT,
    generate_connection_id, create_quic_config, create_client_quic_config,
};