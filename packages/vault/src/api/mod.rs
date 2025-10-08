//! Vault API module
//!
//! Contains production-ready vault operations decomposed into logical modules

pub mod compression_optimizer;
pub mod connection_manager;
pub mod error_recovery;
pub mod passphrase_manager;
pub mod stream_buffer;
pub mod stream_manager;
pub mod surrealdb_builder;
pub mod ttl_operations;

// Re-export all the main types and structs
pub use compression_optimizer::{CompressionAlgorithm, CompressionOptimizer};
pub use connection_manager::{ConnectionManager, ConnectionState};
pub use error_recovery::ErrorRecovery;
pub use passphrase_manager::PassphraseChanger;
pub use stream_buffer::StreamBuffer;
pub use stream_manager::StreamIdManager;
pub use surrealdb_builder::{
    SurrealDbBuilder, SurrealDbBuilderWithChunk, SurrealDbBuilderWithHandler,
};
pub use ttl_operations::VaultWithTtl;

// VaultMasterBuilder is now implemented directly in SurrealDbBuilder
pub type VaultMasterBuilder = SurrealDbBuilder<surrealdb_builder::NoConnection>;
