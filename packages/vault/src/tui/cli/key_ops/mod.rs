//! Key management operations for CLI commands
//!
//! This module provides decomposed key operations for the vault CLI interface,
//! organized by functional responsibility.

pub mod batch_operations;
pub mod generation;
pub mod master_key;
pub mod retrieval;

// Re-export public functions for easy access
pub use batch_operations::{BatchKeyConfig, handle_batch_generate_keys};
pub use generation::handle_generate_key;
pub use master_key::derive_master_key_from_vault;
pub use retrieval::handle_retrieve_key;
