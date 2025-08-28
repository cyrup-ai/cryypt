//! Production-ready Transaction Handling for Vault Operations
//!
//! This module provides ACID transactions using SurrealDB with zero allocation
//! and lock-free design, decomposed into logical components.

pub mod core;
pub mod execution;
pub mod manager;
pub mod results;

// Re-export public types
pub use core::{TransactionOperation, VaultTransaction, next_transaction_id};
pub use manager::TransactionManager;
pub use results::{OperationResult, TransactionResult};
