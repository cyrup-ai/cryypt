//! Transaction Result Types and Utilities
//!
//! This module provides result types for transaction operations and
//! the overall transaction result with timing and success information.

/// Result of a single operation within a transaction
#[derive(Debug, Clone)]
pub enum OperationResult {
    Put { key: String, success: bool },
    Delete { key: String, existed: bool },
    PutIfAbsent { key: String, inserted: bool },
    Update { key: String, updated: bool },
    Increment { key: String, new_value: i64 },
}

/// Result of a committed transaction
#[derive(Debug)]
pub struct TransactionResult {
    transaction_id: u64,
    operations: Vec<OperationResult>,
    committed_at: std::time::Instant,
}

impl TransactionResult {
    /// Create new transaction result
    pub(super) fn new(transaction_id: u64, operations: Vec<OperationResult>) -> Self {
        Self {
            transaction_id,
            operations,
            committed_at: std::time::Instant::now(),
        }
    }

    /// Create empty transaction result
    pub(super) fn empty(transaction_id: u64) -> Self {
        Self {
            transaction_id,
            operations: Vec::new(),
            committed_at: std::time::Instant::now(),
        }
    }

    /// Get transaction ID
    #[inline]
    pub fn transaction_id(&self) -> u64 {
        self.transaction_id
    }

    /// Get operation results
    #[inline]
    pub fn operations(&self) -> &[OperationResult] {
        &self.operations
    }

    /// Get commit timestamp
    #[inline]
    pub fn committed_at(&self) -> std::time::Instant {
        self.committed_at
    }

    /// Check if transaction was successful
    #[inline]
    pub fn is_successful(&self) -> bool {
        !self.operations.is_empty()
    }
}
