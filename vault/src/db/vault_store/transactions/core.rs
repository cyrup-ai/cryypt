//! Core Transaction Types and Operations
//!
//! This module provides the fundamental transaction types, operations, and
//! the main VaultTransaction struct with its basic operations.

use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use surrealdb::{Connection, Surreal};

/// Transaction ID generator using atomic counter for zero allocation
static TRANSACTION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate unique transaction ID without allocation
#[inline]
pub fn next_transaction_id() -> u64 {
    TRANSACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Transaction operation types with zero-copy design
#[derive(Debug, Clone)]
pub enum TransactionOperation {
    Put { key: String, value: VaultValue },
    Delete { key: String },
    PutIfAbsent { key: String, value: VaultValue },
    Update { key: String, value: VaultValue },
    Increment { key: String, amount: i64 },
}

/// Lock-free transaction handle with async operations
pub struct VaultTransaction<C: Connection> {
    pub(super) id: u64,
    pub(super) operations: VecDeque<TransactionOperation>,
    pub(super) db: Surreal<C>,
    pub(super) committed: bool,
    pub(super) rolled_back: bool,
}

impl<C: Connection> VaultTransaction<C> {
    /// Begin a new transaction with zero allocation
    #[inline]
    pub fn begin(db: Surreal<C>) -> Self {
        Self {
            id: next_transaction_id(),
            operations: VecDeque::with_capacity(16), // Pre-allocate for common case
            db,
            committed: false,
            rolled_back: false,
        }
    }

    /// Add a put operation to the transaction
    #[inline]
    pub fn put(&mut self, key: String, value: VaultValue) -> VaultResult<()> {
        if self.committed || self.rolled_back {
            return Err(VaultError::transaction_closed(self.id.to_string()));
        }

        self.operations
            .push_back(TransactionOperation::Put { key, value });
        Ok(())
    }

    /// Add a delete operation to the transaction
    #[inline]
    pub fn delete(&mut self, key: String) -> VaultResult<()> {
        if self.committed || self.rolled_back {
            return Err(VaultError::transaction_closed(self.id.to_string()));
        }

        self.operations
            .push_back(TransactionOperation::Delete { key });
        Ok(())
    }

    /// Add a put-if-absent operation to the transaction
    #[inline]
    pub fn put_if_absent(&mut self, key: String, value: VaultValue) -> VaultResult<()> {
        if self.committed || self.rolled_back {
            return Err(VaultError::transaction_closed(self.id.to_string()));
        }

        self.operations
            .push_back(TransactionOperation::PutIfAbsent { key, value });
        Ok(())
    }

    /// Add an update operation to the transaction
    #[inline]
    pub fn update(&mut self, key: String, value: VaultValue) -> VaultResult<()> {
        if self.committed || self.rolled_back {
            return Err(VaultError::transaction_closed(self.id.to_string()));
        }

        self.operations
            .push_back(TransactionOperation::Update { key, value });
        Ok(())
    }

    /// Add an increment operation to the transaction
    #[inline]
    pub fn increment(&mut self, key: String, amount: i64) -> VaultResult<()> {
        if self.committed || self.rolled_back {
            return Err(VaultError::transaction_closed(self.id.to_string()));
        }

        self.operations
            .push_back(TransactionOperation::Increment { key, amount });
        Ok(())
    }

    /// Get transaction ID
    #[inline]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Check if transaction is committed
    #[inline]
    pub fn is_committed(&self) -> bool {
        self.committed
    }

    /// Check if transaction is rolled back
    #[inline]
    pub fn is_rolled_back(&self) -> bool {
        self.rolled_back
    }

    /// Get number of operations in transaction
    #[inline]
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }
}
