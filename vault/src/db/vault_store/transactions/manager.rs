//! Transaction Manager
//!
//! This module provides the transaction manager for coordinating multiple
//! transactions with lock-free design and cleanup capabilities.

use super::core::VaultTransaction;
use surrealdb::{Connection, Surreal};

/// Lock-free transaction manager with async coordination
pub struct TransactionManager<C: Connection> {
    db: Surreal<C>,
    active_transactions: std::sync::Arc<dashmap::DashMap<u64, std::time::Instant>>,
}

impl<C: Connection> TransactionManager<C> {
    /// Create a new transaction manager
    pub fn new(db: Surreal<C>) -> Self {
        Self {
            db,
            active_transactions: std::sync::Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Begin a new transaction
    pub fn begin_transaction(&self) -> VaultTransaction<C> {
        let tx = VaultTransaction::begin(self.db.clone());
        self.active_transactions
            .insert(tx.id(), std::time::Instant::now());
        tx
    }

    /// Get count of active transactions
    #[inline]
    pub fn active_transaction_count(&self) -> usize {
        self.active_transactions.len()
    }

    /// Clean up completed transactions
    pub fn cleanup_completed_transactions(&self) {
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(300); // 5 minutes
        self.active_transactions
            .retain(|_, &mut created_at| created_at > cutoff);
    }
}

impl<C: Connection> Clone for TransactionManager<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            active_transactions: self.active_transactions.clone(),
        }
    }
}
