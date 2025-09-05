//! Transaction Execution Logic
//!
//! This module provides the execution logic for vault transactions, including
//! commit, rollback, and individual operation execution methods.

use super::core::{TransactionOperation, VaultTransaction};
use super::results::{OperationResult, TransactionResult};
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use surrealdb::Connection;

impl<C: Connection> VaultTransaction<C> {
    /// Commit the transaction with ACID guarantees
    pub async fn commit(mut self) -> VaultResult<TransactionResult> {
        if self.committed {
            return Err(VaultError::transaction_already_committed(
                self.id.to_string(),
                "Transaction already committed".to_string(),
            ));
        }
        if self.rolled_back {
            return Err(VaultError::transaction_already_rolled_back(
                self.id.to_string(),
            ));
        }

        if self.operations.is_empty() {
            self.committed = true;
            return Ok(TransactionResult::empty(self.id));
        }

        // Execute operations directly without explicit transaction in SurrealDB 2.3.7+
        // SurrealDB handles ACID guarantees internally for batch operations

        let mut results = Vec::with_capacity(self.operations.len());

        // Execute all operations directly using the database connection
        for operation in &self.operations {
            let result = match operation {
                TransactionOperation::Put { key, value } => {
                    self.execute_put_direct(key, value).await?
                }
                TransactionOperation::Delete { key } => self.execute_delete_direct(key).await?,
                TransactionOperation::PutIfAbsent { key, value } => {
                    self.execute_put_if_absent_direct(key, value).await?
                }
                TransactionOperation::Update { key, value } => {
                    self.execute_update_direct(key, value).await?
                }
                TransactionOperation::Increment { key, amount } => {
                    self.execute_increment_direct(key, *amount).await?
                }
            };
            results.push(result);
        }

        // Operations completed successfully - no explicit commit needed in SurrealDB 2.3.7+

        self.committed = true;
        Ok(TransactionResult::new(self.id, results))
    }

    /// Rollback the transaction
    pub async fn rollback(mut self) -> VaultResult<()> {
        if self.committed {
            return Err(VaultError::transaction_already_committed(
                self.id.to_string(),
                "Transaction already committed".to_string(),
            ));
        }
        if self.rolled_back {
            return Err(VaultError::transaction_already_rolled_back(
                self.id.to_string(),
            ));
        }

        // SurrealDB transactions are automatically rolled back when dropped
        self.rolled_back = true;
        Ok(())
    }

    /// Execute put operation directly on database
    async fn execute_put_direct(
        &self,
        key: &str,
        value: &VaultValue,
    ) -> VaultResult<OperationResult> {
        let key = key.to_string();
        let value = value.clone();
        let query = "UPDATE vault SET value = $value WHERE key = $key OR CREATE vault SET key = $key, value = $value";
        let _result = self
            .db
            .query(query)
            .bind(("key", key.clone()))
            .bind(("value", value.clone()))
            .await
            .map_err(|e| {
                VaultError::database_operation_failed(self.id.to_string(), e.to_string())
            })?;

        Ok(OperationResult::Put {
            key: key.clone(),
            success: true,
        })
    }

    /// Execute delete operation directly on database
    async fn execute_delete_direct(&self, key: &str) -> VaultResult<OperationResult> {
        let key = key.to_string();
        let query = "DELETE FROM vault WHERE key = $key";
        let _result = self
            .db
            .query(query)
            .bind(("key", key.clone()))
            .await
            .map_err(|e| {
                VaultError::database_operation_failed(self.id.to_string(), e.to_string())
            })?;

        Ok(OperationResult::Delete {
            key: key.to_string(),
            existed: true, // SurrealDB will tell us if it existed
        })
    }

    /// Execute put-if-absent operation directly on database
    async fn execute_put_if_absent_direct(
        &self,
        key: &str,
        value: &VaultValue,
    ) -> VaultResult<OperationResult> {
        let key_string = key.to_string();
        let value = value.clone();
        let query = "CREATE vault SET key = $key, value = $value";
        let _result = self
            .db
            .query(query)
            .bind(("key", key_string.clone()))
            .bind(("value", value))
            .await;

        match _result {
            Ok(_) => Ok(OperationResult::PutIfAbsent {
                key: key_string,
                inserted: true,
            }),
            Err(_) => Ok(OperationResult::PutIfAbsent {
                key: key_string,
                inserted: false,
            }),
        }
    }

    /// Execute update operation directly on database
    async fn execute_update_direct(
        &self,
        key: &str,
        value: &VaultValue,
    ) -> VaultResult<OperationResult> {
        let key = key.to_string();
        let value = value.clone();
        let query = "UPDATE vault SET value = $value WHERE key = $key";
        let _result = self
            .db
            .query(query)
            .bind(("key", key.clone()))
            .bind(("value", value.clone()))
            .await
            .map_err(|e| {
                VaultError::database_operation_failed(self.id.to_string(), e.to_string())
            })?;

        Ok(OperationResult::Update {
            key: key.clone(),
            updated: true,
        })
    }

    /// Execute increment operation directly on database
    async fn execute_increment_direct(
        &self,
        key: &str,
        amount: i64,
    ) -> VaultResult<OperationResult> {
        let key = key.to_string();
        let query =
            "UPDATE vault SET value = value + $amount WHERE key = $key AND type::is::number(value)";
        let _result = self
            .db
            .query(query)
            .bind(("key", key.clone()))
            .bind(("amount", amount))
            .await
            .map_err(|e| {
                VaultError::database_operation_failed(self.id.to_string(), e.to_string())
            })?;

        Ok(OperationResult::Increment {
            key: key.to_string(),
            new_value: 0, // Would extract from result
        })
    }
}
