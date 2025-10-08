//! Cleanup operations for vault entries
//!
//! This module handles maintenance operations including:
//! - Expired entry cleanup and removal
//! - Background TTL cleanup task scheduling
//! - Statistics gathering for cleanup operations
//! - Automated maintenance with proper error handling

use super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use chrono::Utc;

impl LocalVaultProvider {
    /// Clean up expired entries from the vault
    ///
    /// Removes all entries where the expires_at timestamp is less than or equal
    /// to the current time. Returns the count of deleted entries.
    ///
    /// Uses SurrealDB DELETE...RETURN to get accurate deletion counts.
    pub async fn cleanup_expired_entries(&self) -> VaultResult<u64> {
        let db = self.dao.db();
        let now = Utc::now();

        log::debug!("Starting cleanup of expired vault entries at {}", now);

        // Delete expired entries and return them for accurate counting
        let query = "DELETE FROM vault_entries WHERE expires_at IS NOT NULL AND expires_at <= $now RETURN *";

        let mut result = db
            .query(query)
            .bind(("now", now))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to cleanup expired entries: {e}")))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed during cleanup: {e}")))?;

        // Count how many entries were deleted using returned records
        let deleted_entries: Vec<serde_json::Value> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to get cleanup results: {e}")))?;

        let deleted_count = deleted_entries.len() as u64;

        // Log cleanup results appropriately
        if deleted_count > 0 {
            log::info!(
                "TTL cleanup: removed {} expired vault entries",
                deleted_count
            );
        } else {
            log::debug!("TTL cleanup: no expired entries found");
        }

        Ok(deleted_count)
    }

    /// Start periodic TTL cleanup task
    ///
    /// Runs a background task that periodically calls cleanup_expired_entries()
    /// at the specified interval. This function runs indefinitely and should
    /// be spawned as a background task.
    ///
    /// The cleanup continues running even if individual cleanup operations fail,
    /// ensuring robust automated maintenance.
    pub async fn start_ttl_cleanup_task(&self, cleanup_interval_seconds: u64) {
        use tokio::time::{Duration, interval};

        let cleanup_interval = Duration::from_secs(cleanup_interval_seconds);
        let mut cleanup_timer = interval(cleanup_interval);

        log::info!(
            "Starting TTL cleanup task with {} second intervals",
            cleanup_interval_seconds
        );

        // Run cleanup loop indefinitely
        loop {
            cleanup_timer.tick().await;

            // Attempt cleanup, but continue running even on errors
            match self.cleanup_expired_entries().await {
                Ok(deleted_count) => {
                    if deleted_count > 0 {
                        log::debug!("TTL cleanup completed: {} entries removed", deleted_count);
                    }
                }
                Err(e) => {
                    log::error!("TTL cleanup failed: {}", e);
                    // Continue running despite errors - don't break the loop
                }
            }
        }
    }

    /// Get statistics about expired entries without deleting them
    ///
    /// Returns the count of entries that are currently expired but not yet
    /// cleaned up. Useful for monitoring and debugging TTL operations.
    ///
    /// Uses SurrealDB COUNT() with GROUP ALL for accurate statistics.
    pub async fn get_expired_entries_stats(&self) -> VaultResult<u64> {
        let db = self.dao.db();
        let now = Utc::now();

        // Count expired entries using SurrealDB aggregation
        let query = "SELECT COUNT() AS count FROM vault_entries WHERE expires_at IS NOT NULL AND expires_at <= $now GROUP ALL";

        #[derive(serde::Deserialize)]
        struct CountResult {
            count: u64,
        }

        let mut result = db
            .query(query)
            .bind(("now", now))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to count expired entries: {e}")))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?;

        let count_result: Option<CountResult> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to get count results: {e}")))?;

        // Return count or 0 if no results (safe unwrap alternative)
        Ok(count_result.map(|r| r.count).unwrap_or(0))
    }
}
