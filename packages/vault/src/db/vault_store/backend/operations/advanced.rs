//! Advanced vault operations

use super::super::super::LocalVaultProvider;
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};

impl LocalVaultProvider {
    /// Store a key-value pair only if the key doesn't already exist
    pub(crate) async fn put_if_absent_impl(
        &self,
        key: String,
        value: VaultValue,
    ) -> VaultResult<bool> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // This is tricky to do atomically without transactions or specific SurrealDB features.
        // A common approach is to try to fetch first, then insert if not found.
        // This has a race condition but might be acceptable depending on requirements.
        // For a more robust solution, SurrealDB 1.x might need a custom function or
        // rely on unique index constraints during the insert.

        // Check existence first (non-atomic)
        let exists = self.get_impl(&key, None).await?;
        if exists.is_some() {
            return Ok(false); // Key already exists
        }

        // Attempt to put the value
        match self.put_impl(key, value, None).await {
            Ok(_) => Ok(true), // Inserted successfully
            Err(VaultError::Provider(e)) if e.contains("unique index") => {
                // If the error is due to the unique index (race condition hit), treat as non-insertion
                Ok(false)
            }
            Err(e) => Err(e), // Propagate other errors
        }
    }

    /// Store multiple key-value pairs
    pub(crate) async fn put_all_impl(&self, entries: Vec<(String, VaultValue)>) -> VaultResult<()> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Note: This is not atomic. If one put fails, others might have succeeded.
        // Consider using SurrealDB transactions if atomicity is required.
        for (key, value) in entries {
            // Need to clone key and value for each iteration if they are consumed by put_impl
            self.put_impl(key.clone(), value.clone(), None).await?;
        }
        Ok(())
    }
}
