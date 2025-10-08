//! TTL-aware vault operations with production-ready implementation

use crate::core::VaultValue;
use crate::db::vault_store::LocalVaultProvider;
use crate::error::VaultResult;

/// TTL-aware vault operations with production-ready implementation
pub struct VaultWithTtl<'v> {
    vault: &'v LocalVaultProvider,
    key: String,
    ttl_seconds: Option<u64>,
}

impl<'v> VaultWithTtl<'v> {
    /// Create new TTL-aware vault operation
    pub fn new(vault: &'v LocalVaultProvider, key: String, ttl_seconds: Option<u64>) -> Self {
        Self {
            vault,
            key,
            ttl_seconds,
        }
    }

    /// Set value with TTL - production implementation with SurrealDB TTL support
    pub async fn set<V: AsRef<str>>(self, value: V) -> VaultResult<()> {
        let vault_value = VaultValue::from_string(value.as_ref().to_string());
        match self.ttl_seconds {
            Some(ttl) => {
                // Use SurrealDB's native TTL support for production implementation
                let expiry = std::time::SystemTime::now() + std::time::Duration::from_secs(ttl);
                self.vault
                    .put_with_expiry(&self.key, &vault_value, expiry)
                    .await
            }
            None => {
                // Regular set operation without TTL
                self.vault.put(&self.key, &vault_value).await.map(|_| ())
            }
        }
    }

    /// Get value with TTL awareness
    pub async fn get(self) -> VaultResult<Option<String>> {
        // Check if key has expired and clean up if necessary
        match self.vault.get_with_expiry_check(&self.key).await? {
            Some(value) => {
                // TTL check performed by get_with_expiry_check() - expired entries return None
                match value.expose_as_str() {
                    Ok(s) => Ok(Some(s.to_string())),
                    Err(_) => Ok(Some(format!("{:?}", value))),
                }
            }
            None => Ok(None),
        }
    }

    /// Update TTL for existing key
    pub async fn update_ttl(self, new_ttl_seconds: u64) -> VaultResult<()> {
        let new_expiry =
            std::time::SystemTime::now() + std::time::Duration::from_secs(new_ttl_seconds);
        self.vault.update_expiry(&self.key, new_expiry).await
    }

    /// Remove TTL from key (make it permanent)
    pub async fn remove_ttl(self) -> VaultResult<()> {
        self.vault.remove_expiry(&self.key).await
    }
}
