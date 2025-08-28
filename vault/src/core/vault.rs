//! Main Vault implementation
//!
//! Contains the core Vault struct and its operational methods.

use super::types::VaultValue;
use crate::error::{VaultError, VaultResult};
use crate::operation::{
    Passphrase, VaultBoolRequest, VaultChangePassphraseRequest, VaultFindRequest, VaultGetRequest,
    VaultListRequest, VaultOperation, VaultPutAllRequest, VaultUnitRequest,
};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

/// Main Vault struct for managing encrypted storage operations
pub struct Vault {
    providers: Arc<Mutex<Vec<Arc<dyn VaultOperation>>>>,
}

impl Vault {
    /// Creates a new, empty Vault without any providers
    pub fn new() -> Self {
        Self {
            providers: Arc::new(Mutex::new(vec![])),
        }
    }

    /// Creates a new Vault with a LocalVaultProvider using FortressEncrypt (defense-in-depth) encryption (async version)
    pub async fn with_fortress_encryption_async(config: crate::config::VaultConfig) -> VaultResult<Self> {
        let vault = Self::new();
        let provider = crate::LocalVaultProvider::new(config).await?;
        vault.register_operation(provider).await;
        Ok(vault)
    }

    /// Creates a new Vault with a LocalVaultProvider using FortressEncrypt (sync wrapper)
    pub fn with_fortress_encryption(config: crate::config::VaultConfig) -> VaultResult<Self> {
        let (tx, rx) = oneshot::channel();
        
        tokio::spawn(async move {
            let result = Self::with_fortress_encryption_async(config).await;
            let _ = tx.send(result);
        });

        rx.blocking_recv()
            .map_err(|_| VaultError::Other("Provider registration failed".to_string()))?
    }

    pub async fn register_operation(&self, provider: impl VaultOperation) {
        let mut guard = self.providers.lock().await;
        guard.push(Arc::new(provider));
    }

    pub async fn unlock(&self, passphrase: &str) -> VaultResult<()> {
        let secure_passphrase = Passphrase::from(passphrase.to_string());
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            provider.unlock(&secure_passphrase).await
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    pub async fn lock(&self) -> VaultResult<()> {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            provider.lock().await
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    pub async fn is_locked(&self) -> bool {
        let providers = self.providers.lock().await;
        providers
            .first()
            .is_none_or(|provider| provider.is_locked())
    }

    /// Determines if this vault is using fortress-grade (defense-in-depth) encryption
    pub async fn has_fortress_encryption(&self) -> bool {
        let providers = self.providers.lock().await;
        providers
            .first()
            .is_some_and(|provider| provider.supports_defense_in_depth())
    }

    /// Gets the encryption type being used by this vault
    pub async fn encryption_type(&self) -> Option<String> {
        let providers = self.providers.lock().await;
        providers
            .first()
            .map(|provider| provider.encryption_type().to_string())
    }

    pub async fn put(&self, key: &str, value: &str) -> VaultResult<VaultUnitRequest> {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            // Convert &str to VaultValue using from_string
            Ok(provider.put(key, VaultValue::from_string(value.to_string())))
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    pub async fn put_with_metadata(
        &self,
        key: &str,
        value: &str,
        metadata: HashMap<String, String>,
    ) -> VaultResult<VaultUnitRequest> {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            // Convert &str to VaultValue using from_string with metadata
            let vault_value = VaultValue::from_string(value.to_string()).with_metadata(metadata);
            Ok(provider.put(key, vault_value))
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    /// Store a value with TTL (Time To Live) expiration
    pub async fn put_with_ttl(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> VaultResult<VaultUnitRequest> {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            // Check if provider supports TTL
            if !provider.supports_ttl() {
                // Fallback to regular put operation with warning log
                log::warn!(
                    "Provider does not support TTL, storing without expiration: key={}",
                    key
                );
                return Ok(provider.put(key, VaultValue::from_string(value.to_string())));
            }

            // Create VaultValue with TTL metadata for TTL-capable providers
            let mut metadata = HashMap::new();
            metadata.insert("ttl_seconds".to_string(), ttl_seconds.to_string());
            let vault_value = VaultValue::from_string(value.to_string()).with_metadata(metadata);
            Ok(provider.put(key, vault_value))
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    pub async fn put_if_absent(&self, key: &str, value: &str) -> VaultResult<VaultBoolRequest> {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            // Convert &str to VaultValue using from_string
            Ok(provider.put_if_absent(key, VaultValue::from_string(value.to_string())))
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    pub async fn put_all(&self, entries: &[(String, String)]) -> VaultResult<VaultPutAllRequest> {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            // Convert Vec<(String, String)> to Vec<(String, VaultValue)>
            let vault_entries = entries
                .iter()
                .map(|(k, v)| (k.clone(), VaultValue::from_string(v.clone())))
                .collect();
            Ok(provider.put_all(vault_entries))
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    pub async fn get(&self, key: &str) -> VaultResult<VaultGetRequest> {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            Ok(provider.get(key))
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    pub async fn delete(&self, key: &str) -> VaultResult<VaultUnitRequest> {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            Ok(provider.delete(key))
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    pub async fn find(&self, pattern: &str) -> VaultResult<VaultFindRequest> {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            Ok(provider.find(pattern))
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    pub async fn list(&self) -> VaultResult<VaultListRequest> {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            // Call provider list with None to list all under the provider's prefix
            Ok(provider.list(None))
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    pub async fn change_passphrase(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> VaultResult<VaultChangePassphraseRequest> {
        let secure_old_passphrase = Passphrase::from(old_passphrase.to_string());
        let secure_new_passphrase = Passphrase::from(new_passphrase.to_string());

        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            Ok(provider.change_passphrase(&secure_old_passphrase, &secure_new_passphrase))
        } else {
            Err(VaultError::Configuration(
                "No provider configured".to_string(),
            ))
        }
    }

    /// Check if this is a new vault (no passphrase hash stored)
    pub async fn is_new_vault(&self) -> bool {
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.first() {
            // Check if the provider has a stored passphrase hash
            provider.is_new_vault()
        } else {
            true // No provider means new vault
        }
    }
}
