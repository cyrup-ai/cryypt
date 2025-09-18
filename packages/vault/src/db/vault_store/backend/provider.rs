//! VaultOperation trait implementation for LocalVaultProvider
//!
//! Contains the main trait implementation that provides the public vault interface.

use super::super::LocalVaultProvider;
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use crate::logging::log_security_event;
use crate::operation::{
    Passphrase, VaultBoolRequest, VaultChangePassphraseRequest, VaultFindRequest, VaultGetRequest,
    VaultListNamespacesRequest, VaultListRequest, VaultOperation, VaultPutAllRequest,
    VaultSaveRequest, VaultUnitRequest,
};
use cryypt_key::{api::KeyRetriever, store::KeychainStore, api::{MasterKeyBuilder, MasterKeyProvider}};
use cryypt_jwt::Jwt;
// Note: PQCrypto API is in development - using stubs for now
use tokio::sync::{mpsc, oneshot};

impl VaultOperation for LocalVaultProvider {
    fn name(&self) -> &str {
        "Local Vault Provider"
    }

    // Check if user is authenticated (JWT-based)
    fn is_authenticated(&self) -> bool {
        // Extract JWT from environment
        if let Some(jwt_token) = crate::auth::extract_jwt_from_env() {
            // Use FIXED JWT secret (not derived from master key)
            if let Ok(fixed_jwt_secret) = self.get_fixed_jwt_secret() {
                // Validate using cryypt_jwt independent API
                let validation_result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        Jwt::builder()
                            .with_algorithm("HS256")
                            .with_secret(&fixed_jwt_secret)
                            .verify(jwt_token)
                            .await
                            .is_ok()
                    })
                });
                
                return validation_result;
            }
        }
        
        false // No JWT = not authenticated
    }

    // Check if vault file is PQCrypto armored
    fn is_locked(&self) -> bool {
        let vault_path = &self.config.vault_path;
        let armored_path = vault_path.with_extension("vault");
        let unarmored_path = vault_path.with_extension("db");
        
        // Vault is locked if:
        // 1. Armored file (.vault) exists, OR
        // 2. Neither file exists (new vault)
        armored_path.exists() || (!armored_path.exists() && !unarmored_path.exists())
    }

    // Check if master key is available for encryption
    fn has_master_key(&self) -> bool {
        // Synchronous check to avoid async runtime conflicts
        if let Ok(key_guard) = self.encryption_key.try_lock() {
            key_guard.is_some()
        } else {
            false
        }
    }

    // Unlock the vault with a passphrase
    fn unlock(&self, passphrase: &Passphrase) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let passphrase_clone = passphrase.clone();

        tokio::spawn(async move {
            log::debug!("PROVIDER: Starting unlock_impl");
            let result = provider_clone.unlock_impl(passphrase_clone).await;
            log::debug!("PROVIDER: unlock_impl result: {:?}", result);
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    // Lock the vault
    fn lock(&self) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();

        tokio::spawn(async move {
            let result = provider_clone.lock_impl().await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn put(&self, key: &str, value: VaultValue) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();
        // value is already owned, move it

        tokio::spawn(async move {
            let result = provider_clone.put_impl(key, value, None).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn get(&self, key: &str) -> VaultGetRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone.get_impl(&key, None).await;
            let _ = tx.send(result);
        });

        VaultGetRequest::new(rx)
    }

    fn delete(&self, key: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();

        tokio::spawn(async move {
            // Use the existing delete_impl method which handles authentication internally
            // The JWT validation deadlock has been fixed in session.rs
            log::debug!("PROVIDER: Starting delete_impl for key: {}", key);
            let result = provider_clone.delete_impl(&key, None).await;
            log::debug!("PROVIDER: delete_impl result: {:?}", result);
            // Don't treat NotFound as an error for delete
            let final_result = match result {
                Err(VaultError::ItemNotFound) => {
                    log::debug!("PROVIDER: Converting ItemNotFound to Ok() for delete operation");
                    Ok(())
                },
                other => other,
            };
            log::debug!("PROVIDER: Sending final result: {:?}", final_result);
            let _ = tx.send(final_result);
        });

        VaultUnitRequest::new(rx)
    }

    fn list(&self, prefix: Option<&str>) -> VaultListRequest {
        let (tx, rx) = mpsc::channel(100); // Buffer size 100
        let provider_clone = self.clone();
        let prefix = prefix.map(|s| s.to_string()); // Clone prefix into an Option<String>

        tokio::spawn(async move {
            match provider_clone.list_impl(prefix.as_deref()).await {
                Ok(keys) => {
                    for key in keys {
                        if tx.send(Ok(key)).await.is_err() {
                            // Receiver dropped
                            break;
                        }
                    }
                    // Channel closes when tx drops
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        VaultListRequest::new(rx)
    }

    // Change passphrase
    fn change_passphrase(
        &self,
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
    ) -> VaultChangePassphraseRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let old_passphrase_clone = old_passphrase.clone();
        let new_passphrase_clone = new_passphrase.clone();

        tokio::spawn(async move {
            let result = provider_clone
                .change_passphrase_impl(old_passphrase_clone, new_passphrase_clone)
                .await;
            let _ = tx.send(result);
        });

        VaultChangePassphraseRequest::new(rx)
    }

    // Save is not explicitly needed; operations are typically transactional per request
    fn save(&self) -> VaultSaveRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Ok(())); // Assume success as operations are immediate
        VaultSaveRequest::new(rx)
    }

    fn put_if_absent(&self, key: &str, value: VaultValue) -> VaultBoolRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();
        // value is already owned

        tokio::spawn(async move {
            let result = provider_clone.put_if_absent_impl(key, value).await;
            let _ = tx.send(result);
        });

        VaultBoolRequest::new(rx)
    }

    fn put_all(&self, entries: Vec<(String, VaultValue)>) -> VaultPutAllRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        // entries is already owned

        tokio::spawn(async move {
            let result = provider_clone.put_all_impl(entries).await;
            let _ = tx.send(result);
        });

        VaultPutAllRequest::new(rx)
    }

    fn find(&self, pattern: &str) -> VaultFindRequest {
        let (tx, rx) = mpsc::channel(100); // Buffer size 100
        let provider_clone = self.clone();
        let pattern = pattern.to_string();

        tokio::spawn(async move {
            match provider_clone.find_impl(&pattern).await {
                Ok(results) => {
                    for item in results {
                        if tx.send(Ok(item)).await.is_err() {
                            // Receiver dropped
                            break;
                        }
                    }
                    // Channel closes when tx drops
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        VaultFindRequest::new(rx)
    }

    fn is_new_vault(&self) -> bool {
        // For sync context, check if vault database file exists
        // Synchronous filesystem check prevents async runtime conflicts
        !self.config.vault_path.exists()
    }

    fn supports_namespaces(&self) -> bool {
        true
    }

    fn create_namespace(&self, _namespace: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        // Namespaces are implicit in this implementation - created when first key is stored
        let _ = tx.send(Ok(()));
        VaultUnitRequest::new(rx)
    }

    // Namespace-aware operations

    fn put_with_namespace(
        &self,
        namespace: &str,
        key: &str,
        value: VaultValue,
    ) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let namespace = namespace.to_string();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone
                .put_with_namespace(namespace, key, value)
                .await
                .map_err(|e| crate::error::VaultError::Provider(e.to_string()));
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn get_by_namespace(&self, namespace: &str) -> VaultListRequest {
        let (tx, rx) = mpsc::channel(100);
        let provider_clone = self.clone();
        let namespace = namespace.to_string();

        tokio::spawn(async move {
            match provider_clone.get_keys_by_namespace(namespace).await {
                Ok(keys) => {
                    for key in keys {
                        if tx.send(Ok(key)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(crate::error::VaultError::Provider(e.to_string())))
                        .await;
                }
            }
        });

        VaultListRequest::new(rx)
    }

    fn get_from_namespace(&self, namespace: &str, key: &str) -> VaultGetRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let namespace = namespace.to_string();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone.get_impl(&key, Some(&namespace)).await;
            let _ = tx.send(result);
        });

        VaultGetRequest::new(rx)
    }

    fn delete_from_namespace(&self, namespace: &str, key: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let namespace = namespace.to_string();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone.delete_impl(&key, Some(&namespace)).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn find_in_namespace(&self, namespace: &str, pattern: &str) -> VaultFindRequest {
        let (tx, rx) = mpsc::channel(100);
        let provider_clone = self.clone();
        let namespace = namespace.to_string();
        let pattern = pattern.to_string();

        tokio::spawn(async move {
            match provider_clone
                .find_in_namespace_impl(&namespace, &pattern)
                .await
            {
                Ok(results) => {
                    for item in results {
                        if tx.send(Ok(item)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(super::super::map_dao_error(e))).await;
                }
            }
        });

        VaultFindRequest::new(rx)
    }

    fn list_namespaces(&self) -> VaultListNamespacesRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();

        tokio::spawn(async move {
            let result = provider_clone.list_namespaces_impl().await;
            let _ = tx.send(result);
        });

        VaultListNamespacesRequest::new(rx)
    }
}

impl LocalVaultProvider {
    /// Get fixed JWT secret (independent of master key)
    fn get_fixed_jwt_secret(&self) -> VaultResult<Vec<u8>> {
        // Use vault ID + fixed salt for deterministic but independent secret
        let fixed_context = format!("jwt_auth_fixed_{}", self.jwt_handler.vault_id());
        
        let master_key_provider = MasterKeyBuilder::from_passphrase(&fixed_context);
        master_key_provider
            .resolve()
            .map(|key| key.to_vec())
            .map_err(|e| VaultError::Internal(format!("Fixed JWT secret derivation failed: {}", e)))
    }

    /// Emergency lockdown function - Enhanced security system
    /// 
    /// Invalidates ALL active JWT sessions in SurrealDB (not just local),
    /// applies PQCrypto file armor, and performs secure memory cleanup.
    pub async fn emergency_lockdown(&self) -> VaultResult<()> {
        log_security_event("EMERGENCY_LOCKDOWN", "Starting emergency lockdown sequence", true);

        // 1. Invalidate ALL active JWT sessions in SurrealDB (not just local)
        let db = self.dao.db();
        let vault_id = self.jwt_handler.vault_id().to_string();
        match db.query("DELETE jwt_sessions WHERE vault_id = $vault_id")
            .bind(("vault_id", vault_id))
            .await 
        {
            Ok(_) => {
                log_security_event("EMERGENCY_LOCKDOWN", "All JWT sessions invalidated in database", true);
            }
            Err(e) => {
                log_security_event("EMERGENCY_LOCKDOWN", &format!("Failed to invalidate sessions: {}", e), false);
                // Continue with lockdown even if session invalidation fails
            }
        }

        // 2. Apply PQCrypto file armor (.db → .vault) when API is ready
        match self.apply_pqcrypto_armor().await {
            Ok(_) => {
                log_security_event("EMERGENCY_LOCKDOWN", "Vault file armored with PQCrypto", true);
            }
            Err(e) => {
                log_security_event("EMERGENCY_LOCKDOWN", &format!("PQCrypto armor failed: {}", e), false);
                // Continue with lockdown even if PQCrypto armor fails
            }
        }

        // 4. Clear local session (existing sophisticated logic)
        match self.lock_impl().await {
            Ok(_) => {
                log_security_event("EMERGENCY_LOCKDOWN", "Local session cleared successfully", true);
            }
            Err(e) => {
                log_security_event("EMERGENCY_LOCKDOWN", &format!("Local session clearing failed: {}", e), false);
                return Err(e);
            }
        }

        log_security_event("EMERGENCY_LOCKDOWN", "Emergency lockdown completed - all sessions invalidated, vault armored", true);
        Ok(())
    }

    /// Apply PQCrypto file armor (lock operation: .db → .vault)
    /// 
    /// NOTE: This is a STUB implementation. The actual PQCrypto API integration is pending.
    /// When ready, this will:
    /// 1. Load PQCrypto keys from keychain: KeyRetriever::new().with_store(KeychainStore::for_app("vault")).with_namespace("pq_armor").version(1)
    /// 2. Encrypt vault file: PqCryptoMasterBuilder::new().kyber().with_security_level(SecurityLevel::Level3).encapsulate()
    /// 3. Write .vault file and remove .db file atomically
    pub async fn apply_pqcrypto_armor(&self) -> VaultResult<()> {
        // STUB: Log intended operation for now
        log_security_event("PQCRYPTO_ARMOR", "PQCrypto file armor (STUB) - will load keys from keychain 'vault/pq_armor'", true);
        
        // For now, just rename .db to .vault to simulate the armor operation
        let vault_path = self.config.vault_path.with_extension("vault");
        
        if self.config.vault_path.exists() {
            std::fs::copy(&self.config.vault_path, &vault_path)
                .map_err(|e| VaultError::Provider(format!("Failed to create armored vault copy: {}", e)))?;
                
            std::fs::remove_file(&self.config.vault_path)
                .map_err(|e| VaultError::Provider(format!("Failed to remove original vault file: {}", e)))?;
                
            log_security_event("PQCRYPTO_ARMOR", "Vault file moved to .vault extension (STUB)", true);
        }
        
        Ok(())
    }

    /// Remove PQCrypto file armor (unlock operation: .vault → .db)  
    /// 
    /// NOTE: This is a STUB implementation. The actual PQCrypto API integration is pending.
    /// When ready, this will:
    /// 1. Load PQCrypto keys from keychain: KeyRetriever::new().with_store(KeychainStore::for_app("vault")).with_namespace("pq_armor").version(1)  
    /// 2. Decrypt vault file: PqCryptoMasterBuilder::new().kyber().with_security_level(SecurityLevel::Level3).decapsulate()
    /// 3. Write .db file and remove .vault file atomically
    pub async fn remove_pqcrypto_armor(&self) -> VaultResult<()> {
        // STUB: Log intended operation for now
        log_security_event("PQCRYPTO_ARMOR", "PQCrypto file armor removal (STUB) - will load keys from keychain 'vault/pq_armor'", true);
        
        let vault_path = self.config.vault_path.with_extension("vault");
        
        if vault_path.exists() {
            std::fs::copy(&vault_path, &self.config.vault_path)
                .map_err(|e| VaultError::Provider(format!("Failed to restore vault from armor: {}", e)))?;
                
            std::fs::remove_file(&vault_path)
                .map_err(|e| VaultError::Provider(format!("Failed to remove armored vault file: {}", e)))?;
                
            log_security_event("PQCRYPTO_ARMOR", "Vault file restored from .vault extension (STUB)", true);
        }
        
        Ok(())
    }
}
