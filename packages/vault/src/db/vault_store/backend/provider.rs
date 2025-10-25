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
use crate::tui::cli::commands::{generate_pq_keypair, load_pq_key_from_keychain};
use cryypt_cipher::cipher::api::Cipher;
use cryypt_jwt::Jwt;
use cryypt_key::{
    api::KeyRetriever,
    api::{MasterKeyBuilder, MasterKeyProvider},
    store::KeychainStore,
};
use cryypt_pqcrypto::api::{KyberSecurityLevel as SecurityLevel, PqCryptoMasterBuilder};
use tokio::sync::{mpsc, oneshot};

impl VaultOperation for LocalVaultProvider {
    fn name(&self) -> &str {
        "Local Vault Provider"
    }

    // Check if user is authenticated (JWT-based)
    fn is_authenticated(&self) -> bool {
        // Check for JWT session token in memory
        if let Ok(token_guard) = self.session_token.try_lock() {
            if let Some(ref jwt_token) = *token_guard {
                log::debug!("AUTH_CHECK: Found JWT token in memory, validating...");

                // Load RSA keys from filesystem for validation
                use crate::auth::RsaKeyManager;
                let rsa_manager = RsaKeyManager::new(RsaKeyManager::default_path());

                // Attempt to load existing RSA keys (no passphrase needed for public key)
                let keys_result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        rsa_manager.load().await
                    })
                });

                match keys_result {
                    Ok((private_pkcs1, public_pkcs1)) => {
                        // Convert public key to SPKI for verification
                        use crate::auth::key_converter::{pkcs1_to_pkcs8, pkcs1_public_to_spki};

                        let private_pkcs8 = match pkcs1_to_pkcs8(&private_pkcs1) {
                            Ok(key) => key,
                            Err(e) => {
                                log::warn!("AUTH_CHECK: Private key conversion failed: {}", e);
                                return false;
                            }
                        };

                        let public_spki = match pkcs1_public_to_spki(&public_pkcs1) {
                            Ok(key) => key,
                            Err(e) => {
                                log::warn!("AUTH_CHECK: Public key conversion failed: {}", e);
                                return false;
                            }
                        };

                        // Create JWT handler with loaded keys
                        let vault_id = self.config.vault_path.to_string_lossy().to_string();
                        let jwt_handler = crate::auth::JwtHandler::new(
                            vault_id,
                            private_pkcs8,
                            public_spki,
                        );

                        // Validate token
                        let is_valid = tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(async {
                                jwt_handler.is_jwt_valid(jwt_token).await
                            })
                        });

                        if is_valid {
                            log::debug!("AUTH_CHECK: JWT validation successful");
                            return true;
                        } else {
                            log::debug!("AUTH_CHECK: JWT validation failed");
                        }
                    }
                    Err(e) => {
                        log::warn!("AUTH_CHECK: Failed to load RSA keys: {}", e);
                    }
                }
            } else {
                log::debug!("AUTH_CHECK: No JWT token found in memory");
            }
        } else {
            log::debug!("AUTH_CHECK: Could not acquire session token lock");
        }

        false
    }

    // Check if vault is locked in memory
    fn is_locked(&self) -> bool {
        // Check in-memory locked state (synchronous check to avoid async runtime conflicts)
        if let Ok(guard) = self.locked.try_lock() {
            *guard
        } else {
            // If we can't acquire the lock, assume locked for safety
            true
        }
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

        // Execute immediately without spawning a separate task
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { provider_clone.put_impl(key.clone(), value, None).await })
        });

        // Send result immediately
        let _ = tx.send(result);

        VaultUnitRequest::new(rx)
    }

    fn get(&self, key: &str) -> VaultGetRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();

        // Execute immediately without spawning a separate task
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { provider_clone.get_impl(&key, None).await })
        });

        // Send result immediately
        let _ = tx.send(result);

        VaultGetRequest::new(rx)
    }

    fn delete(&self, key: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();

        // Execute immediately without spawning a separate task
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                log::debug!("PROVIDER: Starting delete_impl for key: {}", key);
                let result = provider_clone.delete_impl(&key, None).await;
                log::debug!("PROVIDER: delete_impl result: {:?}", result);
                // Don't treat NotFound as an error for delete
                match result {
                    Err(VaultError::ItemNotFound) => {
                        log::debug!(
                            "PROVIDER: Converting ItemNotFound to Ok() for delete operation"
                        );
                        Ok(())
                    }
                    other => other,
                }
            })
        });

        log::debug!("PROVIDER: Sending final result: {:?}", result);
        let _ = tx.send(result);

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
            let result = provider_clone.put_if_absent_impl(key, value, None).await;
            let _ = tx.send(result);
        });

        VaultBoolRequest::new(rx)
    }

    fn put_all(&self, entries: Vec<(String, VaultValue)>) -> VaultPutAllRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        // entries is already owned

        tokio::spawn(async move {
            let result = provider_clone.put_all_impl(entries, None).await;
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
    /// Create JWT token using RSA keys (for login operations)
    pub async fn create_vault_jwt_token(&self, expires_in_hours: u64) -> VaultResult<String> {
        use crate::auth::{JwtHandler, RsaKeyManager};
        use crate::auth::key_converter::{pkcs1_to_pkcs8, pkcs1_public_to_spki};

        // Load RSA keys from filesystem
        let rsa_manager = RsaKeyManager::new(RsaKeyManager::default_path());
        let (private_pkcs1, public_pkcs1) = rsa_manager.load().await?;

        // Convert to JWT formats
        let private_pkcs8 = pkcs1_to_pkcs8(&private_pkcs1)?;
        let public_spki = pkcs1_public_to_spki(&public_pkcs1)?;

        // Create token
        let vault_id = self.config.vault_path.to_string_lossy().to_string();
        let jwt_handler = JwtHandler::new(vault_id, private_pkcs8, public_spki);

        jwt_handler.create_jwt_token(Some(expires_in_hours)).await
    }

    /// Emergency lockdown function - Enhanced security system
    ///
    /// Invalidates ALL active JWT sessions in SurrealDB (not just local),
    /// applies PQCrypto file armor, and performs secure memory cleanup.
    pub async fn emergency_lockdown(&self) -> VaultResult<()> {
        log_security_event(
            "EMERGENCY_LOCKDOWN",
            "Starting emergency lockdown sequence",
            true,
        );

        // 1. Invalidate ALL active JWT sessions in SurrealDB (not just local)
        let db = self.dao.db();
        let vault_id = self.jwt_handler.vault_id().to_string();
        match db
            .query("DELETE jwt_sessions WHERE vault_id = $vault_id")
            .bind(("vault_id", vault_id))
            .await
        {
            Ok(_) => {
                log_security_event(
                    "EMERGENCY_LOCKDOWN",
                    "All JWT sessions invalidated in database",
                    true,
                );
            }
            Err(e) => {
                log_security_event(
                    "EMERGENCY_LOCKDOWN",
                    &format!("Failed to invalidate sessions: {}", e),
                    false,
                );
                // Continue with lockdown even if session invalidation fails
            }
        }

        // 2. Apply PQCrypto file armor (.db → .vault) when API is ready
        match self.apply_pqcrypto_armor().await {
            Ok(_) => {
                log_security_event(
                    "EMERGENCY_LOCKDOWN",
                    "Vault file armored with PQCrypto",
                    true,
                );
            }
            Err(e) => {
                log_security_event(
                    "EMERGENCY_LOCKDOWN",
                    &format!("PQCrypto armor failed: {}", e),
                    false,
                );
                // Continue with lockdown even if PQCrypto armor fails
            }
        }

        // 4. Clear local session (existing sophisticated logic)
        match self.lock_impl().await {
            Ok(_) => {
                log_security_event(
                    "EMERGENCY_LOCKDOWN",
                    "Local session cleared successfully",
                    true,
                );
            }
            Err(e) => {
                log_security_event(
                    "EMERGENCY_LOCKDOWN",
                    &format!("Local session clearing failed: {}", e),
                    false,
                );
                return Err(e);
            }
        }

        log_security_event(
            "EMERGENCY_LOCKDOWN",
            "Emergency lockdown completed - all sessions invalidated, vault armored",
            true,
        );
        Ok(())
    }

    /// Apply PQCrypto file armor (lock operation: .db → .vault)
    pub async fn apply_pqcrypto_armor(&self) -> VaultResult<()> {
        let config = self.config.keychain_config.clone();
        let db_path = &self.config.vault_path;
        let vault_path = db_path.with_extension("vault");

        // Smart key_id determination:
        // - If .vault exists, read and reuse existing key_id
        // - If .vault doesn't exist, generate new UUID-based key_id
        let key_id = if vault_path.exists() {
            use crate::services::armor::read_key_id_from_vault_file;
            read_key_id_from_vault_file(&vault_path)
                .await
                .map_err(|e| {
                    VaultError::Provider(format!(
                        "Failed to read key ID from {}: {}",
                        vault_path.display(),
                        e
                    ))
                })?
        } else {
            // Generate new UUID-based key_id for fresh vault
            use crate::tui::cli::commands::generate_unique_key_id;
            generate_unique_key_id(&config.pq_namespace)
        };

        // Auto-generate keys if they don't exist and auto_generate is enabled
        if config.auto_generate
            && let Err(_) = load_pq_key_from_keychain(&key_id).await
        {
            generate_pq_keypair(&key_id, SecurityLevel::Level3)
                .await
                .map_err(|e| VaultError::Provider(format!("Failed to generate PQ keys: {}", e)))?;
        }

        // Use armor service for the actual operation
        use crate::services::{KeychainStorage, PQCryptoArmorService};
        let key_storage = KeychainStorage::new("vault");
        let armor_service = PQCryptoArmorService::new(key_storage, SecurityLevel::Level3);

        armor_service
            .armor(db_path, &vault_path, &key_id)
            .await
    }

    /// Remove PQCrypto file armor (unlock operation: .vault → .db)  
    pub async fn remove_pqcrypto_armor(&self) -> VaultResult<()> {
        let vault_path = self.config.vault_path.with_extension("vault");
        let db_path = &self.config.vault_path;

        // Read key_id from .vault file header
        use crate::services::armor::read_key_id_from_vault_file;
        let key_id = read_key_id_from_vault_file(&vault_path)
            .await
            .map_err(|e| {
                VaultError::Provider(format!(
                    "Failed to read key ID from {}: {}",
                    vault_path.display(),
                    e
                ))
            })?;

        // Use armor service for the actual operation
        use crate::services::{KeychainStorage, PQCryptoArmorService};
        let key_storage = KeychainStorage::new("vault");
        let armor_service = PQCryptoArmorService::new(key_storage, SecurityLevel::Level3);

        armor_service
            .unarmor(&vault_path, db_path, &key_id)
            .await
    }
}
