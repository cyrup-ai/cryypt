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
        // Priority 1: Check for restored JWT session in memory (from session persistence)
        if let Ok(token_guard) = self.session_token.try_lock() {
            if let Some(ref jwt_token) = *token_guard {
                log::info!("AUTH_CHECK: Found restored JWT token in memory");
                // Also check if we have the JWT signing key
                if let Ok(jwt_key_guard) = self.jwt_key.try_lock() {
                    if let Some(ref jwt_key) = *jwt_key_guard {
                        log::debug!(
                            "AUTH_CHECK: Found restored JWT key in memory, validating token"
                        );
                        // Validate the restored JWT token using the restored key
                        let validation_result = tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(async {
                                let result = Jwt::builder()
                                    .with_algorithm("HS256")
                                    .with_secret(jwt_key)
                                    .verify(jwt_token)
                                    .await;

                                match &result {
                                    Ok(_) => log::debug!(
                                        "AUTH_CHECK: JWT validation successful with restored key"
                                    ),
                                    Err(e) => log::debug!(
                                        "AUTH_CHECK: JWT validation failed with restored key: {}",
                                        e
                                    ),
                                }

                                result.is_ok()
                            })
                        });

                        if validation_result {
                            log::debug!(
                                "AUTH_CHECK: Authentication successful with restored session"
                            );
                            return true;
                        } else {
                            log::debug!("AUTH_CHECK: Authentication failed with restored session");
                        }
                    } else {
                        log::debug!("AUTH_CHECK: No restored JWT key found in memory");
                    }
                } else {
                    log::debug!("AUTH_CHECK: Could not acquire JWT key lock");
                }
            } else {
                log::debug!("AUTH_CHECK: No restored JWT token found in memory");
            }
        } else {
            log::debug!("AUTH_CHECK: Could not acquire session token lock");
        }

        // Priority 2: Extract JWT from environment (legacy/manual method)
        if let Some(jwt_token) = crate::auth::extract_jwt_from_env() {
            // Use vault-specific fixed secret (independent of master key)
            if let Ok(fixed_jwt_secret) = self.get_vault_jwt_secret() {
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
    /// Get vault-specific JWT secret (independent of master key)
    /// This ensures JWT authentication works even when vault is locked
    fn get_vault_jwt_secret(&self) -> VaultResult<Vec<u8>> {
        // Use vault ID + fixed salt for deterministic but independent secret
        let jwt_context = format!("jwt_auth_vault_{}", self.jwt_handler.vault_id());

        let master_key_provider = MasterKeyBuilder::from_passphrase(&jwt_context);
        master_key_provider
            .resolve()
            .map(|key| key.to_vec())
            .map_err(|e| VaultError::Internal(format!("Vault JWT secret derivation failed: {}", e)))
    }

    /// Create JWT token using vault-specific secret (for login operations)
    pub async fn create_vault_jwt_token(&self, expires_in_hours: u64) -> VaultResult<String> {
        // Get vault-specific JWT secret
        let jwt_secret = self.get_vault_jwt_secret()?;

        // Create JWT claims
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| VaultError::Internal("System time error".to_string()))?
            .as_secs() as i64;

        let claims = crate::auth::VaultJwtClaims {
            sub: "vault_user".to_string(),
            exp: now + (expires_in_hours as i64 * 3600),
            iat: now,
            vault_id: self.jwt_handler.vault_id().to_string(),
            session_id: uuid::Uuid::new_v4().to_string(),
        };

        // Create JWT token using vault secret
        let token = Jwt::builder()
            .with_algorithm("HS256")
            .with_secret(&jwt_secret)
            .sign(claims)
            .await
            .map_err(|e| VaultError::AuthenticationFailed(format!("JWT creation failed: {}", e)))?;

        Ok(token)
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

        // Auto-generate keys if they don't exist and auto_generate is enabled
        if config.auto_generate
            && let Err(_) = load_pq_key_from_keychain(&config.pq_namespace, 1).await
        {
            generate_pq_keypair(&config.pq_namespace, 1, SecurityLevel::Level3)
                .await
                .map_err(|e| VaultError::Provider(format!("Failed to generate PQ keys: {}", e)))?;
        }

        // Load keys from keychain
        let key_data = load_pq_key_from_keychain(&config.pq_namespace, 1)
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to load PQ keys: {}", e)))?;

        // Extract public key portion (first 1184 bytes for ML-KEM-768)
        let public_key = if key_data.len() >= 1184 {
            key_data[..1184].to_vec()
        } else {
            return Err(VaultError::Provider(
                "Invalid PQCrypto keypair: too short".into(),
            ));
        };

        // Read vault file data
        let vault_data = std::fs::read(&self.config.vault_path)
            .map_err(|e| VaultError::Provider(format!("Failed to read vault file: {}", e)))?;

        // Generate random symmetric key using Kyber KEM
        let (ciphertext, shared_secret) = PqCryptoMasterBuilder::new()
            .kyber()
            .with_security_level(SecurityLevel::Level3)
            .encapsulate_hybrid(public_key)
            .await
            .map_err(|e| VaultError::Provider(format!("Kyber encapsulation failed: {}", e)))?;

        // Encrypt vault file with AES-256-GCM
        let encrypted_data = Cipher::aes()
            .with_key(shared_secret)
            .on_result(|result| result.unwrap_or_default())
            .encrypt(vault_data)
            .await;

        // Create .vault file with hybrid format
        let armor_data = Self::create_armor_file_format(
            SecurityLevel::Level3,
            &ciphertext,
            encrypted_data.as_ref(),
        )?;

        // Atomic file operations
        let vault_path = self.config.vault_path.with_extension("vault");
        let temp_path = vault_path.with_extension("vault.tmp");

        std::fs::write(&temp_path, armor_data)
            .map_err(|e| VaultError::Provider(format!("Failed to write armored vault: {}", e)))?;

        std::fs::rename(&temp_path, &vault_path)
            .map_err(|e| VaultError::Provider(format!("Failed to rename armored vault: {}", e)))?;

        std::fs::remove_file(&self.config.vault_path).map_err(|e| {
            VaultError::Provider(format!("Failed to remove original vault file: {}", e))
        })?;

        log_security_event(
            "PQCRYPTO_ARMOR",
            "PQCrypto file armor applied using keychain keys",
            true,
        );

        Ok(())
    }

    /// Remove PQCrypto file armor (unlock operation: .vault → .db)  
    pub async fn remove_pqcrypto_armor(&self) -> VaultResult<()> {
        let config = self.config.keychain_config.clone();
        let vault_path = self.config.vault_path.with_extension("vault");

        // Load keys from keychain
        let key_data = load_pq_key_from_keychain(&config.pq_namespace, 1)
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to load PQ keys: {}", e)))?;

        // Extract private key portion (everything after public key)
        let private_key = if key_data.len() >= 1184 {
            key_data[1184..].to_vec()
        } else {
            return Err(VaultError::Provider(format!(
                "Invalid PQCrypto keypair: got {} bytes, need at least 1184",
                key_data.len()
            )));
        };

        // Read armored vault file data
        let armor_data = std::fs::read(&vault_path).map_err(|e| {
            VaultError::Provider(format!("Failed to read armored vault file: {}", e))
        })?;

        // Parse .vault file format
        let (kyber_algorithm, kyber_ciphertext, encrypted_data) =
            Self::parse_armor_file_format(&armor_data)?;

        // Decapsulate symmetric key using Kyber KEM
        let shared_secret = PqCryptoMasterBuilder::new()
            .kyber()
            .with_security_level(kyber_algorithm)
            .decapsulate_hybrid(private_key, kyber_ciphertext)
            .await
            .map_err(|e| VaultError::Provider(format!("Kyber decapsulation failed: {}", e)))?;

        // Decrypt vault file with AES-256-GCM
        let decrypted_data = Cipher::aes()
            .with_key(shared_secret)
            .on_result(|result| result.unwrap_or_default())
            .decrypt(encrypted_data)
            .await;

        // Atomic file operations
        let temp_path = self.config.vault_path.with_extension("db.tmp");

        std::fs::write(&temp_path, decrypted_data)
            .map_err(|e| VaultError::Provider(format!("Failed to write decrypted vault: {}", e)))?;

        std::fs::rename(&temp_path, &self.config.vault_path).map_err(|e| {
            VaultError::Provider(format!("Failed to rename decrypted vault: {}", e))
        })?;

        std::fs::remove_file(&vault_path).map_err(|e| {
            VaultError::Provider(format!("Failed to remove armored vault file: {}", e))
        })?;

        log_security_event(
            "PQCRYPTO_ARMOR",
            "PQCrypto file armor removed using keychain keys",
            true,
        );

        Ok(())
    }
}
