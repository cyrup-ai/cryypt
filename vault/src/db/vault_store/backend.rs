//! Backend storage implementation for vault operations
//!
//! Contains the core database operations, schema initialization, and internal async helpers.

use super::{LocalVaultProvider, VaultEntry, map_dao_error};
use crate::core::VaultValue;
use crate::db::dao::{Error as DaoError, GenericDao};
use crate::error::{VaultError, VaultResult};
use crate::operation::{
    Passphrase, VaultBoolRequest, VaultChangePassphraseRequest, VaultFindRequest, VaultGetRequest,
    VaultListRequest, VaultOperation, VaultPutAllRequest, VaultSaveRequest, VaultUnitRequest,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use futures::StreamExt;
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot};

// Crypto dependencies
use cryypt_cipher::Cryypt;
use cryypt_jwt::JwtMasterBuilder;
use secrecy::ExposeSecret;

impl LocalVaultProvider {
    /// Initialize the vault schema (specific to this provider)
    pub async fn initialize_schema(&self) -> Result<(), DaoError> {
        // Define vault entries table
        let db = self.dao.db();
        db.query(
            "
            DEFINE TABLE IF NOT EXISTS vault_entries SCHEMAFULL;
            DEFINE FIELD key ON TABLE vault_entries TYPE string;
            DEFINE FIELD value ON TABLE vault_entries TYPE string;
            DEFINE FIELD created_at ON TABLE vault_entries TYPE datetime;
            DEFINE FIELD updated_at ON TABLE vault_entries TYPE datetime;
            DEFINE FIELD namespace ON TABLE vault_entries TYPE option<string>;
            DEFINE INDEX vault_key ON TABLE vault_entries COLUMNS key UNIQUE;
        ",
        )
        .await
        .map_err(|e| DaoError::Database(e.to_string()))?;

        Ok(())
    }

    // --- Internal Async Implementation Helpers ---

    pub(crate) async fn check_unlocked(&self) -> VaultResult<()> {
        match self.locked.lock() {
            Ok(guard) => {
                if *guard {
                    return Err(VaultError::VaultLocked);
                }
            }
            Err(_) => return Err(VaultError::VaultLocked), // Poisoned mutex, assume locked
        }

        // Validate JWT session token
        let token_guard = self.session_token.lock().await;
        if let Some(token) = token_guard.as_ref() {
            // Validate JWT token using cryypt_jwt API - use associated function syntax
            let validation_result = JwtMasterBuilder::new()
                .with_algorithm("HS256")
                .with_secret(b"vault_session_key") // Use a consistent secret
                .on_result(|result| match result {
                    Ok(_) => b"valid".to_vec(),
                    Err(_) => b"invalid".to_vec(),
                })
                .verify(token.clone())
                .await;

            if validation_result == b"valid".to_vec() {
                Ok(())
            } else {
                // Token invalid, lock the vault
                drop(token_guard);
                self.lock_impl().await?;
                Err(VaultError::VaultLocked)
            }
        } else {
            // No token present, vault should be locked
            drop(token_guard);
            self.lock_impl().await?;
            Err(VaultError::VaultLocked)
        }
    }

    pub(crate) async fn unlock_impl(&self, passphrase: Passphrase) -> VaultResult<()> {
        // Ensure vault is currently locked before proceeding
        {
            match self.locked.lock() {
                Ok(guard) => {
                    if !*guard {
                        return Err(VaultError::Provider(
                            "Vault is already unlocked".to_string(),
                        ));
                    }
                }
                Err(_) => {} // Poisoned mutex, proceed as if locked
            }
        }

        // Step 1: Verify passphrase against stored hash if exists
        if let Err(e) = self.verify_passphrase(&passphrase).await {
            return Err(e);
        }

        // Step 2: Derive encryption key from passphrase using secure key derivation
        log::debug!("Deriving encryption key from passphrase...");
        let encryption_key = self.derive_encryption_key(&passphrase).await?;

        // Step 3: Validate that key derivation was successful
        if encryption_key.is_empty() {
            return Err(VaultError::KeyDerivation(
                "Key derivation failed - empty key".to_string(),
            ));
        }
        log::debug!(
            "Successfully derived {} byte encryption key",
            encryption_key.len()
        );

        // Step 4: Test encryption/decryption with derived key to ensure it works
        let test_data = b"vault_unlock_test";
        log::debug!("Testing encryption with {} byte test data", test_data.len());

        let encrypted_test = match self.encrypt_data(test_data).await {
            Ok(encrypted) => {
                log::debug!(
                    "Encryption successful, encrypted size: {} bytes",
                    encrypted.len()
                );
                encrypted
            }
            Err(e) => {
                log::error!("Encryption test failed: {}", e);
                return Err(VaultError::Crypto(format!("Encryption test failed: {}", e)));
            }
        };

        let decrypted_test = match self.decrypt_data(&encrypted_test).await {
            Ok(decrypted) => {
                log::debug!(
                    "Decryption successful, decrypted size: {} bytes",
                    decrypted.len()
                );
                decrypted
            }
            Err(e) => {
                log::error!("Decryption test failed: {}", e);
                return Err(VaultError::Crypto(format!("Decryption test failed: {}", e)));
            }
        };

        if decrypted_test != test_data {
            log::error!(
                "Encryption/decryption test data mismatch! Expected {} bytes, got {} bytes",
                test_data.len(),
                decrypted_test.len()
            );
            return Err(VaultError::Crypto(
                "Encryption/decryption test failed - data mismatch".to_string(),
            ));
        }

        log::debug!("Encryption/decryption test passed successfully");

        // Step 5: Generate secure JWT session token with enhanced claims
        let session_claims = serde_json::json!({
            "session": "vault_unlocked",
            "vault_path": self.config.vault_path.to_string_lossy(),
            "issued_at": chrono::Utc::now().timestamp(),
            "exp": chrono::Utc::now().timestamp() + 3600,
            "nbf": chrono::Utc::now().timestamp()
        });

        let token_result = JwtMasterBuilder::new()
            .with_algorithm("HS256")
            .with_secret(b"vault_session_key")
            .on_result(|result| match result {
                Ok(token) => token,
                Err(e) => {
                    log::error!("JWT generation failed: {}", e);
                    Vec::new()
                }
            })
            .sign(session_claims)
            .await;

        // Step 6: Validate token generation was successful
        if token_result.is_empty() {
            return Err(VaultError::Crypto(
                "Failed to generate session token".to_string(),
            ));
        }

        // Step 7: Store passphrase hash for future verification (after successful validation)
        self.store_passphrase_hash(&passphrase).await?;

        // Step 8: Atomically update all session state
        {
            // Store the passphrase securely in memory (using SecretString from secrecy crate)
            let mut passphrase_guard = self.passphrase.lock().await;
            *passphrase_guard = Some(passphrase.clone());
            drop(passphrase_guard);

            // Store the JWT session token
            let mut token_guard = self.session_token.lock().await;
            *token_guard = Some(String::from_utf8_lossy(&token_result).to_string());
            drop(token_guard);

            // Finally, unlock the vault
            if let Ok(mut locked_guard) = self.locked.lock() {
                *locked_guard = false;
            }
        }

        log::info!("Vault successfully unlocked with full crypto integration");
        Ok(())
    }

    pub(crate) async fn lock_impl(&self) -> VaultResult<()> {
        // Lock the vault and securely clear all sensitive data from memory
        if let Ok(mut locked_guard) = self.locked.lock() {
            *locked_guard = true;
        }

        // Securely clear passphrase from memory (SecretString handles zeroization)
        let mut passphrase_guard = self.passphrase.lock().await;
        *passphrase_guard = None;
        drop(passphrase_guard);

        // Clear session token
        let mut token_guard = self.session_token.lock().await;
        *token_guard = None;
        drop(token_guard);

        // Securely clear encryption key from memory
        let mut key_guard = self.encryption_key.lock().await;
        if let Some(ref mut key) = key_guard.as_mut() {
            // Explicitly zero out the key bytes before dropping
            key.fill(0);
        }
        *key_guard = None;

        Ok(())
    }

    pub(crate) async fn derive_encryption_key(
        &self,
        passphrase: &Passphrase,
    ) -> VaultResult<Vec<u8>> {
        // Read or generate salt from file
        log::trace!("Getting salt for key derivation...");
        let salt = self.get_or_create_salt().await?;
        log::trace!("Using {} byte salt for key derivation", salt.len());

        // Use Argon2 for secure key derivation with the vault's configured parameters
        use argon2::{Argon2, password_hash::Salt};

        log::trace!(
            "Configuring Argon2 with memory_cost={}, time_cost={}, parallelism={}",
            self.config.argon2_memory_cost,
            self.config.argon2_time_cost,
            self.config.argon2_parallelism
        );

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                self.config.argon2_memory_cost,
                self.config.argon2_time_cost,
                self.config.argon2_parallelism,
                Some(32), // 32 bytes for AES-256
            )
            .map_err(|e| VaultError::KeyDerivation(format!("Invalid Argon2 params: {}", e)))?,
        );

        // Create Salt from our salt bytes
        let salt_b64 = BASE64_STANDARD.encode(&salt);
        log::trace!("Salt base64 encoded for Argon2: {} chars", salt_b64.len());
        let salt_str = Salt::from_b64(&salt_b64)
            .map_err(|e| VaultError::KeyDerivation(format!("Invalid salt: {}", e)))?;

        // Derive key using Argon2
        let mut output_key = vec![0u8; 32];
        log::trace!("Running Argon2 key derivation...");
        argon2
            .hash_password_into(
                passphrase.expose_secret().as_bytes(),
                salt_str.as_str().as_bytes(),
                &mut output_key,
            )
            .map_err(|e| {
                VaultError::KeyDerivation(format!("Argon2 key derivation failed: {}", e))
            })?;

        log::trace!("Successfully derived {} byte key", output_key.len());

        // Store derived key in memory for session
        let mut key_guard = self.encryption_key.lock().await;
        *key_guard = Some(output_key.clone());

        Ok(output_key)
    }

    pub(crate) async fn encrypt_data(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        // Get the encryption key from session
        let key_guard = self.encryption_key.lock().await;
        let encryption_key = key_guard.as_ref().ok_or_else(|| VaultError::VaultLocked)?;

        log::trace!(
            "Encrypting {} bytes with {} byte key",
            data.len(),
            encryption_key.len()
        );

        // Use AES encryption with cryypt_cipher - README.md compliant pattern
        let encrypted_data = Cryypt::cipher()
            .aes()
            .with_key(encryption_key.clone())
            .on_result(|result| match result {
                Ok(result) => {
                    log::trace!(
                        "cryypt_cipher encryption succeeded, output: {} bytes",
                        result.len()
                    );
                    result
                }
                Err(e) => {
                    log::error!("cryypt_cipher encryption failed: {:?}", e);
                    Vec::new()
                }
            })
            .encrypt(data.to_vec())
            .await;

        if encrypted_data.is_empty() {
            return Err(VaultError::Encryption(
                "Failed to encrypt data - empty result".to_string(),
            ));
        }

        Ok(encrypted_data)
    }

    pub(crate) async fn decrypt_data(&self, encrypted_data: &[u8]) -> VaultResult<Vec<u8>> {
        // Get the encryption key from session
        let key_guard = self.encryption_key.lock().await;
        let encryption_key = key_guard.as_ref().ok_or_else(|| VaultError::VaultLocked)?;

        log::trace!(
            "Decrypting {} bytes with {} byte key",
            encrypted_data.len(),
            encryption_key.len()
        );

        // Use AES decryption with cryypt_cipher - README.md compliant pattern
        let decrypted_data = Cryypt::cipher()
            .aes()
            .with_key(encryption_key.clone())
            .on_result(|result| match result {
                Ok(result) => {
                    log::trace!(
                        "cryypt_cipher decryption succeeded, output: {} bytes",
                        result.len()
                    );
                    result
                }
                Err(e) => {
                    log::error!("cryypt_cipher decryption failed: {:?}", e);
                    Vec::new()
                }
            })
            .decrypt(encrypted_data.to_vec())
            .await;

        if decrypted_data.is_empty() {
            return Err(VaultError::Decryption(
                "Failed to decrypt data - empty result".to_string(),
            ));
        }

        Ok(decrypted_data)
    }

    /// Securely store passphrase hash for verification
    pub(crate) async fn store_passphrase_hash(&self, passphrase: &Passphrase) -> VaultResult<()> {
        // Use consistent salt for passphrase hashing
        let salt = self.get_or_create_salt().await?;

        // Use Argon2 for passphrase hashing with same parameters
        use argon2::{
            Argon2,
            password_hash::{PasswordHasher, Salt},
        };

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                self.config.argon2_memory_cost,
                self.config.argon2_time_cost,
                self.config.argon2_parallelism,
                None, // Default output length for password hashing
            )
            .map_err(|e| VaultError::KeyDerivation(format!("Invalid Argon2 params: {}", e)))?,
        );

        // Create Salt from our salt bytes
        let salt_b64 = BASE64_STANDARD.encode(&salt);
        let salt_str = Salt::from_b64(&salt_b64)
            .map_err(|e| VaultError::KeyDerivation(format!("Invalid salt: {}", e)))?;

        // Hash the passphrase
        let passphrase_hash = argon2
            .hash_password(passphrase.expose_secret().as_bytes(), salt_str)
            .map_err(|e| VaultError::Crypto(format!("Failed to hash passphrase: {}", e)))?;

        let passphrase_hash = passphrase_hash.to_string().into_bytes();

        if passphrase_hash.is_empty() {
            return Err(VaultError::Crypto("Failed to hash passphrase".to_string()));
        }

        // Store the passphrase hash in the database using SurrealDB UPSERT
        let hash_b64 = BASE64_STANDARD.encode(passphrase_hash);

        // First try to UPDATE, if it doesn't exist, CREATE it
        let update_query = "UPDATE vault_entries:__vault_passphrase_hash__ SET value = $value, updated_at = $updated_at";
        let db = self.dao.db();

        let value = hash_b64.clone();
        let mut update_result = db
            .query(update_query)
            .bind(("value", value))
            .bind(("updated_at", chrono::Utc::now()))
            .await
            .map_err(|e| {
                VaultError::Provider(format!("Failed to update passphrase hash: {}", e))
            })?;

        // Check if any record was updated
        let updated: Option<VaultEntry> = update_result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to check update result: {}", e)))?;

        if updated.is_none() {
            // No existing record, create a new one
            let create_query = "CREATE vault_entries:__vault_passphrase_hash__ SET key = $key, value = $value, created_at = $created_at, updated_at = $updated_at";
            db.query(create_query)
                .bind(("key", "__vault_passphrase_hash__"))
                .bind(("value", hash_b64))
                .bind(("created_at", chrono::Utc::now()))
                .bind(("updated_at", chrono::Utc::now()))
                .await
                .map_err(|e| {
                    VaultError::Provider(format!("Failed to create passphrase hash: {}", e))
                })?;
        }

        Ok(())
    }

    /// Verify passphrase against stored hash
    pub(crate) async fn verify_passphrase(&self, passphrase: &Passphrase) -> VaultResult<()> {
        log::debug!("Verifying passphrase against stored hash...");

        // Try to retrieve stored passphrase hash using SurrealDB syntax
        let query = "SELECT * FROM vault_entries:__vault_passphrase_hash__";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        let hash_entry: Option<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        match hash_entry {
            Some(entry) => {
                log::debug!("Found existing passphrase hash in database");

                // Decode stored hash
                let stored_hash = BASE64_STANDARD.decode(entry.value).map_err(|_| {
                    VaultError::Crypto("Invalid stored passphrase hash".to_string())
                })?;

                // Decode stored hash (it's the full Argon2 hash string)
                let stored_hash_str = String::from_utf8(stored_hash).map_err(|_| {
                    VaultError::Crypto("Invalid stored passphrase hash encoding".to_string())
                })?;

                log::trace!("Stored hash format: {} chars", stored_hash_str.len());

                // Verify passphrase using Argon2 verify
                use argon2::{Argon2, PasswordHash, PasswordVerifier};

                let parsed_hash = PasswordHash::new(&stored_hash_str).map_err(|e| {
                    VaultError::Crypto(format!("Invalid stored hash format: {}", e))
                })?;

                let argon2 = Argon2::default();

                match argon2.verify_password(passphrase.expose_secret().as_bytes(), &parsed_hash) {
                    Ok(_) => {
                        log::debug!("Passphrase verification successful");
                        Ok(())
                    }
                    Err(_) => {
                        log::warn!("Passphrase verification failed - incorrect passphrase");
                        Err(VaultError::InvalidPassphrase)
                    }
                }
            }
            None => {
                // No stored hash means this is the first time unlocking
                // Allow the unlock to proceed, hash will be stored
                log::info!("No existing passphrase hash found - this appears to be a new vault");
                Ok(())
            }
        }
    }

    pub(crate) async fn change_passphrase_impl(
        &self,
        old_passphrase: Passphrase,
        new_passphrase: Passphrase,
    ) -> VaultResult<()> {
        // Verify old passphrase matches current one
        let mut passphrase_guard = self.passphrase.lock().await;

        match passphrase_guard.as_ref() {
            Some(current_passphrase) => {
                if current_passphrase.expose_secret() != old_passphrase.expose_secret() {
                    return Err(VaultError::InvalidPassphrase);
                }
            }
            None => {
                return Err(VaultError::VaultLocked);
            }
        }

        // Update to new passphrase
        *passphrase_guard = Some(new_passphrase);

        Ok(())
    }

    pub(crate) async fn put_impl(&self, key: String, value: VaultValue) -> VaultResult<()> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Encrypt VaultValue bytes using AES encryption
        let encrypted_value = self.encrypt_data(value.expose_secret()).await?;
        let value_b64 = BASE64_STANDARD.encode(encrypted_value);

        let entry = VaultEntry {
            id: Some(format!("entry:{}", key.replace('/', "_"))),
            key: key.clone(), // Clone key for entry
            value: value_b64,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            namespace: None, // Namespace handled separately if needed
        };

        // Use the GenericDao trait
        let mut stream = GenericDao::create(&self.dao, entry);

        // Consume the stream to execute the create operation
        match stream.next().await {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Err(map_dao_error(e)),
            None => Err(VaultError::Provider(
                "Failed to create vault entry: No result from DAO".to_string(),
            )),
        }
    }

    pub(crate) async fn get_impl(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        let query = "SELECT value FROM vault_entries WHERE key = $key LIMIT 1";
        let db = self.dao.db();
        let key = key.to_string(); // Clone to satisfy 'static lifetime

        let mut result = db
            .query(query)
            .bind(("key", key))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        // We only selected 'value', so deserialize into a struct holding just that.
        #[derive(Deserialize)]
        struct ValueOnly {
            value: String,
        }

        // Extract the first result set (index 0)
        let value_entry: Option<ValueOnly> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        match value_entry {
            Some(entry) => {
                // Decode base64 string back to encrypted bytes
                let encrypted_bytes = BASE64_STANDARD.decode(entry.value).map_err(|_| {
                    VaultError::Serialization(
                        serde_json::from_str::<()>("invalid base64").unwrap_err(),
                    )
                })?;
                // Decrypt the bytes using AES decryption
                let decrypted_bytes = self.decrypt_data(&encrypted_bytes).await?;
                Ok(Some(VaultValue::from_bytes(decrypted_bytes)))
            }
            None => Ok(None), // Key not found is not an error for get, return None
        }
    }

    pub(crate) async fn delete_impl(&self, key: &str) -> VaultResult<()> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        let query = "DELETE FROM vault_entries WHERE key = $key";
        let db = self.dao.db();
        let key = key.to_string(); // Clone to satisfy 'static lifetime

        // Execute the delete query
        let mut result = db
            .query(query)
            .bind(("key", key))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        // Check if any records were returned (indicates success, even if 0 deleted)
        let _: Option<()> = result
            .take(0) // We don't care about the actual deleted record data
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        Ok(())
        // Note: SurrealDB DELETE doesn't error if the key doesn't exist,
        // so we don't need special NotFound handling here.
    }

    pub(crate) async fn find_impl(&self, pattern: &str) -> VaultResult<Vec<(String, VaultValue)>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Basic wildcard matching for simplicity, adjust if complex regex needed
        let db_pattern = format!("%{}%", pattern.replace('%', "\\%").replace('_', "\\_"));
        let query = "SELECT key, value FROM vault_entries WHERE key LIKE $pattern";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("pattern", db_pattern))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        #[derive(Deserialize)]
        struct KeyValue {
            key: String,
            value: String,
        }

        // Extract the first result set (index 0)
        let entries: Vec<KeyValue> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            // Decode base64 string back to encrypted bytes
            let encrypted_bytes = BASE64_STANDARD.decode(entry.value).map_err(|_| {
                VaultError::Serialization(serde_json::from_str::<()>("invalid base64").unwrap_err())
            })?;
            // Decrypt the bytes using AES decryption
            let decrypted_bytes = self.decrypt_data(&encrypted_bytes).await?;
            results.push((entry.key, VaultValue::from_bytes(decrypted_bytes)));
        }

        Ok(results)
    }

    pub(crate) async fn list_impl(&self, prefix: Option<&str>) -> VaultResult<Vec<String>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        let query = if prefix.is_some() {
            // Use STARTSWITH for prefix filtering
            "SELECT key FROM vault_entries WHERE string::startsWith(key, $prefix)"
        } else {
            "SELECT key FROM vault_entries"
        };
        let db = self.dao.db();

        let mut query_builder = db.query(query);
        if let Some(p) = prefix {
            let p = p.to_string(); // Clone to satisfy 'static lifetime
            query_builder = query_builder.bind(("prefix", p));
        }

        let mut result = query_builder
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        #[derive(Deserialize)]
        struct KeyOnly {
            key: String,
        }

        // Extract the first result set (index 0)
        let keys_only: Vec<KeyOnly> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        let keys = keys_only.into_iter().map(|k| k.key).collect();
        Ok(keys)
    }

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
        let exists = self.get_impl(&key).await?;
        if exists.is_some() {
            return Ok(false); // Key already exists
        }

        // Attempt to put the value
        match self.put_impl(key, value).await {
            Ok(_) => Ok(true), // Inserted successfully
            Err(VaultError::Provider(e)) if e.contains("unique index") => {
                // If the error is due to the unique index (race condition hit), treat as non-insertion
                Ok(false)
            }
            Err(e) => Err(e), // Propagate other errors
        }
    }

    pub(crate) async fn put_all_impl(&self, entries: Vec<(String, VaultValue)>) -> VaultResult<()> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Note: This is not atomic. If one put fails, others might have succeeded.
        // Consider using SurrealDB transactions if atomicity is required.
        for (key, value) in entries {
            // Need to clone key and value for each iteration if they are consumed by put_impl
            self.put_impl(key.clone(), value.clone()).await?;
        }
        Ok(())
    }

    // --- Namespace methods remain specific to this provider ---

    /// Creates a new namespace for vault entries
    pub async fn create_namespace(&self, namespace: String) -> Result<(), DaoError> {
        // Define namespace in SurrealDB
        let query = "DEFINE NAMESPACE $namespace";
        let db = self.dao.db();

        db.query(query)
            .bind(("namespace", namespace))
            .await
            .map_err(|e| DaoError::Database(e.to_string()))?;

        Ok(())
    }

    /// Store a value with a specific namespace
    pub async fn put_with_namespace(
        &self,
        namespace: String,
        key: String,
        value: VaultValue, // Accept VaultValue
    ) -> Result<(), DaoError> {
        // Encrypt VaultValue bytes using AES encryption
        let encrypted_value = self
            .encrypt_data(value.expose_secret())
            .await
            .map_err(|e| DaoError::Database(format!("Encryption failed: {}", e)))?;
        let value_b64 = BASE64_STANDARD.encode(encrypted_value);

        let entry = VaultEntry {
            id: Some(format!("entry:{}:{}", namespace, key.replace('/', "_"))),
            key,
            value: value_b64, // Store encoded string
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            namespace: Some(namespace),
        };

        // Use the generic DAO trait
        let mut stream = GenericDao::create(&self.dao, entry);
        let mut items = Vec::new();

        while let Some(result) = stream.next().await {
            match result {
                Ok(item) => items.push(item),
                Err(e) => return Err(e),
            }
        }

        if items.is_empty() {
            return Err(DaoError::Database("Failed to create vault entry".into()));
        }

        Ok(())
    }

    /// Get all entries in a namespace
    pub async fn get_by_namespace(
        &self,
        namespace: String,
    ) -> Result<Vec<(String, VaultValue)>, DaoError> {
        let query = "SELECT key, value FROM vault_entries WHERE namespace = $namespace";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("namespace", namespace))
            .await
            .map_err(|e| DaoError::Database(e.to_string()))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| DaoError::Database(e.to_string()))?;

        #[derive(Deserialize)]
        struct KeyValue {
            key: String,
            value: String,
        }
        // Extract the first result set (index 0)
        let entries: Vec<KeyValue> = result
            .take(0)
            .map_err(|e| DaoError::Database(e.to_string()))?;

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            // Decode base64 string back to encrypted bytes
            let encrypted_bytes = BASE64_STANDARD
                .decode(entry.value)
                .map_err(|e| DaoError::Serialization(format!("Base64 decode error: {}", e)))?;
            // Decrypt the bytes using AES decryption
            let decrypted_bytes = self
                .decrypt_data(&encrypted_bytes)
                .await
                .map_err(|e| DaoError::Database(format!("Decryption failed: {}", e)))?;
            results.push((entry.key, VaultValue::from_bytes(decrypted_bytes)));
        }

        Ok(results)
    }

    /// Get or create salt for key derivation
    pub(crate) async fn get_or_create_salt(&self) -> VaultResult<Vec<u8>> {
        use rand::RngCore;
        use tokio::fs;

        // Try to read existing salt
        match fs::read(&self.config.salt_path).await {
            Ok(salt) => {
                if salt.len() >= 16 {
                    // Minimum 16 bytes for salt
                    Ok(salt)
                } else {
                    Err(VaultError::Crypto(
                        "Salt file corrupted: insufficient length".to_string(),
                    ))
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Generate new salt
                let mut salt = vec![0u8; 32]; // 32 bytes salt
                rand::rng().fill_bytes(&mut salt);

                // Ensure parent directory exists
                if let Some(parent) = self.config.salt_path.parent() {
                    fs::create_dir_all(parent)
                        .await
                        .map_err(|e| VaultError::Io(e))?;
                }

                // Write salt to file
                fs::write(&self.config.salt_path, &salt)
                    .await
                    .map_err(|e| VaultError::Io(e))?;

                // Set restrictive permissions on Unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o600);
                    std::fs::set_permissions(&self.config.salt_path, perms)
                        .map_err(|e| VaultError::Io(e))?;
                }

                log::info!(
                    "Generated new salt file at: {}",
                    self.config.salt_path.display()
                );
                Ok(salt)
            }
            Err(e) => Err(VaultError::Io(e)),
        }
    }
}

// --- VaultOperation Implementation ---

impl VaultOperation for LocalVaultProvider {
    fn name(&self) -> &str {
        "Local Vault Provider"
    }

    // Check if the vault is locked
    fn is_locked(&self) -> bool {
        // Use sync mutex to avoid runtime issues
        match self.locked.lock() {
            Ok(guard) => *guard,
            Err(_) => {
                // If mutex is poisoned, assume locked for safety
                true
            }
        }
    }

    // Unlock the vault with a passphrase
    fn unlock(&self, passphrase: &Passphrase) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let passphrase_clone = passphrase.clone();

        tokio::spawn(async move {
            let result = provider_clone.unlock_impl(passphrase_clone).await;
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
            let result = provider_clone.put_impl(key, value).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn get(&self, key: &str) -> VaultGetRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone.get_impl(&key).await;
            let _ = tx.send(result);
        });

        VaultGetRequest::new(rx)
    }

    fn delete(&self, key: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone.delete_impl(&key).await;
            // Don't treat NotFound as an error for delete
            let final_result = match result {
                Err(VaultError::ItemNotFound) => Ok(()),
                other => other,
            };
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
        // This avoids block_on which causes runtime crashes
        !self.config.vault_path.exists()
    }
}
