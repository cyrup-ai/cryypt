//! Basic CRUD operations for vault entries

use super::super::super::{LocalVaultProvider, VaultEntry, map_dao_error, BackupRestoreOptions, BackupRestoreStats, KeyRotationStats, KeyRotationTestStats};
use crate::core::VaultValue;
use crate::db::dao::GenericDao;
use crate::error::{VaultError, VaultResult};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use futures::StreamExt;
use serde::Deserialize;

impl LocalVaultProvider {
    /// Store a key-value pair in the vault (public API)
    pub async fn put(&self, key: &str, value: &VaultValue) -> VaultResult<()> {
        self.put_impl(key.to_string(), value.clone()).await
    }

    /// Store a key-value pair in the vault
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
            metadata: value.metadata().cloned(), // Persist metadata from VaultValue
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            expires_at: None, // No expiry for regular put operations
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

    /// Retrieve a value by key from the vault (public API)
    pub async fn get(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        self.get_impl(key).await
    }

    /// Retrieve a value by key from the vault
    pub(crate) async fn get_impl(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        let query = "SELECT value, metadata FROM vault_entries WHERE key = $key LIMIT 1";
        let db = self.dao.db();
        let key = key.to_string(); // Clone to satisfy 'static lifetime

        let mut result = db
            .query(query)
            .bind(("key", key))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        // Select both value and metadata
        #[derive(Deserialize)]
        struct ValueWithMetadata {
            value: String,
            metadata: Option<serde_json::Value>,
        }

        // Extract the first result set (index 0)
        let value_entry: Option<ValueWithMetadata> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        match value_entry {
            Some(entry) => {
                // Decode base64 string back to encrypted bytes
                let encrypted_bytes = BASE64_STANDARD.decode(entry.value)
                    .map_err(|e| VaultError::Decryption(format!("Base64 decode failed: {}", e)))?;
                // Decrypt the bytes using AES decryption
                let decrypted_bytes = self.decrypt_data(&encrypted_bytes).await?;
                
                // Create VaultValue from decrypted bytes
                let mut vault_value = VaultValue::from_bytes(decrypted_bytes);
                
                // If metadata exists, convert it back to the format VaultValue expects
                if let Some(metadata_json) = entry.metadata {
                    // VaultValue expects a HashMap<String, String> format for metadata
                    if let Some(metadata_obj) = metadata_json.as_object() {
                        let mut metadata_map = std::collections::HashMap::new();
                        for (key, value) in metadata_obj {
                            if let Some(value_str) = value.as_str() {
                                metadata_map.insert(key.clone(), value_str.to_string());
                            }
                        }
                        if !metadata_map.is_empty() {
                            vault_value = vault_value.with_metadata(metadata_map);
                        }
                    }
                }
                
                Ok(Some(vault_value))
            }
            None => Ok(None), // Key not found is not an error for get, return None
        }
    }

    /// Delete a key from the vault (public API)
    pub async fn delete(&self, key: &str) -> VaultResult<()> {
        self.delete_impl(key).await
    }

    /// Delete a key from the vault
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

    /// Store a key-value pair with expiry time
    pub async fn put_with_expiry(
        &self,
        key: &str,
        value: &VaultValue,
        expiry: std::time::SystemTime,
    ) -> VaultResult<()> {
        use chrono::{DateTime, Utc};

        // Convert SystemTime to DateTime<Utc>
        let expires_at: DateTime<Utc> = expiry.into();
        
        // Encrypt the value data using the session key
        let encrypted_value = self.encrypt_data(value.expose_secret()).await?;
        let encoded_value = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, encrypted_value);

        // Create the vault entry with expiration
        let entry = VaultEntry {
            id: None,
            key: key.to_string(),
            value: encoded_value,
            metadata: value.metadata().cloned(), // Persist metadata from VaultValue
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            expires_at: Some(expires_at),
            namespace: None,
        };

        // Use SurrealDB UPSERT to insert or update with expiry
        let db = self.dao.db();
        let query = "
            UPSERT vault_entries SET 
                key = $key,
                value = $value,
                metadata = $metadata,
                created_at = $created_at,
                updated_at = $updated_at,
                expires_at = $expires_at,
                namespace = $namespace
            WHERE key = $key
        ";

        let mut result = db
            .query(query)
            .bind(("key", entry.key.clone()))
            .bind(("value", entry.value.clone()))
            .bind(("metadata", entry.metadata.clone()))
            .bind(("created_at", entry.created_at))
            .bind(("updated_at", entry.updated_at))
            .bind(("expires_at", entry.expires_at))
            .bind(("namespace", entry.namespace))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to upsert with TTL: {}", e)))?;

        // Verify the operation succeeded
        let _: Option<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        Ok(())
    }

    /// Get value with expiry check - returns None if expired
    pub async fn get_with_expiry_check(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        use chrono::Utc;

        let db = self.dao.db();
        let now = Utc::now();

        // Query with expiry check - SurrealDB 2.3.7 time-based filtering
        let query = "
            SELECT * FROM vault_entries 
            WHERE key = $key 
            AND (expires_at IS NONE OR expires_at > $now)
            LIMIT 1
        ";

        let mut result = db
            .query(query)
            .bind(("key", key.to_string()))
            .bind(("now", now))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to query with expiry check: {}", e)))?;

        let entries: Vec<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        match entries.into_iter().next() {
            Some(entry) => {
                // Decrypt the value
                let decoded_value = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &entry.value)
                    .map_err(|e| VaultError::Decryption(format!("Base64 decode failed: {}", e)))?;
                
                let decrypted_value = self.decrypt_data(&decoded_value).await?;
                
                // Convert to VaultValue with metadata restoration
                let mut vault_value = VaultValue::from_bytes(decrypted_value);
                
                // Restore metadata if present
                if let Some(metadata_json) = entry.metadata {
                    if let Some(metadata_obj) = metadata_json.as_object() {
                        let mut metadata_map = std::collections::HashMap::new();
                        for (key, value) in metadata_obj {
                            if let Some(value_str) = value.as_str() {
                                metadata_map.insert(key.clone(), value_str.to_string());
                            }
                        }
                        if !metadata_map.is_empty() {
                            vault_value = vault_value.with_metadata(metadata_map);
                        }
                    }
                }
                
                Ok(Some(vault_value))
            }
            None => Ok(None), // Either doesn't exist or expired
        }
    }

    /// Update expiry time for a key
    pub async fn update_expiry(
        &self,
        key: &str,
        expiry: std::time::SystemTime,
    ) -> VaultResult<()> {
        use chrono::{DateTime, Utc};
        let db = self.dao.db();
        let expiry_dt: DateTime<Utc> = expiry.into();
        
        let query = "UPDATE vault_entries SET expires_at = $expires_at WHERE key = $key";
        let key_owned = key.to_string();
        let mut result = db
            .query(query)
            .bind(("key", key_owned))
            .bind(("expires_at", expiry_dt))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;
            
        let _: Option<()> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;
            
        Ok(())
    }

    /// Remove expiry from a key
    pub async fn remove_expiry(&self, key: &str) -> VaultResult<()> {
        let db = self.dao.db();
        let query = "UPDATE vault_entries SET expires_at = NULL WHERE key = $key";
        let key_owned = key.to_string();
        
        let mut result = db
            .query(query)
            .bind(("key", key_owned))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;
            
        let _: Option<()> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;
            
        Ok(())
    }

    /// Re-encrypt vault with new passphrase
    pub async fn re_encrypt_with_new_passphrase(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> VaultResult<()> {
        let db = self.dao.db();
        
        // Get all vault entries
        let entries: Vec<VaultEntry> = db
            .select("vault_entries")
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to get entries: {}", e)))?;
            
        // Re-encrypt each entry
        for entry in entries {
            // Decrypt current value using existing decryption with old passphrase
            let encrypted_bytes = base64::engine::general_purpose::STANDARD
                .decode(&entry.value)
                .map_err(|_| VaultError::Provider("Invalid base64 in entry".to_string()))?;
                
            let decrypted_bytes = self.decrypt_data_with_passphrase(&encrypted_bytes, old_passphrase).await?;
            let re_encrypted_bytes = self.encrypt_data_with_passphrase(&decrypted_bytes, new_passphrase).await?;
            let value_b64 = base64::engine::general_purpose::STANDARD.encode(re_encrypted_bytes);
            
            // Update entry in database
            let query = "UPDATE vault_entries SET value = $value WHERE key = $key";
            let key_owned = entry.key.clone();
            let mut result = db
                .query(query)
                .bind(("key", key_owned))
                .bind(("value", value_b64))
                .await
                .map_err(|e| VaultError::Provider(format!("Failed to update entry: {}", e)))?
                .check()
                .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;
                
            let _: Option<()> = result
                .take(0)
                .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;
        }
        
        Ok(())
    }

    /// Decrypt data using specific passphrase (internal helper)
    async fn decrypt_data_with_passphrase(&self, encrypted_data: &[u8], passphrase: &str) -> VaultResult<Vec<u8>> {
        // Use AES-256-GCM decryption with the specified passphrase-derived key
        use crate::operation::Passphrase;
        let passphrase_secret = Passphrase::new(passphrase.to_string().into());
        let key = self.derive_encryption_key(&passphrase_secret).await?;

        // Validate input data before attempting decryption
        if encrypted_data.len() < 32 {
            let error_msg = format!(
                "Re-encryption: invalid encrypted data size ({} bytes, minimum 32 required)", 
                encrypted_data.len()
            );
            log::error!("{}", error_msg);
            return Err(VaultError::Decryption(error_msg));
        }

        // Use AES decryption with the passphrase-derived key
        let decrypted_data = cryypt_cipher::Cryypt::cipher()
            .aes()
            .with_key(key.clone())
            .on_result(|result| match result {
                Ok(data) => data,
                Err(error) => {
                    log::error!("passphrase decryption failed: {}", error);
                    Vec::new()
                }
            })
            .decrypt(encrypted_data.to_vec())
            .await;

        if decrypted_data.is_empty() {
            let detailed_error = format!(
                "Passphrase decryption failed - input size: {} bytes, key size: {} bytes, possible cause: wrong old passphrase", 
                encrypted_data.len(),
                key.len()
            );
            log::error!("Re-encryption decrypt failed: {}", detailed_error);
            return Err(VaultError::Decryption(detailed_error));
        }

        Ok(decrypted_data)
    }
    
    /// Encrypt data using specific passphrase (internal helper)
    async fn encrypt_data_with_passphrase(&self, data: &[u8], passphrase: &str) -> VaultResult<Vec<u8>> {
        // Use AES-256-GCM encryption with the specified passphrase-derived key
        use crate::operation::Passphrase;
        let passphrase_secret = Passphrase::new(passphrase.to_string().into());
        let key = self.derive_encryption_key(&passphrase_secret).await?;

        log::trace!("Re-encrypting {} bytes with new passphrase", data.len());

        // Use AES encryption with the passphrase-derived key
        let encrypted_data = cryypt_cipher::Cryypt::cipher()
            .aes()
            .with_key(key.clone())
            .on_result(|result| match result {
                Ok(data) => data,
                Err(error) => {
                    log::error!("passphrase encryption failed: {}", error);
                    Vec::new()
                }
            })
            .encrypt(data.to_vec())
            .await;

        if encrypted_data.is_empty() {
            let detailed_error = format!(
                "Passphrase encryption failed - input size: {} bytes, key size: {} bytes",
                data.len(),
                key.len()
            );
            log::error!("Re-encryption encrypt failed: {}", detailed_error);
            return Err(VaultError::Encryption(detailed_error));
        }

        log::trace!("Re-encryption completed successfully, output: {} bytes", encrypted_data.len());
        Ok(encrypted_data)
    }

    /// Clean up expired entries from the vault
    pub async fn cleanup_expired_entries(&self) -> VaultResult<u64> {
        use chrono::Utc;
        
        let db = self.dao.db();
        let now = Utc::now();
        
        log::debug!("Starting cleanup of expired vault entries at {}", now);
        
        // Query to delete expired entries and return them for accurate counting
        let query = "DELETE FROM vault_entries WHERE expires_at IS NOT NULL AND expires_at <= $now RETURN *";
        
        let mut result = db
            .query(query)
            .bind(("now", now))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to cleanup expired entries: {}", e)))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed during cleanup: {}", e)))?;
            
        // Count how many entries were deleted - now accurately returns deleted records
        let deleted_entries: Vec<serde_json::Value> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to get cleanup results: {}", e)))?;
            
        let deleted_count = deleted_entries.len() as u64;
        
        if deleted_count > 0 {
            log::info!("TTL cleanup: removed {} expired vault entries", deleted_count);
        } else {
            log::debug!("TTL cleanup: no expired entries found");
        }
        
        Ok(deleted_count)
    }

    /// Run periodic TTL cleanup task
    pub async fn start_ttl_cleanup_task(&self, cleanup_interval_seconds: u64) {
        use tokio::time::{interval, Duration};
        
        let cleanup_interval = Duration::from_secs(cleanup_interval_seconds);
        let mut cleanup_timer = interval(cleanup_interval);
        
        log::info!("Starting TTL cleanup task with {} second intervals", cleanup_interval_seconds);
        
        loop {
            cleanup_timer.tick().await;
            
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
    pub async fn get_expired_entries_stats(&self) -> VaultResult<u64> {
        use chrono::Utc;
        
        let db = self.dao.db();
        let now = Utc::now();
        
        // Count expired entries
        let query = "SELECT COUNT() AS count FROM vault_entries WHERE expires_at IS NOT NULL AND expires_at <= $now GROUP ALL";
        
        #[derive(serde::Deserialize)]
        struct CountResult {
            count: u64,
        }
        
        let mut result = db
            .query(query)
            .bind(("now", now))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to count expired entries: {}", e)))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;
            
        let count_result: Option<CountResult> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to get count results: {}", e)))?;
            
        Ok(count_result.map(|r| r.count).unwrap_or(0))
    }

    /// Create encrypted backup of all vault entries
    pub async fn create_encrypted_backup(&self, backup_passphrase: &str) -> VaultResult<Vec<u8>> {
        use chrono::Utc;
        use serde::{Serialize, Deserialize};
        
        // Check if vault is unlocked
        self.check_unlocked().await?;
        
        log::info!("Creating encrypted vault backup");
        
        let db = self.dao.db();
        
        // Get all vault entries (including expired ones for backup purposes)
        let entries: Vec<VaultEntry> = db
            .select("vault_entries")
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to get entries for backup: {}", e)))?;
            
        log::debug!("Backup: found {} entries to backup", entries.len());
        
        #[derive(Serialize, Deserialize)]
        struct BackupData {
            version: String,
            timestamp: chrono::DateTime<Utc>,
            entries: Vec<VaultEntry>,
            metadata: std::collections::HashMap<String, String>,
        }
        
        // Create backup metadata
        let mut backup_metadata = std::collections::HashMap::new();
        backup_metadata.insert("created_by".to_string(), "cryypt_vault".to_string());
        backup_metadata.insert("entry_count".to_string(), entries.len().to_string());
        backup_metadata.insert("backup_type".to_string(), "full".to_string());
        
        let backup_data = BackupData {
            version: "1.0".to_string(),
            timestamp: Utc::now(),
            entries,
            metadata: backup_metadata,
        };
        
        // Serialize backup data to JSON
        let backup_json = serde_json::to_vec(&backup_data)
            .map_err(|e| VaultError::Serialization(e))?;
        
        log::debug!("Backup: serialized {} bytes of JSON data", backup_json.len());
        
        // Encrypt backup with provided passphrase
        let encrypted_backup = self.encrypt_data_with_passphrase(&backup_json, backup_passphrase).await?;
        
        log::info!("Backup: created encrypted backup ({} bytes)", encrypted_backup.len());
        
        Ok(encrypted_backup)
    }

    /// Restore vault from encrypted backup
    pub async fn restore_from_encrypted_backup(
        &self, 
        encrypted_backup: &[u8], 
        backup_passphrase: &str,
        restore_options: BackupRestoreOptions,
    ) -> VaultResult<BackupRestoreStats> {
        use serde::{Serialize, Deserialize};
        
        // Check if vault is unlocked
        self.check_unlocked().await?;
        
        log::info!("Restoring vault from encrypted backup");
        
        // Decrypt backup data
        let backup_json = self.decrypt_data_with_passphrase(encrypted_backup, backup_passphrase).await?;
        
        log::debug!("Backup: decrypted {} bytes of backup data", backup_json.len());
        
        #[derive(Serialize, Deserialize)]
        struct BackupData {
            version: String,
            timestamp: chrono::DateTime<chrono::Utc>,
            entries: Vec<VaultEntry>,
            metadata: std::collections::HashMap<String, String>,
        }
        
        // Deserialize backup data
        let backup_data: BackupData = serde_json::from_slice(&backup_json)
            .map_err(|e| VaultError::Serialization(e))?;
            
        log::info!(
            "Backup: restoring backup version {} from {} with {} entries",
            backup_data.version,
            backup_data.timestamp,
            backup_data.entries.len()
        );
        
        let mut stats = BackupRestoreStats {
            entries_processed: 0,
            entries_restored: 0,
            entries_skipped: 0,
            entries_failed: 0,
        };
        
        let db = self.dao.db();
        
        for entry in backup_data.entries {
            stats.entries_processed += 1;
            
            // Check if entry already exists
            let existing_query = "SELECT id FROM vault_entries WHERE key = $key LIMIT 1";
            let mut result = db
                .query(existing_query)
                .bind(("key", entry.key.clone()))
                .await
                .map_err(|e| VaultError::Provider(format!("Failed to check existing entry: {}", e)))?;
                
            let existing_entry: Option<serde_json::Value> = result
                .take(0)
                .map_err(|e| VaultError::Provider(format!("Failed to parse existing entry check: {}", e)))?;
                
            if existing_entry.is_some() && !restore_options.overwrite_existing {
                log::debug!("Skipping existing entry: {}", entry.key);
                stats.entries_skipped += 1;
                continue;
            }
            
            // Insert or update entry
            let upsert_query = "
                UPSERT vault_entries SET 
                    key = $key,
                    value = $value,
                    metadata = $metadata,
                    created_at = $created_at,
                    updated_at = $updated_at,
                    expires_at = $expires_at,
                    namespace = $namespace
                WHERE key = $key
            ";
            
            match db
                .query(upsert_query)
                .bind(("key", entry.key.clone()))
                .bind(("value", entry.value))
                .bind(("metadata", entry.metadata))
                .bind(("created_at", entry.created_at))
                .bind(("updated_at", entry.updated_at))
                .bind(("expires_at", entry.expires_at))
                .bind(("namespace", entry.namespace))
                .await
            {
                Ok(_) => {
                    log::trace!("Restored entry: {}", entry.key);
                    stats.entries_restored += 1;
                }
                Err(e) => {
                    log::error!("Failed to restore entry {}: {}", entry.key, e);
                    stats.entries_failed += 1;
                }
            }
        }
        
        log::info!(
            "Backup restore completed: {} processed, {} restored, {} skipped, {} failed",
            stats.entries_processed,
            stats.entries_restored,
            stats.entries_skipped,
            stats.entries_failed
        );
        
        Ok(stats)
    }

    /// Export vault entries to unencrypted JSON for debugging (vault must be unlocked)
    pub async fn export_to_json_debug(&self) -> VaultResult<String> {
        use serde::{Serialize, Deserialize};
        
        // Check if vault is unlocked
        self.check_unlocked().await?;
        
        log::warn!("Creating UNENCRYPTED debug export - use only for debugging!");
        
        let db = self.dao.db();
        
        // Get all vault entries
        let entries: Vec<VaultEntry> = db
            .select("vault_entries")
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to get entries for debug export: {}", e)))?;
            
        #[derive(Serialize, Deserialize)]
        struct DebugExport {
            warning: String,
            version: String,
            timestamp: chrono::DateTime<chrono::Utc>,
            entries: Vec<DebugEntry>,
        }
        
        #[derive(Serialize, Deserialize)]
        struct DebugEntry {
            key: String,
            value_preview: String, // Only first 50 chars
            metadata: Option<serde_json::Value>,
            created_at: Option<chrono::DateTime<chrono::Utc>>,
            expires_at: Option<chrono::DateTime<chrono::Utc>>,
            namespace: Option<String>,
        }
        
        let mut debug_entries = Vec::new();
        
        for entry in entries {
            // Decrypt the value to show preview
            let preview = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &entry.value) {
                Ok(encrypted_bytes) => {
                    match self.decrypt_data(&encrypted_bytes).await {
                        Ok(decrypted) => {
                            let value_str = String::from_utf8_lossy(&decrypted);
                            if value_str.len() > 50 {
                                format!("{}...", &value_str[..50])
                            } else {
                                value_str.to_string()
                            }
                        }
                        Err(_) => "<decryption_failed>".to_string()
                    }
                }
                Err(_) => "<invalid_base64>".to_string()
            };
            
            debug_entries.push(DebugEntry {
                key: entry.key,
                value_preview: preview,
                metadata: entry.metadata,
                created_at: entry.created_at,
                expires_at: entry.expires_at,
                namespace: entry.namespace,
            });
        }
        
        let debug_export = DebugExport {
            warning: "THIS IS AN UNENCRYPTED DEBUG EXPORT - DO NOT SHARE".to_string(),
            version: "1.0".to_string(),
            timestamp: chrono::Utc::now(),
            entries: debug_entries,
        };
        
        serde_json::to_string_pretty(&debug_export)
            .map_err(|e| VaultError::Serialization(e))
    }

    /// Rotate vault encryption key - re-encrypts all entries with a new derived key
    pub async fn rotate_encryption_key(
        &self,
        current_passphrase: &str,
        new_passphrase: &str,
    ) -> VaultResult<KeyRotationStats> {
        // Check if vault is unlocked
        self.check_unlocked().await?;
        
        log::info!("Starting encryption key rotation");
        
        let db = self.dao.db();
        
        // Get all vault entries
        let entries: Vec<VaultEntry> = db
            .select("vault_entries")
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to get entries for key rotation: {}", e)))?;
            
        log::info!("Key rotation: processing {} entries", entries.len());
        
        let mut stats = KeyRotationStats {
            entries_processed: 0,
            entries_rotated: 0,
            entries_failed: 0,
            old_salt_used: false,
            new_salt_created: true,
        };
        
        // Step 1: Verify current passphrase by trying to decrypt a test entry
        if let Some(test_entry) = entries.first() {
            log::debug!("Verifying current passphrase with test decryption");
            
            let encrypted_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &test_entry.value)
                .map_err(|e| VaultError::KeyRotation(format!("Invalid base64 in test entry: {}", e)))?;
            
            // Try to decrypt with current passphrase
            match self.decrypt_data_with_passphrase(&encrypted_bytes, current_passphrase).await {
                Ok(_) => {
                    log::debug!("Current passphrase verified successfully");
                }
                Err(e) => {
                    return Err(VaultError::KeyRotation(format!("Current passphrase verification failed: {}", e)));
                }
            }
        }
        
        // Step 2: Generate new salt for the new passphrase
        log::info!("Generating new salt for key rotation");
        let new_salt = self.generate_new_rotation_salt().await?;
        
        // Step 3: Re-encrypt all entries
        for entry in entries {
            stats.entries_processed += 1;
            
            log::trace!("Rotating key for entry: {}", entry.key);
            
            // Decrypt with old passphrase
            let encrypted_bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &entry.value) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("Failed to decode base64 for entry {}: {}", entry.key, e);
                    stats.entries_failed += 1;
                    continue;
                }
            };
            
            let decrypted_data = match self.decrypt_data_with_passphrase(&encrypted_bytes, current_passphrase).await {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Failed to decrypt entry {} with current passphrase: {}", entry.key, e);
                    stats.entries_failed += 1;
                    continue;
                }
            };
            
            // Re-encrypt with new passphrase
            let re_encrypted_data = match self.encrypt_data_with_passphrase(&decrypted_data, new_passphrase).await {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Failed to re-encrypt entry {} with new passphrase: {}", entry.key, e);
                    stats.entries_failed += 1;
                    continue;
                }
            };
            
            let new_value_b64 = base64::engine::general_purpose::STANDARD.encode(re_encrypted_data);
            
            // Update entry in database
            let update_query = "UPDATE vault_entries SET value = $value, updated_at = $updated_at WHERE key = $key";
            
            match db
                .query(update_query)
                .bind(("key", entry.key.clone()))
                .bind(("value", new_value_b64))
                .bind(("updated_at", chrono::Utc::now()))
                .await
            {
                Ok(_) => {
                    log::trace!("Successfully rotated key for entry: {}", entry.key);
                    stats.entries_rotated += 1;
                }
                Err(e) => {
                    log::error!("Failed to update entry {} in database: {}", entry.key, e);
                    stats.entries_failed += 1;
                }
            }
        }
        
        // Step 4: Replace old salt with new salt
        log::info!("Replacing old salt file with new salt");
        match self.replace_salt_file(&new_salt).await {
            Ok(_) => {
                log::info!("Salt file successfully updated");
            }
            Err(e) => {
                log::error!("Failed to update salt file: {}", e);
                // This is concerning but not fatal - the rotation already happened
            }
        }
        
        // Step 5: Update session with new encryption key
        log::info!("Updating session with new encryption key");
        if let Err(e) = self.update_session_key_after_rotation(new_passphrase).await {
            log::error!("Failed to update session key: {}", e);
        }
        
        log::info!(
            "Key rotation completed: {} processed, {} rotated, {} failed",
            stats.entries_processed,
            stats.entries_rotated,
            stats.entries_failed
        );
        
        Ok(stats)
    }

    /// Generate new salt for key rotation
    async fn generate_new_rotation_salt(&self) -> VaultResult<Vec<u8>> {
        use rand::RngCore;
        
        let mut new_salt = vec![0u8; 32]; // 32 bytes salt
        rand::rng().fill_bytes(&mut new_salt);
        
        log::debug!("Generated new {} byte salt for rotation", new_salt.len());
        
        Ok(new_salt)
    }

    /// Replace the current salt file with a new salt
    async fn replace_salt_file(&self, new_salt: &[u8]) -> VaultResult<()> {
        use tokio::fs;
        
        // Create backup of old salt
        let backup_salt_path = self.config.salt_path.with_extension("salt.backup");
        if self.config.salt_path.exists() {
            if let Err(e) = fs::copy(&self.config.salt_path, &backup_salt_path).await {
                log::warn!("Failed to backup old salt file: {}", e);
            } else {
                log::debug!("Old salt backed up to: {}", backup_salt_path.display());
            }
        }
        
        // Write new salt
        fs::write(&self.config.salt_path, new_salt)
            .await
            .map_err(VaultError::Io)?;
        
        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.config.salt_path, perms)
                .map_err(VaultError::Io)?;
        }
        
        log::info!("Salt file replaced at: {}", self.config.salt_path.display());
        
        Ok(())
    }

    /// Update session encryption key after rotation
    async fn update_session_key_after_rotation(&self, new_passphrase: &str) -> VaultResult<()> {
        use crate::operation::Passphrase;
        
        // Create new passphrase secret
        let new_passphrase_secret = Passphrase::new(new_passphrase.to_string().into());
        
        // Derive new encryption key
        let new_key = self.derive_encryption_key(&new_passphrase_secret).await?;
        
        // Update session passphrase
        {
            let mut passphrase_guard = self.passphrase.lock().await;
            *passphrase_guard = Some(new_passphrase_secret);
        }
        
        // Update session encryption key
        {
            let mut key_guard = self.encryption_key.lock().await;
            *key_guard = Some(new_key);
        }
        
        log::debug!("Session updated with new encryption key");
        
        Ok(())
    }

    /// Test key rotation by performing a dry run
    pub async fn test_key_rotation(
        &self,
        current_passphrase: &str,
        new_passphrase: &str,
    ) -> VaultResult<KeyRotationTestStats> {
        // Check if vault is unlocked
        self.check_unlocked().await?;
        
        log::info!("Starting key rotation test (dry run)");
        
        let db = self.dao.db();
        
        // Get first 5 entries as a sample
        let sample_entries: Vec<VaultEntry> = db
            .query("SELECT * FROM vault_entries LIMIT 5")
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to get sample entries: {}", e)))?
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to parse sample entries: {}", e)))?;
            
        log::debug!("Testing key rotation with {} sample entries", sample_entries.len());
        
        let mut stats = KeyRotationTestStats {
            sample_entries_tested: 0,
            successful_decryptions: 0,
            successful_re_encryptions: 0,
            failed_operations: 0,
        };
        
        for entry in sample_entries {
            stats.sample_entries_tested += 1;
            
            log::trace!("Testing rotation for sample entry: {}", entry.key);
            
            // Test decryption with current passphrase
            let encrypted_bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &entry.value) {
                Ok(bytes) => bytes,
                Err(_) => {
                    stats.failed_operations += 1;
                    continue;
                }
            };
            
            let decrypted_data = match self.decrypt_data_with_passphrase(&encrypted_bytes, current_passphrase).await {
                Ok(data) => {
                    stats.successful_decryptions += 1;
                    data
                }
                Err(_) => {
                    stats.failed_operations += 1;
                    continue;
                }
            };
            
            // Test re-encryption with new passphrase
            match self.encrypt_data_with_passphrase(&decrypted_data, new_passphrase).await {
                Ok(_) => {
                    stats.successful_re_encryptions += 1;
                }
                Err(_) => {
                    stats.failed_operations += 1;
                }
            }
        }
        
        log::info!(
            "Key rotation test completed: {} tested, {} decrypt OK, {} re-encrypt OK, {} failed",
            stats.sample_entries_tested,
            stats.successful_decryptions,
            stats.successful_re_encryptions,
            stats.failed_operations
        );
        
        Ok(stats)
    }
}
