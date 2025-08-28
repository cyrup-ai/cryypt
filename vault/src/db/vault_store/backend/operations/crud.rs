//! Basic CRUD operations for vault entries

use super::super::super::{LocalVaultProvider, VaultEntry, map_dao_error};
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
                let encrypted_bytes = BASE64_STANDARD.decode(entry.value)
                    .map_err(|e| VaultError::Decryption(format!("Base64 decode failed: {}", e)))?;
                // Decrypt the bytes using AES decryption
                let decrypted_bytes = self.decrypt_data(&encrypted_bytes).await?;
                Ok(Some(VaultValue::from_bytes(decrypted_bytes)))
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
                
                // Convert to VaultValue
                let value_string = String::from_utf8(decrypted_value)
                    .map_err(|e| VaultError::Decryption(format!("UTF-8 decode failed: {}", e)))?;
                
                Ok(Some(VaultValue::from_string(value_string)))
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

        // Use AES decryption with the passphrase-derived key
        let decrypted_data = cryypt_cipher::Cryypt::cipher()
            .aes()
            .with_key(key)
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
            return Err(VaultError::Decryption("Passphrase decryption failed".to_string()));
        }

        Ok(decrypted_data)
    }
    
    /// Encrypt data using specific passphrase (internal helper)
    async fn encrypt_data_with_passphrase(&self, data: &[u8], passphrase: &str) -> VaultResult<Vec<u8>> {
        // Use AES-256-GCM encryption with the specified passphrase-derived key
        use crate::operation::Passphrase;
        let passphrase_secret = Passphrase::new(passphrase.to_string().into());
        let key = self.derive_encryption_key(&passphrase_secret).await?;

        // Use AES encryption with the passphrase-derived key
        let encrypted_data = cryypt_cipher::Cryypt::cipher()
            .aes()
            .with_key(key)
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
            return Err(VaultError::Encryption("Passphrase encryption failed".to_string()));
        }

        Ok(encrypted_data)
    }
}
