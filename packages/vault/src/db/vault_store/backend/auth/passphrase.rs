//! Passphrase verification and management operations

use super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use secrecy::ExposeSecret;

impl LocalVaultProvider {
    /// Verify passphrase against stored hash
    pub(crate) async fn verify_passphrase(&self, passphrase: &Passphrase) -> VaultResult<()> {
        log::debug!("VERIFY_PASSPHRASE: Starting passphrase verification...");

        // Try to retrieve stored passphrase hash using direct record ID (consistent with salt retrieval)
        let record_id = "vault_entries:__vault_passphrase_hash__";
        let query = format!("SELECT * FROM {}", record_id);
        let db = self.dao.db();

        log::debug!("VERIFY_PASSPHRASE: Executing query: {}", query);
        let mut result = db
            .query(&query)
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {e}")))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?;

        use super::super::super::VaultEntry;
        let hash_entry: Option<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {e}")))?;

        log::debug!("VERIFY_PASSPHRASE: Query result: {}", if hash_entry.is_some() { "FOUND" } else { "NOT FOUND" });

        match hash_entry {
            Some(entry) => {
                log::debug!("VERIFY_PASSPHRASE: Found existing passphrase hash in database");

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

                let parsed_hash = PasswordHash::new(&stored_hash_str)
                    .map_err(|e| VaultError::Crypto(format!("Invalid stored hash format: {e}")))?;

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
                // No stored hash - need to determine if this is first unlock or missing hash
                log::warn!("VERIFY_PASSPHRASE: No passphrase hash found in database");
                
                // Check if vault has any data entries to distinguish between:
                // 1. Truly new vault (first unlock) - OK to proceed
                // 2. Existing vault with missing hash (security issue) - REJECT
                let count_query = "SELECT count() FROM vault_entries WHERE key != $hash_key GROUP ALL";
                let mut count_result = db
                    .query(count_query)
                    .bind(("hash_key", "__vault_passphrase_hash__"))
                    .await
                    .map_err(|e| VaultError::Provider(format!("Failed to count vault entries: {e}")))?;
                
                #[derive(serde::Deserialize)]
                struct CountResult {
                    count: i64,
                }
                
                let count_vec: Vec<CountResult> = count_result
                    .take(0)
                    .map_err(|e| VaultError::Provider(format!("Failed to get count result: {e}")))?;
                
                let entry_count = count_vec.first().map(|c| c.count).unwrap_or(0);
                
                if entry_count > 0 {
                    // Vault has entries but no hash - this is a security violation
                    // Hash should have been stored on first unlock
                    log::error!("VERIFY_PASSPHRASE: Vault has {} entries but no passphrase hash - REJECTING", entry_count);
                    return Err(VaultError::InvalidPassphrase);
                }
                
                // Empty vault - this is legitimately the first unlock
                log::info!("VERIFY_PASSPHRASE: Empty vault, no hash found - accepting as first unlock");
                Ok(())
            }
        }
    }

    /// Change vault passphrase
    pub(crate) async fn change_passphrase_impl(
        &self,
        old_passphrase: Passphrase,
        new_passphrase: Passphrase,
    ) -> VaultResult<()> {
        // Update passphrase hash in database (also verifies old passphrase)
        self.re_encrypt_with_new_passphrase(
            old_passphrase.expose_secret(),
            new_passphrase.expose_secret(),
        )
        .await?;

        // Update in-memory passphrase if it exists
        let mut passphrase_guard = self.passphrase.lock().await;
        if passphrase_guard.is_some() {
            *passphrase_guard = Some(new_passphrase.clone());
        }
        drop(passphrase_guard);

        // Invalidate JWT session to force re-authentication with new passphrase
        // This prevents old JWT tokens from being used after passphrase change
        let mut token_guard = self.session_token.lock().await;
        *token_guard = None;
        drop(token_guard);

        // Delete persisted JWT session from database
        // SECURITY: This MUST succeed - if JWT deletion fails, passphrase change must fail
        let vault_path_hash = self.create_vault_path_hash();
        self.delete_jwt_session(&vault_path_hash).await?;
        log::debug!("JWT session successfully deleted from database");

        // Lock the vault to force full re-authentication with new passphrase
        // This ensures the next operation will verify the new passphrase
        if let Ok(mut locked_guard) = self.locked.lock() {
            *locked_guard = true;
            log::debug!("Vault locked after passphrase change");
        }

        // Clear encryption key from memory
        let mut key_guard = self.encryption_key.lock().await;
        *key_guard = None;
        drop(key_guard);

        log::info!("Passphrase changed, JWT session deleted, and vault locked");

        Ok(())
    }
}
