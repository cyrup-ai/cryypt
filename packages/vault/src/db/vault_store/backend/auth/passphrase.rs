//! Passphrase verification and management operations

use super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use secrecy::ExposeSecret;

impl LocalVaultProvider {
    /// Verify passphrase against stored hash
    pub(crate) async fn verify_passphrase(&self, passphrase: &Passphrase) -> VaultResult<()> {
        log::debug!("Verifying passphrase against stored hash...");

        // Try to retrieve stored passphrase hash using consistent query pattern
        let query = "SELECT * FROM vault_entries WHERE key = $key LIMIT 1";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("key", "__vault_passphrase_hash__"))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {e}")))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?;

        use super::super::super::VaultEntry;
        let hash_entry: Option<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {e}")))?;

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
                // No stored hash means this is the first time unlocking
                // Allow the unlock to proceed, hash will be stored
                log::info!("No existing passphrase hash found - this appears to be a new vault");
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
        let vault_path_hash = self.create_vault_path_hash();
        if let Err(e) = self.delete_jwt_session(&vault_path_hash).await {
            log::warn!("Failed to delete persisted JWT session: {}", e);
            // Continue anyway - session will expire naturally
        }

        log::info!("Passphrase changed and JWT session invalidated");

        Ok(())
    }
}
