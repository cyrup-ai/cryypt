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
}
