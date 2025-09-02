//! Passphrase hashing and verification operations
//!
//! Contains secure passphrase storage, hashing, and verification using Argon2.

use super::super::{LocalVaultProvider, VaultEntry};
use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use secrecy::ExposeSecret;

impl LocalVaultProvider {
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

        // Create Salt from raw salt bytes (must be exactly 22 bytes for Argon2)
        let salt_bytes = if salt.len() >= 22 {
            &salt[..22]
        } else {
            return Err(VaultError::KeyDerivation(format!("Salt too short: {} bytes, need at least 22", salt.len())));
        };
        
        // Convert bytes to base64 string and create Salt
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_SALT};
        let salt_b64 = BASE64_SALT.encode(salt_bytes);
        // Remove padding characters that Salt::from_b64() doesn't accept
        let salt_b64_no_padding = salt_b64.trim_end_matches('=');
        let salt_str = Salt::from_b64(salt_b64_no_padding)
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
}
