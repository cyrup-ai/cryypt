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
        // Use Argon2 for passphrase hashing with proper salt generation
        use argon2::{
            Argon2,
            password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
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
            .map_err(|e| VaultError::KeyDerivation(format!("Invalid Argon2 params: {e}")))?,
        );

        // Generate proper Argon2 salt using the recommended approach
        let salt_str = SaltString::generate(&mut OsRng);

        // Hash the passphrase
        let passphrase_hash = argon2
            .hash_password(passphrase.expose_secret().as_bytes(), &salt_str)
            .map_err(|e| VaultError::Crypto(format!("Failed to hash passphrase: {e}")))?;

        let passphrase_hash = passphrase_hash.to_string().into_bytes();

        if passphrase_hash.is_empty() {
            return Err(VaultError::Crypto("Failed to hash passphrase".to_string()));
        }

        // Store the passphrase hash in the database using SurrealDB UPSERT
        let hash_b64 = BASE64_STANDARD.encode(passphrase_hash);

        // Use UPSERT to handle existing records
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL};
        let key_encoded = BASE64_URL.encode("__vault_passphrase_hash__".as_bytes());
        let record_id = format!("vault_entries:{}", key_encoded);
        let db = self.dao.db();

        // Use UPSERT with consistent record ID format
        let upsert_query = format!(
            "UPSERT {} SET key = $key, value = $value, created_at = $created_at, updated_at = $updated_at",
            record_id
        );

        let now = chrono::Utc::now();
        let mut result = db
            .query(upsert_query)
            .bind(("key", "__vault_passphrase_hash__"))
            .bind(("value", hash_b64))
            .bind(("created_at", surrealdb::value::Datetime::from(now)))
            .bind(("updated_at", surrealdb::value::Datetime::from(now)))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to upsert passphrase hash: {e}")))?;

        // Consume the result to validate the operation succeeded
        let created: Vec<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to check create result: {e}")))?;

        if created.is_empty() {
            return Err(VaultError::Provider(
                "Failed to upsert passphrase hash - no record returned".to_string(),
            ));
        }

        Ok(())
    }
}
