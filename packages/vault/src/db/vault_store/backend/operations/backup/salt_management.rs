//! Salt generation and management operations - encrypted SurrealDB storage

use super::super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};

impl LocalVaultProvider {
    /// Generate new salt for key rotation
    pub(super) async fn generate_new_rotation_salt(&self) -> VaultResult<Vec<u8>> {
        use rand::RngCore;

        let mut new_salt = vec![0u8; 32]; // 32 bytes salt
        rand::rng().fill_bytes(&mut new_salt);

        log::debug!("Generated new {} byte salt for rotation", new_salt.len());

        Ok(new_salt)
    }

    /// Replace the current salt in encrypted database storage
    pub(super) async fn replace_salt_database(&self, new_salt: &[u8]) -> VaultResult<()> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

        let salt_b64 = BASE64_STANDARD.encode(new_salt);
        let db = self.dao.db();

        // Update salt in encrypted database storage
        let update_query =
            "UPDATE vault_entries:__vault_salt__ SET value = $value, updated_at = $updated_at";

        match db
            .query(update_query)
            .bind(("value", salt_b64))
            .bind(("updated_at", chrono::Utc::now()))
            .await
        {
            Ok(_) => {
                log::info!("Salt successfully updated in encrypted database storage");
                Ok(())
            }
            Err(e) => {
                log::error!("Failed to update salt in database: {}", e);
                Err(VaultError::Provider(format!(
                    "Failed to update salt: {}",
                    e
                )))
            }
        }
    }
}
