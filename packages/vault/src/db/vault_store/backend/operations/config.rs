//! Vault configuration persistence for RSA key management

use super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfigRecord {
    pub rsa_key_path: String,
    pub rsa_public_key_spki: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl LocalVaultProvider {
    /// Store RSA key configuration in database
    ///
    /// # Arguments
    /// * `rsa_key_path` - Absolute path to RSA private key file
    /// * `rsa_public_key_spki` - RSA public key in SPKI DER format
    pub async fn store_vault_config(
        &self,
        rsa_key_path: &str,
        rsa_public_key_spki: &[u8],
    ) -> VaultResult<()> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        
        let vault_hash = self.create_vault_path_hash();
        let record_id = format!("vault_config:{}", vault_hash);
        
        let public_key_b64 = BASE64.encode(rsa_public_key_spki);
        let now = chrono::Utc::now();
        
        let upsert_query = format!(
            "UPSERT {} SET 
                rsa_key_path = $rsa_key_path,
                rsa_public_key_spki = $rsa_public_key_spki,
                created_at = $created_at,
                updated_at = $updated_at",
            record_id
        );
        
        let db = self.dao.db();
        db.query(&upsert_query)
            .bind(("rsa_key_path", rsa_key_path.to_string()))
            .bind(("rsa_public_key_spki", public_key_b64))
            .bind(("created_at", surrealdb::value::Datetime::from(now)))
            .bind(("updated_at", surrealdb::value::Datetime::from(now)))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to store vault config: {e}")))?;
        
        log::info!("Stored RSA key configuration for vault hash: {}", vault_hash);
        Ok(())
    }
    
    /// Load RSA key configuration from database
    pub async fn load_vault_config(&self) -> VaultResult<Option<VaultConfigRecord>> {
        let vault_hash = self.create_vault_path_hash();
        let record_id = format!("vault_config:{}", vault_hash);
        
        let query = format!("SELECT * FROM {}", record_id);
        let db = self.dao.db();
        let mut result = db.query(&query).await
            .map_err(|e| VaultError::Provider(format!("Failed to query vault config: {e}")))?;
        
        let config: Option<VaultConfigRecord> = result.take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to deserialize vault config: {e}")))?;
        
        if config.is_some() {
            log::debug!("Loaded RSA key configuration from database");
        } else {
            log::debug!("No RSA key configuration found in database");
        }
        
        Ok(config)
    }
}
