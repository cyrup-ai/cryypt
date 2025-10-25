//! Value encryption service for vault entries
//!
//! INNER security layer - encrypts individual vault values

use crate::error::{VaultError, VaultResult};
use cryypt_cipher::cipher::api::Cipher;
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Debug, Clone)]
pub struct EncryptionService;

impl EncryptionService {
    pub fn new() -> Self {
        Self
    }

    /// Encrypt data with AES-256-GCM
    pub async fn encrypt(&self, data: &[u8], key: &[u8]) -> VaultResult<Vec<u8>> {
        let encrypted = Cipher::aes()
            .with_key(key.to_vec())
            .on_result(|result| result.unwrap_or_default())
            .encrypt(data.to_vec())
            .await;

        if encrypted.is_empty() {
            return Err(VaultError::Encryption(
                "AES encryption failed - empty result".to_string(),
            ));
        }

        Ok(encrypted)
    }

    /// Decrypt data with AES-256-GCM
    pub async fn decrypt(&self, data: &[u8], key: &[u8]) -> VaultResult<Vec<u8>> {
        let decrypted = Cipher::aes()
            .with_key(key.to_vec())
            .on_result(|result| result.unwrap_or_default())
            .decrypt(data.to_vec())
            .await;

        if decrypted.is_empty() {
            return Err(VaultError::Decryption(
                "AES decryption failed - authentication failure".to_string(),
            ));
        }

        Ok(decrypted)
    }

    /// Encrypt to Base64 string (for database storage)
    pub async fn encrypt_to_string(&self, data: &[u8], key: &[u8]) -> VaultResult<String> {
        let encrypted = self.encrypt(data, key).await?;
        Ok(STANDARD.encode(&encrypted))
    }

    /// Decrypt from Base64 string
    pub async fn decrypt_from_string(&self, data: &str, key: &[u8]) -> VaultResult<Vec<u8>> {
        let encrypted = STANDARD.decode(data)
            .map_err(|e| VaultError::Decryption(format!("Base64 decode: {}", e)))?;
        self.decrypt(&encrypted, key).await
    }
}

impl Default for EncryptionService {
    fn default() -> Self {
        Self::new()
    }
}
