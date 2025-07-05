//! AES encryption operations
//!
//! Contains encryption implementations including README.md patterns and old-style encryption.

use super::{AesWithKey, AesWithKeyAndData};
use super::super::{
    cipher_builder_traits::{AadBuilder, EncryptBuilder},
    AsyncEncryptionResult,
};
use crate::{cipher::encryption_result::EncryptionResultImpl, CryptError, Result};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm,
};
use rand::RngCore;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

impl AesWithKey {
    /// Handle result with the on_result! macro - README.md pattern
    /// This just returns self since the standard pattern is identity
    pub fn on_result<F>(self, _handler: F) -> Self 
    where
        F: FnOnce(&mut dyn FnMut(Result<Vec<u8>>) -> Result<Vec<u8>>),
    {
        // The handler is ignored for the standard pattern
        // The macro will ensure this is only called with the identity pattern
        self
    }

    /// Encrypt data directly - README.md pattern
    /// This enables: key.aes().encrypt(data).await?
    pub async fn encrypt<T: Into<Vec<u8>>>(self, data: T) -> Result<Vec<u8>> {
        let data = data.into();
        
        // First resolve the key
        let key_result = self.key_builder.resolve().await;
        let key_vec = match key_result {
            Ok(k) => k,
            Err(e) => return Err(CryptError::from(e)),
        };

        // Generate a 12-byte nonce for AES-GCM
        let mut nonce_bytes = vec![0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);

        // Create secure key wrapper
        let key_bytes = Zeroizing::new(key_vec);
        
        // Validate key size for AES-256
        if key_bytes.len() != 32 {
            return Err(CryptError::InvalidKeySize {
                expected: 32,
                actual: key_bytes.len(),
            });
        }

        // Create AES-256-GCM cipher instance
        let key = GenericArray::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        // Perform encryption
        let ciphertext = cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|_| CryptError::EncryptionFailed("AES-GCM encryption failed".to_string()))?;

        // Build final result: nonce || ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }
}

impl AadBuilder for AesWithKeyAndData {
    type Output = Self;

    fn with_aad(mut self, aad_map: std::collections::HashMap<String, String>) -> Self::Output {
        self.aad.extend(aad_map);
        self
    }
}

impl AesWithKeyAndData {
    /// Add AAD key-value pair for encryption
    pub fn add(mut self, key: &str, value: &str) -> Self {
        self.aad.insert(key.to_string(), value.to_string());
        self
    }
}

impl EncryptBuilder for AesWithKeyAndData {
    fn encrypt(self) -> impl AsyncEncryptionResult {
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            // First resolve the key
            let key_result = self.key_builder.resolve().await;
            let key_vec = match key_result {
                Ok(k) => k,
                Err(e) => {
                    let _ = tx.send(Err(CryptError::from(e)));
                    return;
                }
            };

            let aad = self.aad;
            let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                // Generate nonce
                let mut nonce = vec![0u8; 12];
                rand::rng().fill_bytes(&mut nonce);
                let nonce_array = GenericArray::from_slice(&nonce);

                // Use resolved key
                let key_bytes = Zeroizing::new(key_vec);

                // Create cipher
                let cipher = Aes256Gcm::new_from_slice(&key_bytes)
                    .map_err(|e| CryptError::InvalidKey(format!("Invalid AES key: {}", e)))?;

                // Serialize AAD for AEAD
                let aad_bytes = if aad.is_empty() {
                    Vec::new()
                } else {
                    serde_json::to_vec(&aad).map_err(|e| {
                        CryptError::SerializationError(format!("AAD serialization failed: {}", e))
                    })?
                };

                // Encrypt with AAD
                let ciphertext = cipher
                    .encrypt(
                        nonce_array,
                        aes_gcm::aead::Payload {
                            msg: &self.data,
                            aad: &aad_bytes,
                        },
                    )
                    .map_err(|_| {
                        CryptError::EncryptionFailed("AES-GCM encryption failed".into())
                    })?;

                // Return: [aad_len (4 bytes)][aad][nonce][ciphertext]
                let mut result = Vec::new();
                result.extend_from_slice(&(aad_bytes.len() as u32).to_le_bytes());
                result.extend_from_slice(&aad_bytes);
                result.extend_from_slice(&nonce);
                result.extend_from_slice(&ciphertext);
                Ok(result)
            })
            .await;

            let _ = tx.send(match result {
                Ok(Ok(data)) => Ok(data),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(CryptError::internal(format!(
                    "Encryption task failed: {}",
                    e
                ))),
            });
        });

        EncryptionResultImpl::new(rx)
    }
}