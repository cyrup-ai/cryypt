//! AES decryption operations
//!
//! Contains decryption implementations including README.md patterns and old-style decryption.

use super::{AesWithKey, AesWithKeyAndCiphertext};
use super::super::{
    builder_traits::{AadBuilder, DecryptBuilder},
    AsyncDecryptionResult,
};
use crate::{CryptError, Result};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm,
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

impl AesWithKey {
    /// Decrypt data directly - README.md pattern
    /// This enables: key.aes().decrypt(ciphertext).await?
    pub async fn decrypt(self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // First resolve the key
        let key_result = self.key_builder.resolve().await;
        let key_vec = match key_result {
            Ok(k) => k,
            Err(e) => return Err(CryptError::from(e)),
        };

        // Extract nonce and ciphertext
        if ciphertext.len() < 12 {
            return Err(CryptError::DecryptionFailed("Ciphertext too short".to_string()));
        }
        let (nonce_bytes, cipher_data) = ciphertext.split_at(12);

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
        let nonce = GenericArray::from_slice(nonce_bytes);

        // Perform decryption
        let plaintext = cipher
            .decrypt(nonce, cipher_data)
            .map_err(|_| CryptError::DecryptionFailed("AES-GCM decryption failed".to_string()))?;

        Ok(plaintext)
    }
}

impl AadBuilder for AesWithKeyAndCiphertext {
    type Output = Self;

    fn with_aad(mut self, aad_map: std::collections::HashMap<String, String>) -> Self::Output {
        self.aad.extend(aad_map);
        self
    }
}

impl AesWithKeyAndCiphertext {
    /// Add AAD key-value pair for verification during decryption
    pub fn add(mut self, key: &str, value: &str) -> Self {
        self.aad.insert(key.to_string(), value.to_string());
        self
    }
}

impl DecryptBuilder for AesWithKeyAndCiphertext {
    fn decrypt(self) -> impl AsyncDecryptionResult {
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

            let expected_aad = self.aad;
            let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                // Extract: [aad_len (4 bytes)][aad][nonce (12 bytes)][ciphertext]
                if self.ciphertext.len() < 16 {
                    // 4 + 12 minimum
                    return Err(CryptError::DecryptionFailed("Ciphertext too short".into()));
                }

                let aad_len = u32::from_le_bytes([
                    self.ciphertext[0],
                    self.ciphertext[1],
                    self.ciphertext[2],
                    self.ciphertext[3],
                ]) as usize;

                if self.ciphertext.len() < 4 + aad_len + 12 {
                    return Err(CryptError::DecryptionFailed(
                        "Invalid ciphertext format".into(),
                    ));
                }

                let stored_aad_bytes = &self.ciphertext[4..4 + aad_len];
                let nonce = &self.ciphertext[4 + aad_len..4 + aad_len + 12];
                let ciphertext = &self.ciphertext[4 + aad_len + 12..];

                // Verify AAD matches expected AAD
                let stored_aad: std::collections::HashMap<String, String> = if aad_len == 0 {
                    std::collections::HashMap::new()
                } else {
                    serde_json::from_slice(stored_aad_bytes).map_err(|e| {
                        CryptError::DecryptionFailed(format!("AAD deserialization failed: {}", e))
                    })?
                };

                if stored_aad != expected_aad {
                    return Err(CryptError::AuthenticationFailed("AAD mismatch".into()));
                }

                let nonce_array = GenericArray::from_slice(nonce);

                // Use resolved key
                let key_bytes = Zeroizing::new(key_vec);

                // Create cipher
                let cipher = Aes256Gcm::new_from_slice(&key_bytes)
                    .map_err(|e| CryptError::InvalidKey(format!("Invalid AES key: {}", e)))?;

                // Decrypt with AAD
                let plaintext = cipher
                    .decrypt(
                        nonce_array,
                        aes_gcm::aead::Payload {
                            msg: ciphertext,
                            aad: stored_aad_bytes,
                        },
                    )
                    .map_err(|_| {
                        CryptError::DecryptionFailed("AES-GCM decryption failed".into())
                    })?;

                Ok(plaintext)
            })
            .await;

            let _ = tx.send(match result {
                Ok(plaintext_result) => plaintext_result,
                Err(e) => Err(CryptError::internal(format!(
                    "Decryption task failed: {}",
                    e
                ))),
            });
        });

        crate::cipher::encryption_result::DecryptionResultImpl::new(rx)
    }
}