//! AES encryption builders

use super::{
    builder_traits::{
        AadBuilder, CiphertextBuilder, DataBuilder, DecryptBuilder, EncryptBuilder, KeyBuilder,
        KeyProviderBuilder,
    },
    AsyncDecryptionResult, AsyncEncryptionResult,
};
use crate::{cipher::encryption_result::EncryptionResultImpl, CryptError, Result};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm,
};
use rand::RngCore;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// Initial AES builder
pub struct AesBuilder;

/// AES builder with key
pub struct AesWithKey {
    key_builder: Box<dyn KeyProviderBuilder>,
}

/// AES builder with key and data - ready to encrypt
pub struct AesWithKeyAndData {
    pub(in crate::cipher) key_builder: Box<dyn KeyProviderBuilder>,
    pub(in crate::cipher) data: Vec<u8>,
    pub(in crate::cipher) aad: std::collections::HashMap<String, String>,
}

/// AES builder with key and ciphertext - ready to decrypt
pub struct AesWithKeyAndCiphertext {
    pub(in crate::cipher) key_builder: Box<dyn KeyProviderBuilder>,
    pub(in crate::cipher) ciphertext: Vec<u8>,
    pub(in crate::cipher) aad: std::collections::HashMap<String, String>,
}

impl AesBuilder {
    pub fn new() -> Self {
        Self
    }
}

impl KeyBuilder for AesBuilder {
    type Output = AesWithKey;

    fn with_key<K>(self, key_builder: K) -> Self::Output
    where
        K: KeyProviderBuilder + 'static,
    {
        AesWithKey {
            key_builder: Box::new(key_builder),
        }
    }
}

impl DataBuilder for AesWithKey {
    type Output = AesWithKeyAndData;

    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        AesWithKeyAndData {
            key_builder: self.key_builder,
            data: data.into(),
            aad: std::collections::HashMap::new(),
        }
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
                    let _ = tx.send(Err(e));
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
                    serde_json::to_vec(&aad)
                        .map_err(|e| CryptError::SerializationError(format!("AAD serialization failed: {}", e)))?
                };

                // Encrypt with AAD
                let ciphertext = cipher
                    .encrypt(nonce_array, aes_gcm::aead::Payload {
                        msg: &self.data,
                        aad: &aad_bytes,
                    })
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

impl CiphertextBuilder for AesWithKey {
    type Output = AesWithKeyAndCiphertext;

    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        AesWithKeyAndCiphertext {
            key_builder: self.key_builder,
            ciphertext: ciphertext.into(),
            aad: std::collections::HashMap::new(),
        }
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
                    let _ = tx.send(Err(e));
                    return;
                }
            };

            let expected_aad = self.aad;
            let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                // Extract: [aad_len (4 bytes)][aad][nonce (12 bytes)][ciphertext]
                if self.ciphertext.len() < 16 {  // 4 + 12 minimum
                    return Err(CryptError::DecryptionFailed("Ciphertext too short".into()));
                }

                let aad_len = u32::from_le_bytes([
                    self.ciphertext[0], self.ciphertext[1], 
                    self.ciphertext[2], self.ciphertext[3]
                ]) as usize;

                if self.ciphertext.len() < 4 + aad_len + 12 {
                    return Err(CryptError::DecryptionFailed("Invalid ciphertext format".into()));
                }

                let stored_aad_bytes = &self.ciphertext[4..4 + aad_len];
                let nonce = &self.ciphertext[4 + aad_len..4 + aad_len + 12];
                let ciphertext = &self.ciphertext[4 + aad_len + 12..];

                // Verify AAD matches expected AAD
                let stored_aad: std::collections::HashMap<String, String> = if aad_len == 0 {
                    std::collections::HashMap::new()
                } else {
                    serde_json::from_slice(stored_aad_bytes)
                        .map_err(|e| CryptError::DecryptionFailed(format!("AAD deserialization failed: {}", e)))?
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
                let plaintext = cipher.decrypt(nonce_array, aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: stored_aad_bytes,
                }).map_err(|_| {
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
