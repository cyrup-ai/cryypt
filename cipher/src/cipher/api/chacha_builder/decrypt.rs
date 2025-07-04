//! ChaCha20-Poly1305 decryption operations
//!
//! Contains the decryption methods and trait implementations for ChaCha20-Poly1305.

use super::{ChaChaWithKey, ChaChaWithKeyAndCiphertext};
use super::super::cipher_builder_traits::DecryptBuilder;
use crate::{CryptError, Result};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305,
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

impl ChaChaWithKey {
    /// Decrypt data directly - README.md pattern
    /// This enables: key.chacha20().decrypt(ciphertext).await?
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
        
        // Validate key size for ChaCha20 (32 bytes)
        if key_bytes.len() != 32 {
            return Err(CryptError::InvalidKeySize {
                expected: 32,
                actual: key_bytes.len(),
            });
        }

        // Create ChaCha20-Poly1305 cipher instance
        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|e| CryptError::InvalidKey(format!("Invalid ChaCha key: {}", e)))?;
        let nonce = GenericArray::from_slice(nonce_bytes);

        // Perform decryption
        let plaintext = cipher
            .decrypt(nonce, cipher_data)
            .map_err(|_| CryptError::DecryptionFailed("ChaCha20 decryption failed".to_string()))?;

        Ok(plaintext)
    }
}

impl DecryptBuilder for ChaChaWithKeyAndCiphertext {
    fn decrypt(self) -> impl super::super::AsyncDecryptionResult {
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

            let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                // Extract nonce (first 12 bytes) and ciphertext
                if self.ciphertext.len() < 12 {
                    return Err(CryptError::DecryptionFailed("Ciphertext too short".into()));
                }

                let nonce = &self.ciphertext[..12];
                let ciphertext = &self.ciphertext[12..];
                let nonce_array = GenericArray::from_slice(nonce);

                // Use resolved key
                let key_bytes = Zeroizing::new(key_vec);

                // Create cipher
                let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
                    .map_err(|e| CryptError::InvalidKey(format!("Invalid ChaCha key: {}", e)))?;

                // Decrypt
                let plaintext = cipher.decrypt(nonce_array, ciphertext).map_err(|_| {
                    CryptError::DecryptionFailed("ChaCha20-Poly1305 decryption failed".into())
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