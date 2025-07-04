//! ChaCha20-Poly1305 encryption operations
//!
//! Contains the encryption methods and trait implementations for ChaCha20-Poly1305.

use super::{ChaChaWithKey, ChaChaWithKeyAndData};
use super::super::{AsyncEncryptionResult, CipherOnResultExt, CipherProducer};
use super::super::cipher_builder_traits::EncryptBuilder;
use crate::{cipher::encryption_result::EncryptionResultImpl, CryptError, Result};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305,
};
use rand::RngCore;
use tokio::sync::oneshot;
use zeroize::Zeroizing;
use std::pin::Pin;
use std::future::Future;

impl ChaChaWithKey {
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
    /// This enables: key.chacha20().encrypt(data).await?
    pub async fn encrypt<T: Into<Vec<u8>>>(self, data: T) -> Result<Vec<u8>> {
        let data = data.into();
        
        // First resolve the key
        let key_result = self.key_builder.resolve().await;
        let key_vec = match key_result {
            Ok(k) => k,
            Err(e) => return Err(CryptError::from(e)),
        };

        // Generate a 12-byte nonce for ChaCha20-Poly1305
        let mut nonce_bytes = vec![0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);

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
        let nonce = GenericArray::from_slice(&nonce_bytes);

        // Perform encryption
        let ciphertext = cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|_| CryptError::EncryptionFailed("ChaCha20 encryption failed".to_string()))?;

        // Build final result: nonce || ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }
}

impl EncryptBuilder for ChaChaWithKeyAndData {
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

            let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                // Generate nonce
                let mut nonce = vec![0u8; 12];
                rand::rng().fill_bytes(&mut nonce);
                let nonce_array = GenericArray::from_slice(&nonce);

                // Use resolved key
                let key_bytes = Zeroizing::new(key_vec);

                // Create cipher
                let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
                    .map_err(|e| CryptError::InvalidKey(format!("Invalid ChaCha key: {}", e)))?;

                // Encrypt
                let ciphertext = cipher
                    .encrypt(nonce_array, self.data.as_ref())
                    .map_err(|_| {
                        CryptError::EncryptionFailed("ChaCha20-Poly1305 encryption failed".into())
                    })?;

                // Return ciphertext with nonce prepended
                let mut result = nonce;
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

// Implement CipherOnResultExt for ChaChaWithKey to support on_result! macro
impl CipherOnResultExt for ChaChaWithKey {
    type EncryptOutput = Result<Vec<u8>>;
    type DecryptOutput = Result<Vec<u8>>;
    type EncryptFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send>>;
    type DecryptFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send>>;
    
    fn encrypt<T: Into<Vec<u8>> + Send + 'static>(self, data: T) -> Self::EncryptFuture {
        Box::pin(self.encrypt(data))
    }
    
    fn decrypt(self, ciphertext: &[u8]) -> Self::DecryptFuture {
        let ciphertext = ciphertext.to_vec();
        Box::pin(async move { self.decrypt(&ciphertext).await })
    }
}

// Implement CipherProducer for ChaChaWithKey to support on_result! macro
impl CipherProducer for ChaChaWithKey {
    async fn produce_encrypt(self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.encrypt(data).await
    }
    
    async fn produce_decrypt(self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt(ciphertext).await
    }
}