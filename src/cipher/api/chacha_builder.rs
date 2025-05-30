//! ChaCha20-Poly1305 encryption builders

use crate::{
    Result, CryptError,
    cipher::encryption_result::EncryptionResultImpl,
};
use super::{
    AsyncEncryptionResult, AsyncDecryptionResult,
    builder_traits::{KeyBuilder, DataBuilder, EncryptBuilder, CiphertextBuilder, DecryptBuilder, KeyProviderBuilder},
};
use tokio::sync::oneshot;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305,
};
use rand::{rngs::ThreadRng, RngCore};
use zeroize::Zeroizing;

/// Initial ChaCha builder
pub struct ChaChaBuilder;

/// ChaCha builder with key
pub struct ChaChaWithKey {
    key_builder: Box<dyn KeyProviderBuilder>,
}

/// ChaCha builder with key and data - ready to encrypt
pub struct ChaChaWithKeyAndData {
    key_builder: Box<dyn KeyProviderBuilder>,
    data: Vec<u8>,
}

/// ChaCha builder with key and ciphertext - ready to decrypt
pub struct ChaChaWithKeyAndCiphertext {
    key_builder: Box<dyn KeyProviderBuilder>,
    ciphertext: Vec<u8>,
}

impl ChaChaBuilder {
    pub fn new() -> Self {
        Self
    }
}

impl KeyBuilder for ChaChaBuilder {
    type Output = ChaChaWithKey;
    
    fn with_key<K>(self, key_builder: K) -> Self::Output 
    where 
        K: KeyProviderBuilder + 'static
    {
        ChaChaWithKey { key_builder: Box::new(key_builder) }
    }
}

impl DataBuilder for ChaChaWithKey {
    type Output = ChaChaWithKeyAndData;
    
    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        ChaChaWithKeyAndData {
            key_builder: self.key_builder,
            data: data.into(),
        }
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
                    let _ = tx.send(Err(e));
                    return;
                }
            };
            
            let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                // Generate nonce
                let mut nonce = vec![0u8; 12];
                let mut rng = ThreadRng::default();
                rng.fill_bytes(&mut nonce);
                let nonce_array = GenericArray::from_slice(&nonce);
                
                // Use resolved key
                let key_bytes = Zeroizing::new(key_vec);
                
                // Create cipher
                let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
                    .map_err(|e| CryptError::InvalidKey(format!("Invalid ChaCha key: {}", e)))?;
                
                // Encrypt
                let ciphertext = cipher
                    .encrypt(nonce_array, self.data.as_ref())
                    .map_err(|_| CryptError::EncryptionFailed("ChaCha20-Poly1305 encryption failed".into()))?;
                
                // Return ciphertext with nonce prepended
                let mut result = nonce;
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }).await;
            
            let _ = tx.send(match result {
                Ok(Ok(data)) => Ok(data),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(CryptError::internal(format!("Encryption task failed: {}", e))),
            });
        });
        
        EncryptionResultImpl::new(rx)
    }
}

impl CiphertextBuilder for ChaChaWithKey {
    type Output = ChaChaWithKeyAndCiphertext;
    
    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        ChaChaWithKeyAndCiphertext {
            key_builder: self.key_builder,
            ciphertext: ciphertext.into(),
        }
    }
}

impl DecryptBuilder for ChaChaWithKeyAndCiphertext {
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
                let plaintext = cipher
                    .decrypt(nonce_array, ciphertext)
                    .map_err(|_| CryptError::DecryptionFailed("ChaCha20-Poly1305 decryption failed".into()))?;
                
                Ok(plaintext)
            }).await;
            
            let _ = tx.send(match result {
                Ok(plaintext_result) => plaintext_result,
                Err(e) => Err(CryptError::internal(format!("Decryption task failed: {}", e))),
            });
        });
        
        crate::cipher::encryption_result::DecryptionResultImpl::new(rx)
    }
}