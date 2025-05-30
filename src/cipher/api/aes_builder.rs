//! AES encryption builders

use crate::{
    Result, CryptError,
    cipher::encryption_result::EncryptionResultImpl,
};
use super::{
    AsyncEncryptionResult, AsyncDecryptionResult,
    builder_traits::{KeyBuilder, DataBuilder, EncryptBuilder, CiphertextBuilder, DecryptBuilder, KeyProviderBuilder},
};
use tokio::sync::oneshot;
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm,
};
use rand::{rngs::ThreadRng, RngCore};
use zeroize::Zeroizing;

/// Initial AES builder
pub struct AesBuilder;

/// AES builder with key
pub struct AesWithKey {
    key_builder: Box<dyn KeyProviderBuilder>,
}

/// AES builder with key and data - ready to encrypt
pub struct AesWithKeyAndData {
    key_builder: Box<dyn KeyProviderBuilder>,
    data: Vec<u8>,
}

/// AES builder with key and ciphertext - ready to decrypt
pub struct AesWithKeyAndCiphertext {
    key_builder: Box<dyn KeyProviderBuilder>,
    ciphertext: Vec<u8>,
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
        K: KeyProviderBuilder + 'static
    {
        AesWithKey { key_builder: Box::new(key_builder) }
    }
}

impl DataBuilder for AesWithKey {
    type Output = AesWithKeyAndData;
    
    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        AesWithKeyAndData {
            key_builder: self.key_builder,
            data: data.into(),
        }
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
            
            let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                // Generate nonce
                let mut nonce = vec![0u8; 12];
                let mut rng = ThreadRng::default();
                rng.fill_bytes(&mut nonce);
                let nonce_array = GenericArray::from_slice(&nonce);
                
                // Use resolved key
                let key_bytes = Zeroizing::new(key_vec);
                
                // Create cipher
                let cipher = Aes256Gcm::new_from_slice(&key_bytes)
                    .map_err(|e| CryptError::InvalidKey(format!("Invalid AES key: {}", e)))?;
                
                // Encrypt
                let ciphertext = cipher
                    .encrypt(nonce_array, self.data.as_ref())
                    .map_err(|_| CryptError::EncryptionFailed("AES-GCM encryption failed".into()))?;
                
                // Return ciphertext with nonce prepended (standard practice)
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

impl CiphertextBuilder for AesWithKey {
    type Output = AesWithKeyAndCiphertext;
    
    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        AesWithKeyAndCiphertext {
            key_builder: self.key_builder,
            ciphertext: ciphertext.into(),
        }
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
                let cipher = Aes256Gcm::new_from_slice(&key_bytes)
                    .map_err(|e| CryptError::InvalidKey(format!("Invalid AES key: {}", e)))?;
                
                // Decrypt
                let plaintext = cipher
                    .decrypt(nonce_array, ciphertext)
                    .map_err(|_| CryptError::DecryptionFailed("AES-GCM decryption failed".into()))?;
                
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