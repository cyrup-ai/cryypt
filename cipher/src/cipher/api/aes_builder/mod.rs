//! AES encryption builders following README.md patterns exactly

use crate::{Result, CryptError};

// Declare submodules
pub mod encrypt;
pub mod decrypt;
pub mod stream;
pub mod aad;

/// Initial AES builder - entry point
pub struct AesBuilder;

/// AES builder with key
pub struct AesWithKey {
    key: Vec<u8>,
    result_handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Result<Vec<u8>> + Send + Sync>>,
}

impl AesBuilder {
    /// Create new AES builder
    pub fn new() -> Self {
        Self
    }

    /// Add key to builder - README.md pattern
    pub fn with_key<T: Into<Vec<u8>>>(self, key: T) -> AesWithKey {
        AesWithKey::new(key.into())
    }
}

impl AesWithKey {
    /// Create AES builder with key
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            result_handler: None,
        }
    }

    /// Add on_result! handler - README.md pattern
    pub fn on_result<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<Vec<u8>>) -> Result<Vec<u8>> + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }

    /// Encrypt data - action takes data as argument per README.md
    pub async fn encrypt<T: Into<Vec<u8>>>(self, data: T) -> Result<Vec<u8>> {
        let data = data.into();
        
        // Perform AES-GCM encryption
        let result = aes_encrypt(&self.key, &data).await;
        
        // Apply result handler if present
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }

    /// Decrypt data - action takes data as argument per README.md
    pub async fn decrypt<T: Into<Vec<u8>>>(self, ciphertext: T) -> Result<Vec<u8>> {
        let ciphertext = ciphertext.into();
        
        // Perform AES-GCM decryption
        let result = aes_decrypt(&self.key, &ciphertext).await;
        
        // Apply result handler if present
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
}

// Internal encryption function using true async
async fn aes_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    let data = data.to_vec();
    let key = key.to_vec();
    
    tokio::task::spawn_blocking(move || {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, generic_array::GenericArray}};
        use rand::RngCore;
        
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);
        
        // Encrypt the data
        let ciphertext = cipher.encrypt(nonce, data.as_ref())
            .map_err(|e| CryptError::EncryptionFailed(e.to_string()))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    })
    .await
    .map_err(|e| CryptError::InternalError(e.to_string()))?
}

// Internal decryption function using true async
async fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    if ciphertext.len() < 12 {
        return Err(CryptError::InvalidEncryptedData("Ciphertext too short".to_string()));
    }

    let ciphertext = ciphertext.to_vec();
    let key = key.to_vec();
    
    tokio::task::spawn_blocking(move || {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, generic_array::GenericArray}};
        
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        
        // Extract nonce and ciphertext
        let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(12);
        let nonce = GenericArray::from_slice(nonce_bytes);
        
        // Decrypt the data
        let plaintext = cipher.decrypt(nonce, actual_ciphertext)
            .map_err(|e| CryptError::DecryptionFailed(e.to_string()))?;
        
        Ok(plaintext)
    })
    .await
    .map_err(|e| CryptError::InternalError(e.to_string()))?
}