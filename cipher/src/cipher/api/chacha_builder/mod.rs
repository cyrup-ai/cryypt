//! ChaCha20-Poly1305 encryption builders following README.md patterns exactly

use crate::{Result, CryptError};

// Declare submodules
pub mod encrypt;
pub mod decrypt;
pub mod stream;

/// Initial ChaCha builder - entry point
pub struct ChaChaBuilder;

/// ChaCha builder with key
pub struct ChaChaWithKey {
    key: Vec<u8>,
    result_handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Result<Vec<u8>> + Send + Sync>>,
}

impl ChaChaBuilder {
    /// Create new ChaCha builder
    pub fn new() -> Self {
        Self
    }

    /// Add key to builder - README.md pattern
    pub fn with_key<T: Into<Vec<u8>>>(self, key: T) -> ChaChaWithKey {
        ChaChaWithKey::new(key.into())
    }
}

impl ChaChaWithKey {
    /// Create ChaCha builder with key
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
        
        // Perform ChaCha20-Poly1305 encryption
        let result = chacha_encrypt(&self.key, &data).await;
        
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
        
        // Perform ChaCha20-Poly1305 decryption
        let result = chacha_decrypt(&self.key, &ciphertext).await;
        
        // Apply result handler if present
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
}

// Internal encryption function using true async
async fn chacha_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    let data = data.to_vec();
    let key = key.to_vec();
    
    tokio::task::spawn_blocking(move || {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, generic_array::GenericArray}};
        use rand::RngCore;
        
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
        
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
async fn chacha_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
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
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, generic_array::GenericArray}};
        
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
        
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