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
}

/// ChaCha builder with key and result handler
pub struct ChaChaWithKeyAndHandler<F, T> {
    key: Vec<u8>,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
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
        Self { key }
    }

    /// Add on_result handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> ChaChaWithKeyAndHandler<F, T>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        ChaChaWithKeyAndHandler {
            key: self.key,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Encrypt data - action takes data as argument per README.md
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn encrypt<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();
        
        // Perform ChaCha20-Poly1305 encryption with default unwrapping
        let result = chacha_encrypt(&self.key, &data).await;
        
        // Default unwrapping: Ok(data) => data, Err(_) => Vec::new()
        match result {
            Ok(encrypted_data) => encrypted_data,
            Err(_) => Vec::new(),
        }
    }

    /// Decrypt data - action takes data as argument per README.md
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn decrypt<T: Into<Vec<u8>>>(self, ciphertext: T) -> Vec<u8> {
        let ciphertext = ciphertext.into();
        
        // Perform ChaCha20-Poly1305 decryption with default unwrapping
        let result = chacha_decrypt(&self.key, &ciphertext).await;
        
        // Default unwrapping: Ok(data) => data, Err(_) => Vec::new()
        match result {
            Ok(decrypted_data) => decrypted_data,
            Err(_) => Vec::new(),
        }
    }
}

impl<F, T> ChaChaWithKeyAndHandler<F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Encrypt data - action takes data as argument per README.md
    pub async fn encrypt<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let key = self.key;
        let handler = self.result_handler;
        
        // Perform ChaCha20-Poly1305 encryption
        let result = chacha_encrypt(&key, &data).await;
        
        // Apply result handler
        handler(result)
    }

    /// Decrypt data - action takes data as argument per README.md
    pub async fn decrypt<D: Into<Vec<u8>>>(self, ciphertext: D) -> T {
        let ciphertext = ciphertext.into();
        let key = self.key;
        let handler = self.result_handler;
        
        // Perform ChaCha20-Poly1305 decryption
        let result = chacha_decrypt(&key, &ciphertext).await;
        
        // Apply result handler
        handler(result)
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