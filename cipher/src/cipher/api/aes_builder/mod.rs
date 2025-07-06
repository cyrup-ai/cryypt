//! AES encryption builders following README.md patterns exactly

use crate::{Result, CryptError, CipherResult, CipherResultWithHandler};
use tokio::sync::oneshot;

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
}

/// AES builder with key and result handler
pub struct AesWithKeyAndHandler<F, T> {
    key: Vec<u8>,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
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
        Self { key }
    }

    /// Add on_result handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> AesWithKeyAndHandler<F, T>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        AesWithKeyAndHandler {
            key: self.key,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }


    /// Encrypt data - action takes data as argument per README.md
    pub fn encrypt<T: Into<Vec<u8>>>(self, data: T) -> CipherResult {
        let data = data.into();
        let key = self.key;
        
        let (tx, rx) = oneshot::channel();
        
        tokio::spawn(async move {
            let result = aes_encrypt(&key, &data).await;
            let _ = tx.send(result);
        });
        
        CipherResult::new(rx)
    }

    /// Decrypt data - action takes data as argument per README.md
    pub fn decrypt<T: Into<Vec<u8>>>(self, ciphertext: T) -> CipherResult {
        let ciphertext = ciphertext.into();
        let key = self.key;
        
        let (tx, rx) = oneshot::channel();
        
        tokio::spawn(async move {
            let result = aes_decrypt(&key, &ciphertext).await;
            let _ = tx.send(result);
        });
        
        CipherResult::new(rx)
    }
}

impl<F, T> AesWithKeyAndHandler<F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Encrypt data - action takes data as argument per README.md
    pub async fn encrypt<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let key = self.key;
        let handler = self.result_handler;
        
        // Perform AES-GCM encryption
        let result = aes_encrypt(&key, &data).await;
        
        // Apply result handler
        handler(result)
    }

    /// Decrypt data - action takes data as argument per README.md
    pub async fn decrypt<D: Into<Vec<u8>>>(self, ciphertext: D) -> T {
        let ciphertext = ciphertext.into();
        let key = self.key;
        let handler = self.result_handler;
        
        // Perform AES-GCM decryption
        let result = aes_decrypt(&key, &ciphertext).await;
        
        // Apply result handler
        handler(result)
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