//! AES encryption builders following README.md patterns exactly

use crate::{CryptError, Result};
use tokio::sync::oneshot;

// Declare submodules
pub mod aad;
pub mod decrypt;
pub mod encrypt;
pub mod stream;

/// Initial AES builder - entry point
pub struct AesBuilder;

/// AES builder with key
pub struct AesWithKey {
    key: Vec<u8>,
    aad: Option<Vec<u8>>,
}

/// AES builder with key and result handler
pub struct AesWithKeyAndHandler<F, T> {
    key: Vec<u8>,
    aad: Option<Vec<u8>>,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// AES builder with key and chunk handler for streaming
pub struct AesWithKeyAndChunkHandler<F> {
    key: Vec<u8>,
    aad: Option<Vec<u8>>,
    chunk_handler: F,
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
        Self { key, aad: None }
    }

    /// Add additional authenticated data (AAD) for AES-GCM
    pub fn with_aad<T: Into<Vec<u8>>>(mut self, aad: T) -> Self {
        self.aad = Some(aad.into());
        self
    }

    /// Internal implementation for on_result - called by macro
    fn on_result_impl<F>(self, handler: F) -> AesWithKeyAndHandler<F, Vec<u8>>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        AesWithKeyAndHandler {
            key: self.key,
            aad: self.aad,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Internal implementation for on_chunk - called by macro
    fn on_chunk_impl<F>(self, handler: F) -> AesWithKeyAndChunkHandler<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        AesWithKeyAndChunkHandler {
            key: self.key,
            aad: self.aad,
            chunk_handler: handler,
        }
    }
}

impl AesWithKey {
    /// Add on_result handler - transforms pattern matching internally  
    pub fn on_result<F>(self, handler: F) -> AesWithKeyAndHandler<F, Vec<u8>>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        self.on_result_impl(cryypt_common::transform_on_result!(handler))
    }

    /// Add on_chunk handler - transforms pattern matching internally
    pub fn on_chunk<F>(self, handler: F) -> AesWithKeyAndChunkHandler<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        self.on_chunk_impl(cryypt_common::transform_on_chunk!(handler))
    }

    /// Encrypt data - action takes data as argument per README.md
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn encrypt<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();
        let key = self.key;
        let aad = self.aad;

        // Perform AES-GCM encryption with default unwrapping
        let result = aes_encrypt_with_aad(&key, &data, aad.as_deref()).await;

        // Default unwrapping: Ok(data) => data, Err(_) => Vec::new()
        match result {
            Ok(encrypted_data) => encrypted_data,
            Err(_) => Vec::new(),
        }
    }

    /// Encrypt data with encodable result - provides additional formatting methods
    pub fn encrypt_encodable<T: Into<Vec<u8>>>(
        self,
        data: T,
    ) -> crate::cipher::encryption_result::EncryptionResultImpl {
        let data = data.into();
        let key = self.key;
        let aad = self.aad;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = aes_encrypt_with_aad(&key, &data, aad.as_deref()).await;
            let _ = tx.send(result);
        });

        crate::cipher::encryption_result::EncryptionResultImpl::new(rx)
    }

    /// Decrypt data - action takes data as argument per README.md
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn decrypt<T: Into<Vec<u8>>>(self, ciphertext: T) -> Vec<u8> {
        let ciphertext = ciphertext.into();
        let key = self.key;
        let aad = self.aad;

        // Perform AES-GCM decryption with default unwrapping
        let result = aes_decrypt_with_aad(&key, &ciphertext, aad.as_deref()).await;

        // Default unwrapping: Ok(data) => data, Err(_) => Vec::new()
        match result {
            Ok(decrypted_data) => decrypted_data,
            Err(_) => Vec::new(),
        }
    }

    /// Decrypt data with automatic error handling - returns Vec<u8> directly
    pub fn decrypt_auto<T: Into<Vec<u8>>>(
        self,
        ciphertext: T,
    ) -> crate::cipher::encryption_result::DecryptionResultImpl {
        let ciphertext = ciphertext.into();
        let key = self.key;
        let aad = self.aad;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = aes_decrypt_with_aad(&key, &ciphertext, aad.as_deref()).await;
            let _ = tx.send(result);
        });

        crate::cipher::encryption_result::DecryptionResultImpl::new(rx)
    }
}

impl<F> AesWithKeyAndHandler<F, Vec<u8>>
where
    F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Encrypt data - action takes data as argument per README.md
    pub async fn encrypt<D: Into<Vec<u8>>>(self, data: D) -> Vec<u8> {
        let data = data.into();
        let key = self.key;
        let aad = self.aad;
        let handler = self.result_handler;

        // Perform AES-GCM encryption with optional AAD
        let result = aes_encrypt_with_aad(&key, &data, aad.as_deref()).await;

        // Apply result handler
        handler(result)
    }

    /// Decrypt data - action takes data as argument per README.md
    pub async fn decrypt<D: Into<Vec<u8>>>(self, ciphertext: D) -> Vec<u8> {
        let ciphertext = ciphertext.into();
        let key = self.key;
        let aad = self.aad;
        let handler = self.result_handler;

        // Perform AES-GCM decryption with optional AAD
        let result = aes_decrypt_with_aad(&key, &ciphertext, aad.as_deref()).await;

        // Apply result handler
        handler(result)
    }
}

impl<F> AesWithKeyAndChunkHandler<F>
where
    F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Encrypt data as stream - returns async iterator of chunks
    pub fn encrypt_stream<D: Into<Vec<u8>>>(
        self,
        data: D,
    ) -> impl futures::Stream<Item = Vec<u8>> + Send {
        let data = data.into();
        let key = self.key;
        let aad = self.aad;
        let handler = self.chunk_handler;

        futures::stream::unfold((data, key, aad, handler, 0), move |(data, key, aad, handler, offset)| async move {
            if offset >= data.len() {
                return None;
            }

            const CHUNK_SIZE: usize = 1024;
            let end = std::cmp::min(offset + CHUNK_SIZE, data.len());
            let chunk = data[offset..end].to_vec();

            // Encrypt the chunk
            let result = aes_encrypt_with_aad(&key, &chunk, aad.as_deref()).await;
            let processed_chunk = handler(result);

            Some((processed_chunk, (data, key, aad, handler, end)))
        })
    }

    /// Decrypt data as stream - returns async iterator of chunks
    pub fn decrypt_stream<D: Into<Vec<u8>>>(
        self,
        ciphertext: D,
    ) -> impl futures::Stream<Item = Vec<u8>> + Send {
        let ciphertext = ciphertext.into();
        let key = self.key;
        let aad = self.aad;
        let handler = self.chunk_handler;

        futures::stream::unfold((ciphertext, key, aad, handler, 0), move |(ciphertext, key, aad, handler, offset)| async move {
            if offset >= ciphertext.len() {
                return None;
            }

            const CHUNK_SIZE: usize = 1024;
            let end = std::cmp::min(offset + CHUNK_SIZE, ciphertext.len());
            let chunk = ciphertext[offset..end].to_vec();

            // Decrypt the chunk
            let result = aes_decrypt_with_aad(&key, &chunk, aad.as_deref()).await;
            let processed_chunk = handler(result);

            Some((processed_chunk, (ciphertext, key, aad, handler, end)))
        })
    }
}

// Internal encryption function using true async (backwards compatibility)
#[allow(dead_code)]
async fn aes_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    aes_encrypt_with_aad(key, data, None).await
}

// Internal encryption function with AAD support using true async
async fn aes_encrypt_with_aad(key: &[u8], data: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    let data = data.to_vec();
    let key = key.to_vec();
    let aad = aad.map(|a| a.to_vec());

    tokio::task::spawn_blocking(move || {
        use aes_gcm::{
            Aes256Gcm, KeyInit,
            aead::{Aead, generic_array::GenericArray},
        };
        use rand::RngCore;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        // For AES-GCM, AAD is used in the authentication but not encrypted
        // If AAD is provided, we prepend it to the result for later verification
        let ciphertext = cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|e| CryptError::EncryptionFailed(e.to_string()))?;

        // Build result: [AAD_LEN(4 bytes)][AAD][NONCE(12 bytes)][CIPHERTEXT]
        let mut result = Vec::new();

        if let Some(ref aad_data) = aad {
            // Store AAD length (4 bytes) + AAD data
            result.extend_from_slice(&(aad_data.len() as u32).to_le_bytes());
            result.extend_from_slice(aad_data);
        } else {
            // No AAD - store 0 length
            result.extend_from_slice(&0u32.to_le_bytes());
        }

        // Add nonce and ciphertext
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    })
    .await
    .map_err(|e| CryptError::InternalError(e.to_string()))?
}

// Internal decryption function using true async (backwards compatibility)
#[allow(dead_code)]
async fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    aes_decrypt_with_aad(key, ciphertext, None).await
}

// Internal decryption function with AAD support using true async
async fn aes_decrypt_with_aad(
    key: &[u8],
    ciphertext: &[u8],
    expected_aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    // Minimum size: 4 bytes (AAD length) + 12 bytes (nonce) + 16 bytes (min ciphertext with tag)
    if ciphertext.len() < 32 {
        return Err(CryptError::InvalidEncryptedData(
            "Ciphertext too short".to_string(),
        ));
    }

    let ciphertext = ciphertext.to_vec();
    let key = key.to_vec();
    let expected_aad = expected_aad.map(|a| a.to_vec());

    tokio::task::spawn_blocking(move || {
        use aes_gcm::{
            Aes256Gcm, KeyInit,
            aead::{Aead, generic_array::GenericArray},
        };

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));

        // Parse the new format: [AAD_LEN(4)][AAD][NONCE(12)][CIPHERTEXT]
        let mut offset = 0;

        // Read AAD length
        if ciphertext.len() < 4 {
            return Err(CryptError::InvalidEncryptedData(
                "Cannot read AAD length".to_string(),
            ));
        }
        let aad_len = u32::from_le_bytes([
            ciphertext[offset],
            ciphertext[offset + 1],
            ciphertext[offset + 2],
            ciphertext[offset + 3],
        ]) as usize;
        offset += 4;

        // Read AAD if present
        let stored_aad = if aad_len > 0 {
            if ciphertext.len() < offset + aad_len {
                return Err(CryptError::InvalidEncryptedData(
                    "Cannot read AAD data".to_string(),
                ));
            }
            let aad = ciphertext[offset..offset + aad_len].to_vec();
            offset += aad_len;
            Some(aad)
        } else {
            None
        };

        // Verify AAD matches expected (if provided)
        if let Some(ref expected) = expected_aad {
            match &stored_aad {
                Some(stored) if stored != expected => {
                    return Err(CryptError::DecryptionFailed("AAD mismatch".to_string()));
                }
                None => {
                    return Err(CryptError::DecryptionFailed(
                        "Expected AAD but none found".to_string(),
                    ));
                }
                _ => {} // AAD matches
            }
        }

        // Read nonce (12 bytes)
        if ciphertext.len() < offset + 12 {
            return Err(CryptError::InvalidEncryptedData(
                "Cannot read nonce".to_string(),
            ));
        }
        let nonce_bytes = &ciphertext[offset..offset + 12];
        let nonce = GenericArray::from_slice(nonce_bytes);
        offset += 12;

        // Read actual ciphertext
        let actual_ciphertext = &ciphertext[offset..];

        // Decrypt the data
        let plaintext = cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|e| CryptError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    })
    .await
    .map_err(|e| CryptError::InternalError(e.to_string()))?
}

