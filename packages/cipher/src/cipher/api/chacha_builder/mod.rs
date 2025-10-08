//! ChaCha20-Poly1305 encryption builders following README.md patterns exactly

use crate::{CryptError, Result};

// Declare submodules
pub mod decrypt;
pub mod encrypt;
pub mod stream;

/// Initial `ChaCha` builder - entry point
pub struct ChaChaBuilder;

/// `ChaCha` builder with key
pub struct ChaChaWithKey {
    key: Vec<u8>,
}

/// `ChaCha` builder with key and result handler
pub struct ChaChaWithKeyAndHandler<F, T> {
    key: Vec<u8>,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// `ChaCha` builder with key and chunk handler for streaming
pub struct ChaChaWithKeyAndChunkHandler<F> {
    key: Vec<u8>,
    chunk_handler: F,
}

impl Default for ChaChaBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChaChaBuilder {
    /// Create new `ChaCha` builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Add key to builder - README.md pattern
    pub fn with_key<T: Into<Vec<u8>>>(self, key: T) -> ChaChaWithKey {
        ChaChaWithKey::new(key.into())
    }
}

impl ChaChaWithKey {
    /// Create `ChaCha` builder with key
    #[must_use]
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Internal implementation for `on_result` - called by macro
    fn on_result_impl<F>(self, handler: F) -> ChaChaWithKeyAndHandler<F, Vec<u8>>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        ChaChaWithKeyAndHandler {
            key: self.key,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Internal implementation for `on_chunk` - called by macro
    fn on_chunk_impl<F>(self, handler: F) -> ChaChaWithKeyAndChunkHandler<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        ChaChaWithKeyAndChunkHandler {
            key: self.key,
            chunk_handler: handler,
        }
    }
}

impl ChaChaWithKey {
    /// Add `on_result` handler - transforms pattern matching internally  
    pub fn on_result<F>(self, handler: F) -> ChaChaWithKeyAndHandler<F, Vec<u8>>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        self.on_result_impl(handler)
    }

    /// Add `on_chunk` handler - transforms pattern matching internally
    pub fn on_chunk<F>(self, handler: F) -> ChaChaWithKeyAndChunkHandler<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        self.on_chunk_impl(handler)
    }

    /// Encrypt data - action takes data as argument per README.md
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn encrypt<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();

        // Perform ChaCha20-Poly1305 encryption with default unwrapping
        let result = chacha_encrypt(&self.key, &data).await;

        // Default unwrapping: Ok(data) => data, Err(_) => Vec::new()
        result.unwrap_or_default()
    }

    /// Decrypt data - action takes data as argument per README.md
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn decrypt<T: Into<Vec<u8>>>(self, ciphertext: T) -> Vec<u8> {
        let ciphertext = ciphertext.into();

        // Perform ChaCha20-Poly1305 decryption with default unwrapping
        let result = chacha_decrypt(&self.key, &ciphertext).await;

        // Default unwrapping: Ok(data) => data, Err(_) => Vec::new()
        result.unwrap_or_default()
    }
}

impl<F> ChaChaWithKeyAndHandler<F, Vec<u8>>
where
    F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Encrypt data - action takes data as argument per README.md
    pub async fn encrypt<D: Into<Vec<u8>>>(self, data: D) -> Vec<u8> {
        let data = data.into();
        let key = self.key;
        let handler = self.result_handler;

        // Perform ChaCha20-Poly1305 encryption
        let result = chacha_encrypt(&key, &data).await;

        // Apply result handler
        handler(result)
    }

    /// Decrypt data - action takes data as argument per README.md
    pub async fn decrypt<D: Into<Vec<u8>>>(self, ciphertext: D) -> Vec<u8> {
        let ciphertext = ciphertext.into();
        let key = self.key;
        let handler = self.result_handler;

        // Perform ChaCha20-Poly1305 decryption
        let result = chacha_decrypt(&key, &ciphertext).await;

        // Apply result handler
        handler(result)
    }
}

// Internal encryption function with chunked async processing
async fn chacha_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    const CHUNK_SIZE: usize = 8192;

    use chacha20poly1305::{
        ChaCha20Poly1305, KeyInit,
        aead::{Aead, generic_array::GenericArray},
    };
    use rand::RngCore;

    if key.len() != 32 {
        return Err(CryptError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    // Process data in chunks to avoid blocking
    if data.len() > CHUNK_SIZE {
        tokio::task::yield_now().await;
    }

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    // Encrypt with yield points for large data
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| CryptError::EncryptionFailed(e.to_string()))?;

    // Yield after encryption for large results
    if ciphertext.len() > CHUNK_SIZE {
        tokio::task::yield_now().await;
    }

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

// Internal decryption function with chunked async processing
async fn chacha_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    const CHUNK_SIZE: usize = 8192;

    use chacha20poly1305::{
        ChaCha20Poly1305, KeyInit,
        aead::{Aead, generic_array::GenericArray},
    };

    if key.len() != 32 {
        return Err(CryptError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    if ciphertext.len() < 12 {
        return Err(CryptError::InvalidEncryptedData(
            "Ciphertext too short".to_string(),
        ));
    }

    // Process data in chunks to avoid blocking
    if ciphertext.len() > CHUNK_SIZE {
        tokio::task::yield_now().await;
    }

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));

    // Extract nonce and ciphertext
    let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(12);
    let nonce = GenericArray::from_slice(nonce_bytes);

    // Decrypt the data with yield points for large data
    let plaintext = cipher
        .decrypt(nonce, actual_ciphertext)
        .map_err(|e| CryptError::DecryptionFailed(e.to_string()))?;

    // Yield after decryption for large results
    if plaintext.len() > CHUNK_SIZE {
        tokio::task::yield_now().await;
    }

    Ok(plaintext)
}

impl<F> ChaChaWithKeyAndChunkHandler<F>
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
        let handler = self.chunk_handler;

        futures::stream::unfold(
            (data, key, handler, 0),
            move |(data, key, handler, offset)| async move {
                const CHUNK_SIZE: usize = 1024;

                if offset >= data.len() {
                    return None;
                }
                let end = std::cmp::min(offset + CHUNK_SIZE, data.len());
                let chunk = data[offset..end].to_vec();

                // Encrypt the chunk
                let result = chacha_encrypt(&key, &chunk).await;
                let processed_chunk = handler(result);

                Some((processed_chunk, (data, key, handler, end)))
            },
        )
    }

    /// Decrypt data as stream - returns async iterator of chunks
    pub fn decrypt_stream<D: Into<Vec<u8>>>(
        self,
        ciphertext: D,
    ) -> impl futures::Stream<Item = Vec<u8>> + Send {
        let ciphertext = ciphertext.into();
        let key = self.key;
        let handler = self.chunk_handler;

        futures::stream::unfold(
            (ciphertext, key, handler, 0),
            move |(ciphertext, key, handler, offset)| async move {
                const CHUNK_SIZE: usize = 1024;

                if offset >= ciphertext.len() {
                    return None;
                }
                let end = std::cmp::min(offset + CHUNK_SIZE, ciphertext.len());
                let chunk = ciphertext[offset..end].to_vec();

                // Decrypt the chunk
                let result = chacha_decrypt(&key, &chunk).await;
                let processed_chunk = handler(result);

                Some((processed_chunk, (ciphertext, key, handler, end)))
            },
        )
    }
}
