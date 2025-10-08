//! AES encryption operations

use super::builder_types::{AesWithKey, AesWithKeyAndChunkHandler, AesWithKeyAndHandler};
use crate::{CryptError, Result};
use tokio::sync::oneshot;

impl AesWithKey {
    /// Encrypt data - action takes data as argument per README.md
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn encrypt<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();
        let key = self.key;
        let aad = self.aad;

        // Perform AES-GCM encryption with default unwrapping
        let result = aes_encrypt_with_aad(&key, &data, aad.as_deref()).await;

        // Default unwrapping: Ok(data) => data, Err(_) => Vec::new()
        result.unwrap_or_default()
    }

    /// Encrypt data with encodable result - provides additional formatting methods
    #[must_use]
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
}

impl<F> AesWithKeyAndChunkHandler<F>
where
    F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Encrypt data in chunks - returns stream of encrypted chunks
    pub fn encrypt<T: Into<Vec<u8>>>(self, data: T) -> impl futures::Stream<Item = Vec<u8>> {
        use tokio::sync::mpsc;

        let data = data.into();
        let key = self.key;
        let aad = self.aad;
        let handler = self.chunk_handler;

        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

            for chunk in data.chunks(CHUNK_SIZE) {
                // Encrypt each chunk with unique nonce
                let result = aes_encrypt_chunk(&key, chunk, aad.as_deref());
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break;
                }
            }
        });

        tokio_stream::wrappers::ReceiverStream::new(rx)
    }
}

// Chunk-specific encryption function for streaming
fn aes_encrypt_chunk(key: &[u8], data: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{Aead, generic_array::GenericArray},
    };
    use rand::RngCore;

    if key.len() != 32 {
        return Err(CryptError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));

    // Generate random nonce for this chunk
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| CryptError::EncryptionFailed(e.to_string()))?;

    // Build chunk result: [CHUNK_LEN(4)][AAD_LEN(4)][AAD][NONCE(12)][CIPHERTEXT]
    let mut result = Vec::new();

    // Length prefix for this chunk
    let chunk_data_len = if let Some(aad_data) = aad {
        4 + aad_data.len() + 12 + ciphertext.len()
    } else {
        4 + 12 + ciphertext.len()
    };
    result.extend_from_slice(&u32::try_from(chunk_data_len).unwrap_or(0).to_le_bytes());

    if let Some(aad_data) = aad {
        result.extend_from_slice(&u32::try_from(aad_data.len()).unwrap_or(0).to_le_bytes());
        result.extend_from_slice(aad_data);
    } else {
        result.extend_from_slice(&0u32.to_le_bytes());
    }

    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

// Internal encryption function using true async (backwards compatibility)
#[allow(dead_code)]
pub(super) async fn aes_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    aes_encrypt_with_aad(key, data, None).await
}

// Internal encryption function with AAD support using chunked async processing
pub(super) async fn aes_encrypt_with_aad(
    key: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    const CHUNK_SIZE: usize = 8192;

    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{Aead, generic_array::GenericArray},
    };
    use rand::RngCore;

    if key.len() != 32 {
        return Err(CryptError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    // Yield for large data processing
    if data.len() > CHUNK_SIZE {
        tokio::task::yield_now().await;
    }

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    // For AES-GCM, AAD is used in the authentication but not encrypted
    // If AAD is provided, we prepend it to the result for later verification
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| CryptError::EncryptionFailed(e.to_string()))?;

    // Build result: [AAD_LEN(4 bytes)][AAD][NONCE(12 bytes)][CIPHERTEXT]
    let mut result = Vec::new();

    if let Some(aad_data) = aad {
        // Store AAD length (4 bytes) + AAD data
        result.extend_from_slice(&u32::try_from(aad_data.len()).unwrap_or(0).to_le_bytes());
        result.extend_from_slice(aad_data);
    } else {
        // No AAD - store 0 length
        result.extend_from_slice(&0u32.to_le_bytes());
    }

    // Add nonce and ciphertext
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    // Yield after building large results
    if result.len() > CHUNK_SIZE {
        tokio::task::yield_now().await;
    }

    Ok(result)
}
