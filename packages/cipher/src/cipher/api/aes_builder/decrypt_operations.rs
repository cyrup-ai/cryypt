//! AES decryption operations

use super::builder_types::{AesWithKey, AesWithKeyAndChunkHandler, AesWithKeyAndHandler};
use crate::{CryptError, Result};
use tokio::sync::oneshot;

impl AesWithKey {
    /// Decrypt data - action takes data as argument per README.md
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn decrypt<T: Into<Vec<u8>>>(self, ciphertext: T) -> Vec<u8> {
        let ciphertext = ciphertext.into();
        let key = self.key;
        let aad = self.aad;

        // Perform AES-GCM decryption with default unwrapping
        let result = aes_decrypt_with_aad(&key, &ciphertext, aad.as_deref()).await;

        // Default unwrapping: Ok(data) => data, Err(_) => Vec::new()
        result.unwrap_or_default()
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
    /// Decrypt chunked data - returns stream of decrypted chunks
    pub fn decrypt<T: Into<Vec<u8>>>(self, data: T) -> impl futures::Stream<Item = Vec<u8>> {
        use tokio::sync::mpsc;

        let data = data.into();
        let key = self.key;
        let aad = self.aad;
        let handler = self.chunk_handler;

        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            let mut offset = 0;

            while offset < data.len() {
                // Read chunk length (4 bytes)
                if offset + 4 > data.len() {
                    let error_result = Err(CryptError::InvalidEncryptedData(
                        "Cannot read chunk length".to_string(),
                    ));
                    let processed_chunk = handler(error_result);
                    if tx.send(processed_chunk).await.is_err() {
                        break;
                    }
                    break;
                }

                let chunk_len = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]) as usize;
                offset += 4;

                // Read the chunk data
                if offset + chunk_len > data.len() {
                    let error_result = Err(CryptError::InvalidEncryptedData(
                        "Chunk data truncated".to_string(),
                    ));
                    let processed_chunk = handler(error_result);
                    if tx.send(processed_chunk).await.is_err() {
                        break;
                    }
                    break;
                }

                let chunk_data = &data[offset..offset + chunk_len];
                offset += chunk_len;

                // Decrypt this chunk
                let result = aes_decrypt_chunk(&key, chunk_data, aad.as_deref());
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break;
                }
            }
        });

        tokio_stream::wrappers::ReceiverStream::new(rx)
    }
}

// Chunk-specific decryption function for streaming
fn aes_decrypt_chunk(
    key: &[u8],
    chunk_data: &[u8],
    expected_aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{Aead, generic_array::GenericArray},
    };

    if key.len() != 32 {
        return Err(CryptError::InvalidKeySize {
            expected: 32,
            actual: key.len(),
        });
    }

    // Parse chunk format: [AAD_LEN(4)][AAD][NONCE(12)][CIPHERTEXT]
    let mut offset = 0;

    // Read AAD length
    if chunk_data.len() < 4 {
        return Err(CryptError::InvalidEncryptedData(
            "Cannot read AAD length from chunk".to_string(),
        ));
    }
    let aad_len = u32::from_le_bytes([
        chunk_data[offset],
        chunk_data[offset + 1],
        chunk_data[offset + 2],
        chunk_data[offset + 3],
    ]) as usize;
    offset += 4;

    // Read AAD if present
    let stored_aad = if aad_len > 0 {
        if chunk_data.len() < offset + aad_len {
            return Err(CryptError::InvalidEncryptedData(
                "Cannot read AAD data from chunk".to_string(),
            ));
        }
        let aad = chunk_data[offset..offset + aad_len].to_vec();
        offset += aad_len;
        Some(aad)
    } else {
        None
    };

    // Verify AAD matches expected (if provided)
    if let Some(expected) = expected_aad {
        match &stored_aad {
            Some(stored) if stored != expected => {
                return Err(CryptError::DecryptionFailed(
                    "AAD mismatch in chunk".to_string(),
                ));
            }
            None => {
                return Err(CryptError::DecryptionFailed(
                    "Expected AAD but none found in chunk".to_string(),
                ));
            }
            _ => {} // AAD matches
        }
    }

    // Read nonce (12 bytes)
    if chunk_data.len() < offset + 12 {
        return Err(CryptError::InvalidEncryptedData(
            "Cannot read nonce from chunk".to_string(),
        ));
    }
    let nonce_bytes = &chunk_data[offset..offset + 12];
    let nonce = GenericArray::from_slice(nonce_bytes);
    offset += 12;

    // Read actual ciphertext
    let actual_ciphertext = &chunk_data[offset..];

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));

    // Decrypt the chunk
    let plaintext = cipher
        .decrypt(nonce, actual_ciphertext)
        .map_err(|e| CryptError::DecryptionFailed(format!("Chunk decryption failed: {e}")))?;

    Ok(plaintext)
}

// Internal decryption function using true async (backwards compatibility)
#[allow(dead_code)]
pub(super) async fn aes_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    aes_decrypt_with_aad(key, ciphertext, None).await
}

// Internal decryption function with AAD support using chunked async processing
pub(super) async fn aes_decrypt_with_aad(
    key: &[u8],
    ciphertext: &[u8],
    expected_aad: Option<&[u8]>,
) -> Result<Vec<u8>> {
    const CHUNK_SIZE: usize = 8192;

    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{Aead, generic_array::GenericArray},
    };

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

    // Process data in chunks to avoid blocking
    if ciphertext.len() > CHUNK_SIZE {
        tokio::task::yield_now().await;
    }

    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));

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
    if let Some(expected) = expected_aad {
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
