//! Encryption pipeline for message processing
//!
//! This module provides streaming encryption and decryption functionality
//! using the cryypt cipher API for secure message processing.

use super::super::types::{EncryptionAlgorithm, EncryptionMetadata};
use crate::error::CryptoTransportError;
use cryypt_cipher::Cipher;

/// Streaming encryption pipeline using cryypt cipher API  
///
/// # Errors
///
/// Returns an error if:
/// - Encryption operation fails
/// - Invalid encryption key
/// - Unsupported encryption algorithm
pub async fn encrypt_payload_stream(
    data: Vec<u8>,
    algorithm: EncryptionAlgorithm,
    key: Vec<u8>,
    key_id: String,
) -> crate::Result<(Vec<u8>, EncryptionMetadata)> {
    let timestamp = std::time::SystemTime::now();

    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            let data_was_empty = data.is_empty();
            let encrypted = Cipher::aes()
                .with_key(key)
                .on_result(|result| match result {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!("AES encryption failed: {}", e);
                        Vec::new() // Return empty on error
                    }
                })
                .encrypt(data)
                .await;

            // Check if encryption failed (empty result indicates error only if original wasn't empty)
            if encrypted.is_empty() && !data_was_empty {
                return Err(CryptoTransportError::Internal(
                    "AES encryption failed - produced empty result for non-empty input".to_string(),
                ));
            }

            let metadata = EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id,
                nonce: Vec::new(), // Nonce is embedded in ciphertext by cipher implementation
                chunks: 1,
                auth_tag: Vec::new(), // AES-GCM auth tag is integrated into encrypted data
                timestamp,
            };

            Ok((encrypted, metadata))
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            let data_was_empty = data.is_empty();
            let encrypted = Cipher::chacha20()
                .with_key(key)
                .on_result(|result| match result {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!("ChaCha20 encryption failed: {}", e);
                        Vec::new() // Return empty on error
                    }
                })
                .encrypt(data)
                .await;

            // Check if encryption failed (empty result indicates error only if original wasn't empty)
            if encrypted.is_empty() && !data_was_empty {
                return Err(CryptoTransportError::Internal(
                    "ChaCha20 encryption failed - produced empty result for non-empty input"
                        .to_string(),
                ));
            }

            let metadata = EncryptionMetadata {
                algorithm: "chacha20-poly1305".to_string(),
                key_id,
                nonce: Vec::new(), // Nonce is embedded in ciphertext by cipher implementation
                chunks: 1,
                auth_tag: Vec::new(), // ChaCha20-Poly1305 auth tag is integrated into encrypted data
                timestamp,
            };

            Ok((encrypted, metadata))
        }
        EncryptionAlgorithm::None => {
            // No encryption - return original data with empty metadata
            let metadata = EncryptionMetadata {
                algorithm: "none".to_string(),
                key_id: "none".to_string(),
                nonce: Vec::new(),
                chunks: 1,
                auth_tag: Vec::new(),
                timestamp,
            };
            Ok((data, metadata))
        }
    }
}

/// Streaming decryption pipeline using cryypt cipher API
///
/// # Errors
///
/// Returns an error if:
/// - Decryption operation fails  
/// - Invalid decryption key
/// - Corrupted or invalid encrypted data
/// - Unsupported encryption algorithm
pub async fn decrypt_payload_stream(
    data: Vec<u8>,
    metadata: &EncryptionMetadata,
    key: Vec<u8>,
) -> crate::Result<Vec<u8>> {
    match metadata.algorithm.as_str() {
        "aes-256-gcm" => {
            let data_was_empty = data.is_empty();
            let decrypted = Cipher::aes()
                .with_key(key)
                .on_result(|result| match result {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!("AES decryption failed: {}", e);
                        Vec::new() // Return empty Vec on error, will be checked later
                    }
                })
                .decrypt(data)
                .await;

            // Check if decryption failed (empty result indicates error only if input wasn't empty)
            if decrypted.is_empty() && !data_was_empty {
                return Err(CryptoTransportError::Internal(
                    "AES decryption failed - produced empty result for non-empty input".to_string(),
                ));
            }

            Ok(decrypted)
        }
        "chacha20-poly1305" => {
            let data_was_empty = data.is_empty();
            let decrypted = Cipher::chacha20()
                .with_key(key)
                .on_result(|result| match result {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!("ChaCha20 decryption failed: {}", e);
                        Vec::new() // Return empty Vec on error, will be checked later
                    }
                })
                .decrypt(data)
                .await;

            // Check if decryption failed (empty result indicates error only if input wasn't empty)
            if decrypted.is_empty() && !data_was_empty {
                return Err(CryptoTransportError::Internal(
                    "ChaCha20 decryption failed - produced empty result for non-empty input"
                        .to_string(),
                ));
            }

            Ok(decrypted)
        }
        "none" => Ok(data), // No decryption needed
        _ => Err(CryptoTransportError::Internal(format!(
            "Unsupported encryption algorithm: {}",
            metadata.algorithm
        ))),
    }
}
