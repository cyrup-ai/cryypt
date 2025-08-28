//! Message processing pipeline with compression and encryption

use futures::StreamExt;
use rand::RngCore;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use super::types::{CompressionAlgorithm, CompressionMetadata, EncryptionAlgorithm, EncryptionMetadata};
use cryypt_compression::Compress;
use cryypt_cipher::Cipher;
use crate::error::CryptoTransportError;

/// Calculate checksum for message integrity verification
pub fn calculate_checksum(data: &[u8]) -> u32 {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish() as u32
}

/// Generate encryption key from QUIC connection ID and shared secret
pub fn derive_connection_key(conn_id: &[u8], shared_secret: &[u8]) -> Vec<u8> {
    // Simple key derivation using HKDF-like approach
    let mut hasher = DefaultHasher::new();
    hasher.write(b"cryypt-quic-messaging-v1");
    hasher.write(conn_id);
    hasher.write(shared_secret);
    
    let hash = hasher.finish();
    let mut key = vec![0u8; 32]; // 256-bit key
    
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = ((hash >> (i % 8 * 8)) & 0xFF) as u8;
    }
    
    key
}

/// Streaming compression pipeline using cryypt compression API
pub async fn compress_payload_stream(
    data: Vec<u8>,
    algorithm: CompressionAlgorithm,
    level: u8,
) -> crate::Result<(Vec<u8>, CompressionMetadata)> {
    let original_size = data.len();
    let timestamp = std::time::SystemTime::now();
    
    match algorithm {
        CompressionAlgorithm::Zstd => {
            let mut compressed_chunks = Vec::new();
            let mut chunk_count = 0;
            
            // Use cryypt streaming compression API with 64KB chunks
            let stream = Compress::zstd()
                .with_level(level)
                .on_chunk(|result| match result {
                    Ok(chunk) => {
                        tracing::debug!("Processing Zstd compressed chunk: {} bytes", chunk.len());
                        chunk.into()
                    }
                    Err(e) => {
                        tracing::error!("Zstd chunk compression failed: {}", e);
                        panic!("Critical Zstd chunk compression failure")
                    }
                })
                .compress(data);
            
            let mut pinned_stream = Box::pin(stream);
            
            while let Some(chunk) = pinned_stream.next().await {
                if !chunk.is_empty() {
                    compressed_chunks.extend_from_slice(&chunk);
                    chunk_count += 1;
                }
            }
            
            let compressed_size = compressed_chunks.len();
            let algorithm_name = "zstd".to_string();
            
            let metadata = CompressionMetadata {
                algorithm: algorithm_name,
                level,
                original_size,
                compressed_size,
                chunks: chunk_count,
                timestamp,
            };
            
            Ok((compressed_chunks, metadata))
        }
        CompressionAlgorithm::None => {
            // No compression - return original data with metadata
            let metadata = CompressionMetadata {
                algorithm: "none".to_string(),
                level: 0,
                original_size,
                compressed_size: original_size,
                chunks: 1,
                timestamp,
            };
            Ok((data, metadata))
        }
    }
}

/// Streaming decompression pipeline using cryypt compression API
pub async fn decompress_payload_stream(
    data: Vec<u8>,
    metadata: &CompressionMetadata,
) -> crate::Result<Vec<u8>> {
    match metadata.algorithm.as_str() {
        "zstd" => {
            let mut decompressed_chunks = Vec::new();
            
            // Use cryypt streaming decompression API
            let stream = Compress::zstd()
                .on_chunk(|result| match result {
                    Ok(chunk) => {
                        tracing::debug!("Processing Zstd decompressed chunk: {} bytes", chunk.len());
                        chunk.into()
                    }
                    Err(e) => {
                        tracing::error!("Zstd chunk decompression failed: {}", e);
                        panic!("Critical Zstd chunk decompression failure")
                    }
                })
                .decompress(data);
            
            let mut pinned_stream = Box::pin(stream);
            
            while let Some(chunk) = pinned_stream.next().await {
                if !chunk.is_empty() {
                    decompressed_chunks.extend_from_slice(&chunk);
                }
            }
            
            // Verify decompressed size matches expected
            if decompressed_chunks.len() != metadata.original_size {
                return Err(CryptoTransportError::Internal(
                    format!("Decompressed size mismatch: expected {}, got {}", 
                        metadata.original_size, decompressed_chunks.len())
                ));
            }
            
            Ok(decompressed_chunks)
        }
        "none" => Ok(data), // No decompression needed
        _ => Err(CryptoTransportError::Internal(
            format!("Unsupported compression algorithm: {}", metadata.algorithm)
        ))
    }
}

/// Streaming encryption pipeline using cryypt cipher API  
pub async fn encrypt_payload_stream(
    data: Vec<u8>,
    algorithm: EncryptionAlgorithm,
    key: Vec<u8>,
    key_id: String,
) -> crate::Result<(Vec<u8>, EncryptionMetadata)> {
    let timestamp = std::time::SystemTime::now();
    
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm => {
            // Generate random nonce for AES-GCM
            let mut nonce = vec![0u8; 12]; // 96-bit nonce for AES-GCM
            rand::rng().fill_bytes(&mut nonce);
            
            let mut encrypted_chunks = Vec::new();
            let mut chunk_count = 0;
            let mut auth_tag = Vec::new();
            
            // Use cryypt streaming encryption API with 64KB chunks
            let stream = Cipher::aes()
                .with_key(key)
                .on_chunk(|result| match result {
                    Ok(chunk) => {
                        tracing::debug!("Processing AES encrypted chunk: {} bytes", chunk.len());
                        chunk.into()
                    },
                    Err(e) => {
                        tracing::error!("AES chunk encryption failed: {}", e);
                        panic!("Critical AES chunk encryption failure")
                    }
                })
                .encrypt(data);
            
            let mut pinned_stream = Box::pin(stream);
            
            while let Some(chunk) = pinned_stream.next().await {
                if !chunk.is_empty() {
                    // For AES-GCM, extract auth tag from final chunk
                    if chunk.len() >= 16 {
                        let chunk_len = chunk.len();
                        auth_tag = chunk[chunk_len-16..].to_vec();
                        encrypted_chunks.extend_from_slice(&chunk[..chunk_len-16]);
                    } else {
                        encrypted_chunks.extend_from_slice(&chunk);
                    }
                    chunk_count += 1;
                }
            }
            
            let metadata = EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id,
                nonce,
                chunks: chunk_count,
                auth_tag,
                timestamp,
            };
            
            Ok((encrypted_chunks, metadata))
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            // Generate random nonce for ChaCha20-Poly1305
            let mut nonce = vec![0u8; 12]; // 96-bit nonce for ChaCha20-Poly1305
            rand::rng().fill_bytes(&mut nonce);
            
            let mut encrypted_chunks = Vec::new();
            let mut chunk_count = 0;
            let mut auth_tag = Vec::new();
            
            // Use cryypt streaming encryption API with ChaCha20
            let stream = Cipher::chacha20()
                .with_key(key)
                .on_chunk(|result| match result {
                    Ok(chunk) => {
                        tracing::debug!("Processing ChaCha20 encrypted chunk: {} bytes", chunk.len());
                        chunk.into()
                    }
                    Err(e) => {
                        tracing::error!("ChaCha20 chunk encryption failed: {}", e);
                        panic!("Critical ChaCha20 chunk encryption failure")
                    }
                })
                .encrypt(data);
            
            let mut pinned_stream = Box::pin(stream);
            
            while let Some(chunk) = pinned_stream.next().await {
                if !chunk.is_empty() {
                    // For ChaCha20-Poly1305, extract auth tag from final chunk
                    if chunk.len() >= 16 {
                        let chunk_len = chunk.len();
                        auth_tag = chunk[chunk_len-16..].to_vec();
                        encrypted_chunks.extend_from_slice(&chunk[..chunk_len-16]);
                    } else {
                        encrypted_chunks.extend_from_slice(&chunk);
                    }
                    chunk_count += 1;
                }
            }
            
            let metadata = EncryptionMetadata {
                algorithm: "chacha20-poly1305".to_string(),
                key_id,
                nonce,
                chunks: chunk_count,
                auth_tag,
                timestamp,
            };
            
            Ok((encrypted_chunks, metadata))
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
pub async fn decrypt_payload_stream(
    data: Vec<u8>,
    metadata: &EncryptionMetadata,
    key: Vec<u8>,
) -> crate::Result<Vec<u8>> {
    match metadata.algorithm.as_str() {
        "aes-256-gcm" => {
            // Reconstruct encrypted data with auth tag
            let mut encrypted_with_tag = data;
            encrypted_with_tag.extend_from_slice(&metadata.auth_tag);
            
            let mut decrypted_chunks = Vec::new();
            
            // Use cryypt streaming decryption API
            let stream = Cipher::aes()
                .with_key(key)
                .on_chunk(|result| match result {
                    Ok(chunk) => {
                        tracing::debug!("Processing AES decrypted chunk: {} bytes", chunk.len());
                        chunk.into()
                    }
                    Err(e) => {
                        tracing::error!("AES chunk decryption failed: {}", e);
                        panic!("Critical AES chunk decryption failure")
                    }
                })
                .decrypt(encrypted_with_tag);
            
            let mut pinned_stream = Box::pin(stream);
            
            while let Some(chunk) = pinned_stream.next().await {
                if !chunk.is_empty() {
                    decrypted_chunks.extend_from_slice(&chunk);
                }
            }
            
            Ok(decrypted_chunks)
        }
        "chacha20-poly1305" => {
            // Reconstruct encrypted data with auth tag
            let mut encrypted_with_tag = data;
            encrypted_with_tag.extend_from_slice(&metadata.auth_tag);
            
            let mut decrypted_chunks = Vec::new();
            
            // Use cryypt streaming decryption API
            let stream = Cipher::chacha20()
                .with_key(key)
                .on_chunk(|result| match result {
                    Ok(chunk) => {
                        tracing::debug!("Processing ChaCha20 decrypted chunk: {} bytes", chunk.len());
                        chunk.into()
                    }
                    Err(e) => {
                        tracing::error!("ChaCha20 chunk decryption failed: {}", e);
                        panic!("Critical ChaCha20 chunk decryption failure")
                    }
                })
                .decrypt(encrypted_with_tag);
            
            let mut pinned_stream = Box::pin(stream);
            
            while let Some(chunk) = pinned_stream.next().await {
                if !chunk.is_empty() {
                    decrypted_chunks.extend_from_slice(&chunk);
                }
            }
            
            Ok(decrypted_chunks)
        }
        "none" => Ok(data), // No decryption needed
        _ => Err(CryptoTransportError::Internal(
            format!("Unsupported encryption algorithm: {}", metadata.algorithm)
        ))
    }
}

/// Combined compression and encryption pipeline (compress then encrypt)
pub async fn process_payload_forward(
    data: Vec<u8>,
    compression_alg: CompressionAlgorithm,
    compression_level: u8,
    encryption_alg: EncryptionAlgorithm,
    encryption_key: Vec<u8>,
    key_id: String,
) -> crate::Result<(Vec<u8>, Option<CompressionMetadata>, Option<EncryptionMetadata>)> {
    // Step 1: Compress the data
    let (compressed_data, compression_metadata) = if matches!(compression_alg, CompressionAlgorithm::None) {
        (data, None)
    } else {
        let (compressed, metadata) = compress_payload_stream(data, compression_alg, compression_level).await?;
        (compressed, Some(metadata))
    };
    
    // Step 2: Encrypt the compressed data
    let (final_data, encryption_metadata) = if matches!(encryption_alg, EncryptionAlgorithm::None) {
        (compressed_data, None)
    } else {
        let (encrypted, metadata) = encrypt_payload_stream(compressed_data, encryption_alg, encryption_key, key_id).await?;
        (encrypted, Some(metadata))
    };
    
    Ok((final_data, compression_metadata, encryption_metadata))
}

/// Combined decryption and decompression pipeline (decrypt then decompress)
pub async fn process_payload_reverse(
    data: Vec<u8>,
    compression_metadata: Option<&CompressionMetadata>,
    encryption_metadata: Option<&EncryptionMetadata>,
    encryption_key: Vec<u8>,
) -> crate::Result<Vec<u8>> {
    // Step 1: Decrypt the data if encrypted
    let decrypted_data = if let Some(enc_meta) = encryption_metadata {
        decrypt_payload_stream(data, enc_meta, encryption_key).await?
    } else {
        data
    };
    
    // Step 2: Decompress the decrypted data if compressed  
    let final_data = if let Some(comp_meta) = compression_metadata {
        decompress_payload_stream(decrypted_data, comp_meta).await?
    } else {
        decrypted_data
    };
    
    Ok(final_data)
}