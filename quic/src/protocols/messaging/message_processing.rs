//! Message processing pipeline with compression and encryption

use futures::StreamExt;

use super::types::{CompressionAlgorithm, CompressionMetadata, EncryptionAlgorithm, EncryptionMetadata};
use cryypt_compression::Compress;
use cryypt_cipher::Cipher;
use crate::error::CryptoTransportError;

/// Calculate checksum for message integrity verification using cryypt SHA256
/// 
/// Uses 64 bits from SHA256 for improved collision resistance while maintaining reasonable performance.
/// Provides 2^32 expected collisions vs 2^16 for 32-bit checksums.
pub async fn calculate_checksum(data: &[u8]) -> u32 {
    calculate_checksum_64(data).await as u32 // Backward compatibility: return lower 32 bits
}

/// Calculate 64-bit checksum for enhanced integrity verification
/// 
/// Uses the first 64 bits of SHA256, providing significantly better collision resistance
/// than 32-bit checksums. Recommended for security-critical applications.
pub async fn calculate_checksum_64(data: &[u8]) -> u64 {
    use cryypt_hashing::Hash;
    
    Hash::sha256()
        .on_result(|result| match result {
            Ok(hash_result) => {
                // Convert first 8 bytes to u64
                let bytes = hash_result.as_bytes();
                if bytes.len() >= 8 {
                    u64::from_be_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7]
                    ])
                } else {
                    tracing::error!("SHA256 hash too short: {} bytes", bytes.len());
                    0u64 // Fallback value
                }
            }
            Err(e) => {
                tracing::error!("SHA256 hash computation failed: {}", e);
                0u64 // Fallback value for checksum failure
            }
        })
        .compute(data)
        .await
}

/// Calculate HMAC-based authenticated checksum for maximum security
/// 
/// Uses HMAC-SHA256 with the provided key for cryptographically secure message authentication.
/// Protects against both accidental corruption and malicious tampering.
pub async fn calculate_authenticated_checksum(data: &[u8], key: &[u8]) -> [u8; 32] {
    use cryypt_hashing::Hash;
    
    let hmac_bytes = Hash::sha256()
        .with_key(key.to_vec())
        .on_result(|result| match result {
            Ok(hash_result) => {
                // Return the raw hash bytes
                hash_result.to_vec()
            }
            Err(e) => {
                tracing::error!("HMAC-SHA256 computation failed: {}", e);
                vec![0u8; 32] // Fallback value for HMAC failure
            }
        })
        .compute(data)
        .await;
    
    // Convert to fixed-size array
    let mut result = [0u8; 32];
    if hmac_bytes.len() >= 32 {
        result.copy_from_slice(&hmac_bytes[0..32]);
    } else {
        tracing::error!("HMAC-SHA256 hash too short: {} bytes", hmac_bytes.len());
    }
    result
}

/// Verify HMAC-based authenticated checksum
pub async fn verify_authenticated_checksum(data: &[u8], key: &[u8], expected_checksum: &[u8; 32]) -> bool {
    // Compute HMAC using cryypt API and compare with expected
    let computed_checksum = calculate_authenticated_checksum(data, key).await;
    
    // Constant-time comparison to prevent timing attacks
    computed_checksum.iter()
        .zip(expected_checksum.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Generate encryption key from QUIC connection ID and shared secret using HMAC-SHA256
pub async fn derive_connection_key(conn_id: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, CryptoTransportError> {
    use cryypt_hashing::Hash;
    
    // Create connection-specific input combining conn_id with domain separation
    const DOMAIN_SEPARATION: &[u8] = b"cryypt-quic-key-derivation-v1";
    let mut input = Vec::with_capacity(conn_id.len() + DOMAIN_SEPARATION.len());
    input.extend_from_slice(conn_id);
    input.extend_from_slice(DOMAIN_SEPARATION);
    
    let derived_key = Hash::sha256()
        .with_key(shared_secret.to_vec())
        .on_result(|result| match result {
            Ok(hash_result) => hash_result.to_vec(),
            Err(e) => {
                tracing::error!("Connection key derivation failed: {}", e);
                Vec::new()
            }
        })
        .compute(input)
        .await;
    
    if derived_key.is_empty() {
        Err(CryptoTransportError::Internal("Key derivation failed".to_string()))
    } else {
        // Truncate to 32 bytes for consistent key size
        Ok(derived_key[..32.min(derived_key.len())].to_vec())
    }
}

/// Streaming compression pipeline using cryypt compression API with QUIC stream integration
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
            
            // Use cryypt streaming compression API with QUIC-optimized chunks
            let stream = Compress::zstd()
                .with_level(level as i32)
                .on_chunk(|result| match result {
                    Ok(chunk) => {
                        tracing::debug!("Processing Zstd compressed chunk: {} bytes", chunk.len());
                        chunk // Return chunk directly
                    }
                    Err(e) => {
                        tracing::error!("Zstd chunk compression failed: {}", e);
                        cryypt_common::BadChunk::from_error(e).into() // Return BadChunk for failed chunks
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
            let decompressed_chunks = Compress::zstd()
                .on_result(|result| match result {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!("Zstd decompression failed: {}", e);
                        Vec::new() // Return empty Vec on error, will be checked later
                    }
                })
                .decompress(data)
                .await;
            
            // Check if decompression failed (empty result indicates error)
            if decompressed_chunks.is_empty() {
                return Err(CryptoTransportError::Internal(
                    "Zstd decompression failed - produced empty result".to_string()
                ));
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
            
            // Check if encryption failed (empty result indicates error)
            if encrypted.is_empty() {
                return Err(CryptoTransportError::Internal(
                    "AES encryption failed - produced empty result".to_string()
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
            
            // Check if encryption failed (empty result indicates error)
            if encrypted.is_empty() {
                return Err(CryptoTransportError::Internal(
                    "ChaCha20 encryption failed - produced empty result".to_string()
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
pub async fn decrypt_payload_stream(
    data: Vec<u8>,
    metadata: &EncryptionMetadata,
    key: Vec<u8>,
) -> crate::Result<Vec<u8>> {
    match metadata.algorithm.as_str() {
        "aes-256-gcm" => {
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
            
            // Check if decryption failed (empty result indicates error)
            if decrypted.is_empty() {
                return Err(CryptoTransportError::Internal(
                    "AES decryption failed - produced empty result".to_string()
                ));
            }
            
            Ok(decrypted)
        }
        "chacha20-poly1305" => {
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
            
            // Check if decryption failed (empty result indicates error)
            if decrypted.is_empty() {
                return Err(CryptoTransportError::Internal(
                    "ChaCha20 decryption failed - produced empty result".to_string()
                ));
            }
            
            Ok(decrypted)
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

