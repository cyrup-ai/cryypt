//! Combined processing pipelines for message processing
//!
//! This module provides high-level functions that combine compression and encryption
//! operations in the correct order for message processing workflows.

use super::super::types::{
    CompressionAlgorithm, CompressionMetadata, EncryptionAlgorithm, EncryptionMetadata,
};
use super::compression_pipeline::{compress_payload_stream, decompress_payload_stream};
use super::encryption_pipeline::{decrypt_payload_stream, encrypt_payload_stream};

/// Combined compression and encryption pipeline (compress then encrypt)
///
/// # Errors
///
/// Returns an error if:
/// - Compression operations fail
/// - Encryption operations fail
/// - Key derivation fails
pub async fn process_payload_forward(
    data: Vec<u8>,
    compression_alg: CompressionAlgorithm,
    compression_level: u8,
    encryption_alg: EncryptionAlgorithm,
    encryption_key: Vec<u8>,
    key_id: String,
) -> crate::Result<(
    Vec<u8>,
    Option<CompressionMetadata>,
    Option<EncryptionMetadata>,
)> {
    // Step 1: Compress the data
    let (compressed_data, compression_metadata) =
        if matches!(compression_alg, CompressionAlgorithm::None) {
            (data, None)
        } else {
            let (compressed, metadata) =
                compress_payload_stream(data, compression_alg, compression_level).await?;
            (compressed, Some(metadata))
        };

    // Step 2: Encrypt the compressed data
    let (final_data, encryption_metadata) = if matches!(encryption_alg, EncryptionAlgorithm::None) {
        (compressed_data, None)
    } else {
        let (encrypted, metadata) =
            encrypt_payload_stream(compressed_data, encryption_alg, encryption_key, key_id).await?;
        (encrypted, Some(metadata))
    };

    Ok((final_data, compression_metadata, encryption_metadata))
}

/// Combined decryption and decompression pipeline (decrypt then decompress)
///
/// # Errors
///
/// Returns an error if:
/// - Decryption operations fail
/// - Decompression operations fail  
/// - Metadata validation fails
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
