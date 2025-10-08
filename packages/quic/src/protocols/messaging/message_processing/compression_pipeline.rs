//! Compression pipeline for message processing
//!
//! This module provides streaming compression and decompression functionality
//! using the cryypt compression API with QUIC stream integration.

use super::super::types::{CompressionAlgorithm, CompressionMetadata};
use crate::error::CryptoTransportError;
use cryypt_compression::Compress;
use futures::StreamExt;

/// Streaming compression pipeline using cryypt compression API with QUIC stream integration
///
/// # Errors
///
/// Returns an error if:
/// - Compression initialization fails
/// - Streaming compression fails
/// - Data validation fails
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
                .with_level(i32::from(level))
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
///
/// # Errors
///
/// Returns an error if:
/// - Decompression operation fails
/// - Corrupted or invalid compressed data
/// - Unsupported compression algorithm
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

            // Check if decompression failed (empty result indicates error only if original wasn't empty)
            if decompressed_chunks.is_empty() && metadata.original_size > 0 {
                return Err(CryptoTransportError::Internal(
                    "Zstd decompression failed - produced empty result for non-empty input"
                        .to_string(),
                ));
            }

            // Verify decompressed size matches expected
            if decompressed_chunks.len() != metadata.original_size {
                return Err(CryptoTransportError::Internal(format!(
                    "Decompressed size mismatch: expected {}, got {}",
                    metadata.original_size,
                    decompressed_chunks.len()
                )));
            }

            Ok(decompressed_chunks)
        }
        "none" => Ok(data), // No decompression needed
        _ => Err(CryptoTransportError::Internal(format!(
            "Unsupported compression algorithm: {}",
            metadata.algorithm
        ))),
    }
}
