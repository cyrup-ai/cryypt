//!
//! Contains the compression and decompression implementations for Gzip.

use super::{GzipBuilder, GzipBuilderWithChunk, GzipBuilderWithHandler, HasLevel, NoLevel};
use crate::{AsyncCompressionResult, CompressionAlgorithm, CompressionResult, Result};
use tokio::sync::oneshot;

impl GzipBuilder<NoLevel> {
    /// Compress data using default compression level
    #[must_use]
    pub fn compress<T: Into<Vec<u8>>>(self, data: T) -> AsyncCompressionResult {
        let data = data.into();
        let original_size = data.len();
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = match gzip_compress_async(data, flate2::Compression::default()).await {
                Ok((compressed, _)) => Ok(CompressionResult::with_original_size(
                    compressed,
                    CompressionAlgorithm::Gzip { level: Some(6) }, // Default gzip level
                    original_size,
                )),
                Err(e) => {
                    let error = match error_handler {
                        Some(handler) => handler(e),
                        None => e,
                    };
                    Err(error)
                }
            };

            let _ = tx.send(result);
        });

        AsyncCompressionResult::new(rx)
    }

    /// Decompress data
    #[must_use]
    pub fn decompress<T: Into<Vec<u8>>>(self, data: T) -> AsyncCompressionResult {
        let data = data.into();
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = match gzip_decompress_async(data).await {
                Ok(decompressed) => Ok(CompressionResult::new(
                    decompressed,
                    CompressionAlgorithm::Gzip { level: None },
                )),
                Err(e) => {
                    let error = match error_handler {
                        Some(handler) => handler(e),
                        None => e,
                    };
                    Err(error)
                }
            };

            let _ = tx.send(result);
        });

        AsyncCompressionResult::new(rx)
    }
}

impl GzipBuilder<HasLevel> {
    /// Compress data using specified compression level
    #[must_use]
    pub fn compress<T: Into<Vec<u8>>>(self, data: T) -> AsyncCompressionResult {
        let data = data.into();
        let original_size = data.len();
        let level = self.level.0;
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let flate_level = flate2::Compression::new(level);
            let result = match gzip_compress_async(data, flate_level).await {
                Ok((compressed, _)) => Ok(CompressionResult::with_original_size(
                    compressed,
                    CompressionAlgorithm::Gzip { level: Some(level) },
                    original_size,
                )),
                Err(e) => {
                    let error = match error_handler {
                        Some(handler) => handler(e),
                        None => e,
                    };
                    Err(error)
                }
            };

            let _ = tx.send(result);
        });

        AsyncCompressionResult::new(rx)
    }
}

// Handler implementations for unwrapping pattern
impl<F, T> GzipBuilderWithHandler<NoLevel, F, T>
where
    F: Fn(Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compress data using default compression level
    pub async fn compress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let _original_size = data.len();

        let result = gzip_compress_async(data, flate2::Compression::default())
            .await
            .map(|(compressed, _)| compressed); // Convert to Vec<u8>

        (self.result_handler)(result)
    }

    /// Decompress data
    pub async fn decompress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();

        let result = gzip_decompress_async(data).await; // Already Vec<u8>

        (self.result_handler)(result)
    }
}

impl<F, T> GzipBuilderWithHandler<HasLevel, F, T>
where
    F: Fn(Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compress data using specified compression level
    pub async fn compress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let _original_size = data.len();
        let level = self.level.0;

        let flate_level = flate2::Compression::new(level);
        let result = gzip_compress_async(data, flate_level)
            .await
            .map(|(compressed, _)| compressed); // Convert to Vec<u8>

        (self.result_handler)(result)
    }
}

// Chunked streaming implementations
impl<F> GzipBuilderWithChunk<NoLevel, F>
where
    F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Compress data in chunks - returns stream of compressed chunks
    pub fn compress<T: Into<Vec<u8>>>(self, data: T) -> impl futures::Stream<Item = Vec<u8>> {
        use tokio::sync::mpsc;

        let data = data.into();
        let handler = self.chunk_handler;

        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

            for chunk in data.chunks(CHUNK_SIZE) {
                // Compress each chunk independently
                let result =
                    gzip_compress_chunk(chunk.to_vec(), flate2::Compression::default()).await;
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break;
                }
            }
        });

        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    /// Decompress chunked data - returns stream of decompressed chunks
    pub fn decompress_stream<T: Into<Vec<u8>>>(
        self,
        data: T,
    ) -> impl futures::Stream<Item = Vec<u8>> {
        use tokio::sync::mpsc;

        let data = data.into();
        let handler = self.chunk_handler;

        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            let mut offset = 0;

            while offset < data.len() {
                // Read chunk length (4 bytes)
                if offset + 4 > data.len() {
                    let error_result = Err(crate::CompressionError::internal(
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
                    let error_result = Err(crate::CompressionError::internal(
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

                // Decompress this chunk
                let result = gzip_decompress_async(chunk_data.to_vec()).await;
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break;
                }
            }
        });

        tokio_stream::wrappers::ReceiverStream::new(rx)
    }
}

impl<F> GzipBuilderWithChunk<HasLevel, F>
where
    F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Compress data in chunks - returns stream of compressed chunks
    pub fn compress<T: Into<Vec<u8>>>(self, data: T) -> impl futures::Stream<Item = Vec<u8>> {
        use tokio::sync::mpsc;

        let data = data.into();
        let level = self.level.0;
        let handler = self.chunk_handler;

        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

            for chunk in data.chunks(CHUNK_SIZE) {
                // Compress each chunk with specified level
                let flate_level = flate2::Compression::new(level);
                let result = gzip_compress_chunk(chunk.to_vec(), flate_level).await;
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break;
                }
            }
        });

        tokio_stream::wrappers::ReceiverStream::new(rx)
    }
}

// True async compression using cooperative yielding
async fn gzip_compress_async(
    data: Vec<u8>,
    level: flate2::Compression,
) -> Result<(Vec<u8>, usize)> {
    use flate2::write::GzEncoder;
    use std::io::Write;

    const CHUNK_SIZE: usize = 8192;
    let original_size = data.len();

    // Yield for large data processing
    if data.len() > CHUNK_SIZE {
        tokio::task::yield_now().await;
    }

    let result = (|| {
        let mut encoder = GzEncoder::new(Vec::new(), level);
        encoder.write_all(&data)?;
        Ok((encoder.finish()?, original_size))
    })()
    .map_err(|e: std::io::Error| crate::CompressionError::internal(e.to_string()));

    // Yield after compression for large results
    if let Ok((ref compressed, _)) = result
        && compressed.len() > CHUNK_SIZE
    {
        tokio::task::yield_now().await;
    }

    result
}

async fn gzip_decompress_async(data: Vec<u8>) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    // Yield for large data processing
    const CHUNK_SIZE: usize = 8192;
    if data.len() > CHUNK_SIZE {
        tokio::task::yield_now().await;
    }

    let result = (|| {
        let mut decoder = GzDecoder::new(&data[..]);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;
        Ok(output)
    })()
    .map_err(|e: std::io::Error| crate::CompressionError::internal(e.to_string()));

    // Yield after decompression for large results
    if let Ok(ref decompressed) = result
        && decompressed.len() > CHUNK_SIZE
    {
        tokio::task::yield_now().await;
    }

    result
}

// Chunk-specific compression function for streaming
async fn gzip_compress_chunk(data: Vec<u8>, level: flate2::Compression) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use std::io::Write;

    // Yield for processing
    tokio::task::yield_now().await;

    let compressed = (|| {
        let mut encoder = GzEncoder::new(Vec::new(), level);
        encoder.write_all(&data)?;
        encoder.finish()
    })()
    .map_err(|e: std::io::Error| crate::CompressionError::internal(e.to_string()))?;

    // Build chunk result: [CHUNK_LEN(4)][COMPRESSED_DATA]
    let mut result = Vec::new();
    result.extend_from_slice(&u32::try_from(compressed.len()).unwrap_or(0).to_le_bytes());
    result.extend_from_slice(&compressed);

    Ok(result)
}
