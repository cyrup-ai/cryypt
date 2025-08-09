//! Gzip compression operations
//!
//! Contains the compression and decompression implementations for Gzip.

use super::{GzipBuilder, GzipBuilderWithHandler, HasLevel, NoLevel};
use crate::{AsyncCompressionResult, CompressionAlgorithm, CompressionResult, Result};
use tokio::sync::oneshot;

impl GzipBuilder<NoLevel> {
    /// Compress data using default compression level
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

    /// Decompress data
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

// True async compression using channels
async fn gzip_compress_async(
    data: Vec<u8>,
    level: flate2::Compression,
) -> Result<(Vec<u8>, usize)> {
    let (tx, rx) = oneshot::channel();
    let original_size = data.len();

    std::thread::spawn(move || {
        let result = (|| {
            use flate2::write::GzEncoder;
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::new(), level);
            encoder.write_all(&data)?;
            Ok((encoder.finish()?, original_size))
        })()
        .map_err(|e: std::io::Error| crate::CompressionError::internal(e.to_string()));

        let _ = tx.send(result);
    });

    rx.await
        .map_err(|_| crate::CompressionError::internal("Compression task failed"))?
}

async fn gzip_decompress_async(data: Vec<u8>) -> Result<Vec<u8>> {
    let (tx, rx) = oneshot::channel();

    std::thread::spawn(move || {
        let result = (|| {
            use flate2::read::GzDecoder;
            use std::io::Read;

            let mut decoder = GzDecoder::new(&data[..]);
            let mut output = Vec::new();
            decoder.read_to_end(&mut output)?;
            Ok(output)
        })()
        .map_err(|e: std::io::Error| crate::CompressionError::internal(e.to_string()));

        let _ = tx.send(result);
    });

    rx.await
        .map_err(|_| crate::CompressionError::internal("Decompression task failed"))?
}

// Handler implementations for unwrapping pattern
impl<F, T> GzipBuilderWithHandler<NoLevel, F, T>
where
    F: FnOnce(Result<CompressionResult>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compress data using default compression level
    pub async fn compress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let original_size = data.len();

        let result = gzip_compress_async(data, flate2::Compression::default())
            .await
            .map(|(compressed, _)| {
                CompressionResult::with_original_size(
                    compressed,
                    CompressionAlgorithm::Gzip { level: Some(6) },
                    original_size,
                )
            });

        (self.result_handler)(result)
    }

    /// Decompress data
    pub async fn decompress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();

        let result = gzip_decompress_async(data).await.map(|decompressed| {
            CompressionResult::new(decompressed, CompressionAlgorithm::Gzip { level: None })
        });

        (self.result_handler)(result)
    }
}

impl<F, T> GzipBuilderWithHandler<HasLevel, F, T>
where
    F: FnOnce(Result<CompressionResult>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compress data using specified compression level
    pub async fn compress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let original_size = data.len();
        let level = self.level.0;

        let flate_level = flate2::Compression::new(level);
        let result = gzip_compress_async(data, flate_level)
            .await
            .map(|(compressed, _)| {
                CompressionResult::with_original_size(
                    compressed,
                    CompressionAlgorithm::Gzip { level: Some(level) },
                    original_size,
                )
            });

        (self.result_handler)(result)
    }

    /// Decompress data
    pub async fn decompress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();

        let result = gzip_decompress_async(data).await.map(|decompressed| {
            CompressionResult::new(decompressed, CompressionAlgorithm::Gzip { level: None })
        });

        (self.result_handler)(result)
    }
}
