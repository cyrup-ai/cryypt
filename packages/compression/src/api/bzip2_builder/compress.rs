//! Bzip2 compression operations
//!
//! Contains the compression and decompression implementations for Bzip2.

use super::{Bzip2Builder, Bzip2BuilderWithHandler, HasLevel, NoLevel};
use crate::{AsyncCompressionResult, CompressionAlgorithm, CompressionResult, Result};
use tokio::sync::oneshot;

impl Bzip2Builder<NoLevel> {
    /// Compress data using default compression level
    #[must_use]
    pub fn compress<T: Into<Vec<u8>>>(self, data: T) -> AsyncCompressionResult {
        let data = data.into();
        let original_size = data.len();
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = match bzip2_compress_async(data, bzip2::Compression::default()).await {
                Ok((compressed, _)) => Ok(CompressionResult::with_original_size(
                    compressed,
                    CompressionAlgorithm::Bzip2 { level: Some(6) }, // Default bzip2 level
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
            let result = match bzip2_decompress_async(data).await {
                Ok(decompressed) => Ok(CompressionResult::new(
                    decompressed,
                    CompressionAlgorithm::Bzip2 { level: None },
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

impl Bzip2Builder<HasLevel> {
    /// Compress data using specified compression level
    #[must_use]
    pub fn compress<T: Into<Vec<u8>>>(self, data: T) -> AsyncCompressionResult {
        let data = data.into();
        let original_size = data.len();
        let level = self.level.0;
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let bz_level = bzip2::Compression::new(level);
            let result = match bzip2_compress_async(data, bz_level).await {
                Ok((compressed, _)) => Ok(CompressionResult::with_original_size(
                    compressed,
                    CompressionAlgorithm::Bzip2 { level: Some(level) },
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
            let result = match bzip2_decompress_async(data).await {
                Ok(decompressed) => Ok(CompressionResult::new(
                    decompressed,
                    CompressionAlgorithm::Bzip2 { level: None },
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
async fn bzip2_compress_async(
    data: Vec<u8>,
    level: bzip2::Compression,
) -> Result<(Vec<u8>, usize)> {
    let (tx, rx) = oneshot::channel();
    let original_size = data.len();

    std::thread::spawn(move || {
        let result = (|| {
            use bzip2::write::BzEncoder;
            use std::io::Write;

            let mut encoder = BzEncoder::new(Vec::new(), level);
            encoder.write_all(&data)?;
            Ok((encoder.finish()?, original_size))
        })()
        .map_err(|e: std::io::Error| crate::CompressionError::internal(e.to_string()));

        let _ = tx.send(result);
    });

    rx.await
        .map_err(|_| crate::CompressionError::internal("Compression task failed"))?
}

async fn bzip2_decompress_async(data: Vec<u8>) -> Result<Vec<u8>> {
    let (tx, rx) = oneshot::channel();

    std::thread::spawn(move || {
        let result = (|| {
            use bzip2::read::BzDecoder;
            use std::io::Read;

            let mut decoder = BzDecoder::new(&data[..]);
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
impl<F, T> Bzip2BuilderWithHandler<NoLevel, F, T>
where
    F: Fn(Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compress data using default compression level
    pub async fn compress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();

        let result = bzip2_compress_async(data, bzip2::Compression::default())
            .await
            .map(|(compressed, _)| compressed); // Convert to Vec<u8>

        (self.result_handler)(result)
    }

    /// Decompress data
    pub async fn decompress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();

        let result = bzip2_decompress_async(data).await; // Already Vec<u8>

        (self.result_handler)(result)
    }
}

impl<F, T> Bzip2BuilderWithHandler<HasLevel, F, T>
where
    F: Fn(Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compress data using specified compression level
    pub async fn compress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let level = self.level.0;

        let bz_level = bzip2::Compression::new(level);
        let result = bzip2_compress_async(data, bz_level)
            .await
            .map(|(compressed, _)| compressed); // Convert to Vec<u8>

        (self.result_handler)(result)
    }

    /// Decompress data
    pub async fn decompress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();

        let result = bzip2_decompress_async(data).await; // Already Vec<u8>

        (self.result_handler)(result)
    }
}
