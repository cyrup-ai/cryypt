//! Zstd compression and decompression operations following README.md patterns

use super::{HasLevel, NoLevel, ZstdBuilder, ZstdBuilderWithHandler};
use crate::{AsyncCompressionResult, CompressionAlgorithm, CompressionResult, Result};
use tokio::sync::oneshot;

impl ZstdBuilder<NoLevel> {
    /// Compress data using default level (3) - README.md pattern
    #[must_use]
    pub fn compress<T: Into<Vec<u8>>>(self, data: T) -> AsyncCompressionResult {
        let data = data.into();
        let original_size = data.len();
        let level = 3; // Default level

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = zstd_compress(data, level).await.map(|compressed| {
                CompressionResult::with_original_size(
                    compressed,
                    CompressionAlgorithm::Zstd { level: Some(level) },
                    original_size,
                )
            });
            let _ = tx.send(result);
        });

        AsyncCompressionResult::new(rx)
    }

    /// Decompress data - README.md pattern
    #[must_use]
    pub fn decompress<T: Into<Vec<u8>>>(self, data: T) -> AsyncCompressionResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = zstd_decompress(data).await.map(|decompressed| {
                CompressionResult::new(decompressed, CompressionAlgorithm::Zstd { level: None })
            });
            let _ = tx.send(result);
        });

        AsyncCompressionResult::new(rx)
    }
}

impl ZstdBuilder<HasLevel> {
    /// Compress data using configured level - README.md pattern
    #[must_use]
    pub fn compress<T: Into<Vec<u8>>>(self, data: T) -> AsyncCompressionResult {
        let data = data.into();
        let original_size = data.len();
        let level = self.level.0;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = zstd_compress(data, level).await.map(|compressed| {
                CompressionResult::with_original_size(
                    compressed,
                    CompressionAlgorithm::Zstd { level: Some(level) },
                    original_size,
                )
            });
            let _ = tx.send(result);
        });

        AsyncCompressionResult::new(rx)
    }

    /// Decompress data - README.md pattern
    #[must_use]
    pub fn decompress<T: Into<Vec<u8>>>(self, data: T) -> AsyncCompressionResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = zstd_decompress(data).await.map(|decompressed| {
                CompressionResult::new(decompressed, CompressionAlgorithm::Zstd { level: None })
            });
            let _ = tx.send(result);
        });

        AsyncCompressionResult::new(rx)
    }
}

// Internal compression functions - using true async with channels per ARCHITECTURE.md
pub(super) async fn zstd_compress(data: Vec<u8>, level: i32) -> Result<Vec<u8>> {
    let (tx, rx) = tokio::sync::oneshot::channel();

    std::thread::spawn(move || {
        let result = crate::zstd::compress_with_level(&data, level);
        let _ = tx.send(result);
    });

    rx.await
        .map_err(|_| crate::CompressionError::internal("Compression task failed"))?
}

pub(super) async fn zstd_decompress(data: Vec<u8>) -> Result<Vec<u8>> {
    let (tx, rx) = tokio::sync::oneshot::channel();

    std::thread::spawn(move || {
        let result = crate::zstd::decompress(&data);
        let _ = tx.send(result);
    });

    rx.await
        .map_err(|_| crate::CompressionError::internal("Decompression task failed"))?
}

// Handler implementations for CompressionResult pattern
impl<F, T> ZstdBuilderWithHandler<NoLevel, F, T>
where
    F: Fn(Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compress data using default level (3) - returns Vec<u8>
    pub async fn compress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let level = 3;

        let result = zstd_compress(data, level).await; // Already Vec<u8>

        (self.result_handler)(result)
    }

    /// Decompress data - returns Vec<u8>
    pub async fn decompress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();

        let result = zstd_decompress(data).await; // Already Vec<u8>

        (self.result_handler)(result)
    }
}

impl<F, T> ZstdBuilderWithHandler<HasLevel, F, T>
where
    F: Fn(Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compress data using configured level - returns Vec<u8>
    pub async fn compress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let level = self.level.0;

        let result = zstd_compress(data, level).await; // Already Vec<u8>

        (self.result_handler)(result)
    }

    /// Decompress data - returns Vec<u8>
    pub async fn decompress<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();

        let result = zstd_decompress(data).await; // Already Vec<u8>

        (self.result_handler)(result)
    }
}
