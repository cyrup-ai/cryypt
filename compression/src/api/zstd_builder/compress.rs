//! Zstd compression and decompression operations following README.md patterns

use super::{ZstdBuilder, NoLevel, HasLevel};
use crate::{CompressionResult, CompressionAlgorithm, Result};
use crate::compression_on_result_impl;

impl ZstdBuilder<NoLevel> {
    /// Compress data using default level (3) - README.md pattern
    pub async fn compress<T: Into<Vec<u8>>>(self, data: T) -> Result<CompressionResult> {
        let data = data.into();
        let original_size = data.len();
        let level = 3; // Default level
        
        let result = zstd_compress(data, level).await.map(|compressed| {
            CompressionResult::with_original_size(
                compressed,
                CompressionAlgorithm::Zstd { level: Some(level) },
                original_size,
            )
        });
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
    
    /// Decompress data - README.md pattern
    pub async fn decompress<T: Into<Vec<u8>>>(self, data: T) -> Result<CompressionResult> {
        let data = data.into();
        
        let result = zstd_decompress(data).await.map(|decompressed| {
            CompressionResult::new(
                decompressed,
                CompressionAlgorithm::Zstd { level: None },
            )
        });
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
}

impl ZstdBuilder<HasLevel> {
    /// Compress data using configured level - README.md pattern
    pub async fn compress<T: Into<Vec<u8>>>(self, data: T) -> Result<CompressionResult> {
        let data = data.into();
        let original_size = data.len();
        let level = self.level.0;
        
        let result = zstd_compress(data, level).await.map(|compressed| {
            CompressionResult::with_original_size(
                compressed,
                CompressionAlgorithm::Zstd { level: Some(level) },
                original_size,
            )
        });
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
    
    /// Decompress data - README.md pattern
    pub async fn decompress<T: Into<Vec<u8>>>(self, data: T) -> Result<CompressionResult> {
        let data = data.into();
        
        let result = zstd_decompress(data).await.map(|decompressed| {
            CompressionResult::new(
                decompressed,
                CompressionAlgorithm::Zstd { level: None },
            )
        });
        
        if let Some(handler) = self.result_handler {
            handler(result)
        } else {
            result
        }
    }
}

// Internal compression functions - using true async with channels per ARCHITECTURE.md
async fn zstd_compress(data: Vec<u8>, level: i32) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        crate::zstd::compress_with_level(&data, level)
    })
    .await
    .map_err(|e| crate::CompressionError::internal(e.to_string()))?
}

async fn zstd_decompress(data: Vec<u8>) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        crate::zstd::decompress(&data)
    })
    .await
    .map_err(|e| crate::CompressionError::internal(e.to_string()))?
}