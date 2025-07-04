//! Zstd compression and decompression operations
//!
//! Contains the main compress/decompress methods for both NoLevel and HasLevel builders.

use super::{ZstdBuilder, NoLevel, HasLevel};
use crate::{CompressionResult, CompressionAlgorithm, Result};

// Compression methods for builder without specific level (uses default level 3)
impl ZstdBuilder<NoLevel> {
    /// Compress the provided data using default level (3)
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
    
    /// Decompress the provided data
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

// Compression methods for builder with specific level
impl ZstdBuilder<HasLevel> {
    /// Compress the provided data using the configured level
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
    
    /// Decompress the provided data
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

// Internal compression functions
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