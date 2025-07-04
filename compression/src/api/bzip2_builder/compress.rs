//! Bzip2 compression and decompression operations
//!
//! Contains the main compress/decompress methods for both NoLevel and HasLevel builders.

use super::{Bzip2Builder, NoLevel, HasLevel};
use crate::{CompressionResult, CompressionAlgorithm, Result};

// Compression methods for builder without specific level (uses default level 9)
impl Bzip2Builder<NoLevel> {
    /// Compress the provided data using default level (9)
    pub async fn compress<T: Into<Vec<u8>>>(self, data: T) -> Result<CompressionResult> {
        let data = data.into();
        let original_size = data.len();
        let level = 9; // Default level (maximum compression)
        
        let result = bzip2_compress(data, level).await.map(|compressed| {
            CompressionResult::with_original_size(
                compressed,
                CompressionAlgorithm::Bzip2 { level: Some(level) },
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
        
        let result = bzip2_decompress(data).await.map(|decompressed| {
            CompressionResult::new(
                decompressed,
                CompressionAlgorithm::Bzip2 { level: None },
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
impl Bzip2Builder<HasLevel> {
    /// Compress the provided data using the configured level
    pub async fn compress<T: Into<Vec<u8>>>(self, data: T) -> Result<CompressionResult> {
        let data = data.into();
        let original_size = data.len();
        let level = self.level.0;
        
        let result = bzip2_compress(data, level).await.map(|compressed| {
            CompressionResult::with_original_size(
                compressed,
                CompressionAlgorithm::Bzip2 { level: Some(level) },
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
        
        let result = bzip2_decompress(data).await.map(|decompressed| {
            CompressionResult::new(
                decompressed,
                CompressionAlgorithm::Bzip2 { level: None },
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
async fn bzip2_compress(data: Vec<u8>, level: u32) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        crate::bzip2::compress(&data, level).map_err(|e| {
            crate::CompressionError::internal(format!("Bzip2 compression failed: {}", e))
        })
    })
    .await
    .map_err(|e| crate::CompressionError::internal(e.to_string()))?
}

async fn bzip2_decompress(data: Vec<u8>) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        crate::bzip2::decompress(&data).map_err(|e| {
            crate::CompressionError::internal(format!("Bzip2 decompression failed: {}", e))
        })
    })
    .await
    .map_err(|e| crate::CompressionError::internal(e.to_string()))?
}