//! Gzip compression builder

use super::{DataBuilder, LevelBuilder, CompressExecutor, DecompressExecutor, AsyncCompressResult, AsyncDecompressResult};

/// Initial Gzip builder
pub struct GzipBuilder;

/// Gzip with data
pub struct GzipWithData {
    data: Vec<u8>,
}

/// Gzip with data and level
pub struct GzipWithDataAndLevel {
    data: Vec<u8>,
    level: u32,
}

// Initial builder
impl DataBuilder for GzipBuilder {
    type Output = GzipWithData;
    
    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        GzipWithData {
            data: data.into(),
        }
    }
    
    fn with_text<T: Into<String>>(self, text: T) -> Self::Output {
        GzipWithData {
            data: text.into().into_bytes(),
        }
    }
}

// With data
impl LevelBuilder for GzipWithData {
    type Output = GzipWithDataAndLevel;
    
    fn with_level(self, level: u32) -> Self::Output {
        GzipWithDataAndLevel {
            data: self.data,
            level: level.min(9), // Clamp to valid range
        }
    }
}

impl GzipWithData {
    /// Maximum compression (level 9)
    pub fn max_compression(self) -> GzipWithDataAndLevel {
        self.with_level(9)
    }
}

impl CompressExecutor for GzipWithData {
    fn compress(self) -> impl AsyncCompressResult {
        // Default to maximum compression (level 9) for production
        GzipWithDataAndLevel {
            data: self.data,
            level: 9,
        }.compress()
    }
}

impl DecompressExecutor for GzipWithData {
    fn decompress(self) -> impl AsyncDecompressResult {
        async move {
            tokio::task::spawn_blocking(move || {
                crate::compression::gzip::decompress(&self.data)
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}

// With data and level
impl CompressExecutor for GzipWithDataAndLevel {
    fn compress(self) -> impl AsyncCompressResult {
        async move {
            tokio::task::spawn_blocking(move || {
                crate::compression::gzip::compress_with_level(&self.data, self.level as i32)
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}