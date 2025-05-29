//! Bzip2 compression builder

use super::{DataBuilder, LevelBuilder, CompressExecutor, DecompressExecutor, AsyncCompressResult, AsyncDecompressResult};

/// Initial Bzip2 builder
pub struct Bzip2Builder;

/// Bzip2 with data
pub struct Bzip2WithData {
    data: Vec<u8>,
}

/// Bzip2 with data and level
pub struct Bzip2WithDataAndLevel {
    data: Vec<u8>,
    level: u32,
}

// Initial builder
impl DataBuilder for Bzip2Builder {
    type Output = Bzip2WithData;
    
    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        Bzip2WithData {
            data: data.into(),
        }
    }
    
    fn with_text<T: Into<String>>(self, text: T) -> Self::Output {
        Bzip2WithData {
            data: text.into().into_bytes(),
        }
    }
}

// With data
impl LevelBuilder for Bzip2WithData {
    type Output = Bzip2WithDataAndLevel;
    
    fn with_level(self, level: u32) -> Self::Output {
        Bzip2WithDataAndLevel {
            data: self.data,
            level: level.min(9), // Clamp to valid range
        }
    }
}

impl Bzip2WithData {
    /// Maximum compression (level 9)
    pub fn max_compression(self) -> Bzip2WithDataAndLevel {
        self.with_level(9)
    }
    
    /// Balanced compression (level 6)
    pub fn balanced_compression(self) -> Bzip2WithDataAndLevel {
        self.with_level(6)
    }
}

impl CompressExecutor for Bzip2WithData {
    fn compress(self) -> impl AsyncCompressResult {
        // Default to maximum compression (level 9) for production
        Bzip2WithDataAndLevel {
            data: self.data,
            level: 9,
        }.compress()
    }
}

impl DecompressExecutor for Bzip2WithData {
    fn decompress(self) -> impl AsyncDecompressResult {
        async move {
            tokio::task::spawn_blocking(move || {
                crate::compression::bzip2::decompress(&self.data)
                    .map_err(|e| crate::CryptError::internal(format!("Bzip2 decompression failed: {}", e)))
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}

// With data and level
impl CompressExecutor for Bzip2WithDataAndLevel {
    fn compress(self) -> impl AsyncCompressResult {
        async move {
            tokio::task::spawn_blocking(move || {
                crate::compression::bzip2::compress(&self.data, self.level as u32)
                    .map_err(|e| crate::CryptError::internal(format!("Bzip2 compression failed: {}", e)))
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}