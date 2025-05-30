//! Zip compression builder

use super::{
    AsyncCompressResult, AsyncDecompressResult, CompressExecutor, DataBuilder, DecompressExecutor,
    LevelBuilder,
};

/// Initial Zip builder
pub struct ZipBuilder;

/// Zip with data
pub struct ZipWithData {
    data: Vec<u8>,
}

/// Zip with data and level
pub struct ZipWithDataAndLevel {
    data: Vec<u8>,
    level: u32,
}

// Initial builder
impl DataBuilder for ZipBuilder {
    type Output = ZipWithData;

    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        ZipWithData { data: data.into() }
    }

    fn with_text<T: Into<String>>(self, text: T) -> Self::Output {
        ZipWithData {
            data: text.into().into_bytes(),
        }
    }
}

// With data
impl LevelBuilder for ZipWithData {
    type Output = ZipWithDataAndLevel;

    fn with_level(self, level: u32) -> Self::Output {
        ZipWithDataAndLevel {
            data: self.data,
            level: level.min(9), // Clamp to valid range
        }
    }
}

impl ZipWithData {
    /// Maximum compression (level 9)
    pub fn max_compression(self) -> ZipWithDataAndLevel {
        self.with_level(9)
    }
}

impl CompressExecutor for ZipWithData {
    fn compress(self) -> impl AsyncCompressResult {
        async move {
            tokio::task::spawn_blocking(move || crate::compression::zip::compress(&self.data))
                .await
                .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}

impl DecompressExecutor for ZipWithData {
    fn decompress(self) -> impl AsyncDecompressResult {
        async move {
            tokio::task::spawn_blocking(move || crate::compression::zip::decompress(&self.data))
                .await
                .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}

// With data and level
impl CompressExecutor for ZipWithDataAndLevel {
    fn compress(self) -> impl AsyncCompressResult {
        async move {
            tokio::task::spawn_blocking(move || {
                crate::compression::zip::compress_with_level(&self.data, self.level as i32)
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}
