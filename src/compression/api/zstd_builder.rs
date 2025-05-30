//! Zstd compression builder

use super::{
    AsyncCompressResult, AsyncDecompressResult, CompressExecutor, DataBuilder, DecompressExecutor,
    LevelBuilder,
};

/// Initial Zstd builder
pub struct ZstdBuilder;

/// Zstd with data
pub struct ZstdWithData {
    data: Vec<u8>,
}

/// Zstd with data and level
pub struct ZstdWithDataAndLevel {
    data: Vec<u8>,
    level: i32,
}

// Initial builder
impl DataBuilder for ZstdBuilder {
    type Output = ZstdWithData;

    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        ZstdWithData { data: data.into() }
    }

    fn with_text<T: Into<String>>(self, text: T) -> Self::Output {
        ZstdWithData {
            data: text.into().into_bytes(),
        }
    }
}

// With data
impl LevelBuilder for ZstdWithData {
    type Output = ZstdWithDataAndLevel;

    fn with_level(self, level: u32) -> Self::Output {
        ZstdWithDataAndLevel {
            data: self.data,
            level: level as i32,
        }
    }
}

impl ZstdWithData {
    /// Maximum compression (level 22)
    pub fn max_compression(self) -> ZstdWithDataAndLevel {
        ZstdWithDataAndLevel {
            data: self.data,
            level: 22,
        }
    }
}

impl CompressExecutor for ZstdWithData {
    fn compress(self) -> impl AsyncCompressResult {
        // Default to high compression (level 19) for production
        // Not using 22 (max) as it has diminishing returns
        ZstdWithDataAndLevel {
            data: self.data,
            level: 19,
        }
        .compress()
    }
}

impl DecompressExecutor for ZstdWithData {
    fn decompress(self) -> impl AsyncDecompressResult {
        async move {
            tokio::task::spawn_blocking(move || crate::compression::zstd::decompress(&self.data))
                .await
                .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}

// With data and level
impl CompressExecutor for ZstdWithDataAndLevel {
    fn compress(self) -> impl AsyncCompressResult {
        async move {
            tokio::task::spawn_blocking(move || {
                crate::compression::zstd::compress_with_level(&self.data, self.level)
            })
            .await
            .map_err(|e| crate::CryptError::internal(e.to_string()))?
        }
    }
}
