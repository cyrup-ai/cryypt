//! Traits for the compression builder pattern

use crate::Result;
use std::future::Future;

/// Async result for compression operations
pub trait AsyncCompressResult: Future<Output = Result<Vec<u8>>> + Send {}
impl<T> AsyncCompressResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}

/// Async result for decompression operations
pub trait AsyncDecompressResult: Future<Output = Result<Vec<u8>>> + Send {}
impl<T> AsyncDecompressResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}

/// Trait for setting data to compress
pub trait DataBuilder {
    type Output;

    /// Set the data to compress (as bytes)
    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output;

    /// Set the data to compress (as text)
    fn with_text<T: Into<String>>(self, text: T) -> Self::Output;
}

/// Trait for setting compression level
pub trait LevelBuilder {
    type Output;

    /// Set the compression level (0-9, where 0 is no compression and 9 is maximum)
    fn with_level(self, level: u32) -> Self::Output;
}

/// Trait for executing the compression operation
pub trait CompressExecutor {
    /// Execute the compression operation
    fn compress(self) -> impl AsyncCompressResult;
}

/// Trait for decompression operations
pub trait DecompressExecutor {
    /// Execute the decompression operation
    fn decompress(self) -> impl AsyncDecompressResult;
}
