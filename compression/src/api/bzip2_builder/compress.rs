//! Bzip2 compression operations
//!
//! Contains the compression and decompression implementations for Bzip2.

use crate::{CompressionResult, CompressionAlgorithm, Result};
use super::{Bzip2Builder, NoLevel, HasLevel};
use std::future::Future;
use tokio::sync::oneshot;
use crate::compression_on_result_impl;

/// Apply result handler using compression_on_result_impl macro
#[allow(dead_code)]
pub(crate) fn apply_compression_result_handler() -> impl Fn(Result<CompressionResult>) -> Result<CompressionResult> {
    compression_on_result_impl!(|result| { Ok => Ok(result), Err(e) => Err(e) })
}

impl Bzip2Builder<NoLevel> {
    /// Compress data using default compression level
    pub fn compress(self, data: &[u8]) -> impl Future<Output = Result<CompressionResult>> {
        let data = data.to_vec();
        let handler = self.result_handler;
        
        async move {
            let compressed = bzip2_compress_async(data, bzip2::Compression::default()).await?;
            
            let result = Ok(CompressionResult::with_original_size(
                compressed.0,
                CompressionAlgorithm::Bzip2 { level: Some(6) }, // Default bzip2 level
                compressed.1,
            ));
            
            if let Some(handler) = handler {
                handler(result)
            } else {
                result
            }
        }
    }
    
    /// Decompress data
    pub fn decompress(self, data: &[u8]) -> impl Future<Output = Result<Vec<u8>>> {
        let data = data.to_vec();
        let handler = self.result_handler;
        
        async move {
            let decompressed = bzip2_decompress_async(data).await;
            
            let result = decompressed.map(|data| CompressionResult::new(
                data,
                CompressionAlgorithm::Bzip2 { level: None },
            ));
            
            if let Some(handler) = handler {
                handler(result).map(|r| r.to_vec())
            } else {
                result.map(|r| r.to_vec())
            }
        }
    }
}

impl Bzip2Builder<HasLevel> {
    /// Compress data using specified compression level
    pub fn compress(self, data: &[u8]) -> impl Future<Output = Result<CompressionResult>> {
        let data = data.to_vec();
        let level = self.level.0;
        let handler = self.result_handler;
        
        async move {
            let bz_level = bzip2::Compression::new(level as u32);
            let compressed = bzip2_compress_async(data, bz_level).await?;
            
            let result = Ok(CompressionResult::with_original_size(
                compressed.0,
                CompressionAlgorithm::Bzip2 { level: Some(6) }, // Default bzip2 level
                compressed.1,
            ));
            
            if let Some(handler) = handler {
                handler(result)
            } else {
                result
            }
        }
    }
    
    /// Decompress data
    pub fn decompress(self, data: &[u8]) -> impl Future<Output = Result<Vec<u8>>> {
        let data = data.to_vec();
        let handler = self.result_handler;
        
        async move {
            let decompressed = bzip2_decompress_async(data).await;
            
            let result = decompressed.map(|data| CompressionResult::new(
                data,
                CompressionAlgorithm::Bzip2 { level: None },
            ));
            
            if let Some(handler) = handler {
                handler(result).map(|r| r.to_vec())
            } else {
                result.map(|r| r.to_vec())
            }
        }
    }
}

// True async compression using channels
async fn bzip2_compress_async(data: Vec<u8>, level: bzip2::Compression) -> Result<(Vec<u8>, usize)> {
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
    
    rx.await.map_err(|_| crate::CompressionError::internal("Compression task failed"))?
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
    
    rx.await.map_err(|_| crate::CompressionError::internal("Decompression task failed"))?
}