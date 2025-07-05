//! Gzip compression operations
//!
//! Contains the compression and decompression implementations for Gzip.

use crate::{CompressionResult, CompressionAlgorithm, Result};
use super::{GzipBuilder, NoLevel, HasLevel};
use std::future::Future;
use tokio::sync::oneshot;

impl GzipBuilder<NoLevel> {
    /// Compress data using default compression level
    pub fn compress(self, data: &[u8]) -> impl Future<Output = Result<CompressionResult>> {
        let data = data.to_vec();
        let handler = self.result_handler;
        
        async move {
            let compressed = gzip_compress_async(data, flate2::Compression::default()).await?;
            
            let result = Ok(CompressionResult::with_original_size(
                compressed.0,
                CompressionAlgorithm::Gzip { level: Some(6) }, // Default gzip level
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
            let decompressed = gzip_decompress_async(data).await;
            
            let result = decompressed.map(|data| CompressionResult::new(
                data,
                CompressionAlgorithm::Gzip { level: None },
            ));
            
            if let Some(handler) = handler {
                handler(result).map(|r| r.to_vec())
            } else {
                result.map(|r| r.to_vec())
            }
        }
    }
}

impl GzipBuilder<HasLevel> {
    /// Compress data using specified compression level
    pub fn compress(self, data: &[u8]) -> impl Future<Output = Result<CompressionResult>> {
        let data = data.to_vec();
        let level = self.level.0;
        let handler = self.result_handler;
        
        async move {
            let flate_level = flate2::Compression::new(level as u32);
            let compressed = gzip_compress_async(data, flate_level).await?;
            
            let result = Ok(CompressionResult::with_original_size(
                compressed.0,
                CompressionAlgorithm::Gzip { level: Some(6) }, // Default gzip level
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
            let decompressed = gzip_decompress_async(data).await;
            
            let result = decompressed.map(|data| CompressionResult::new(
                data,
                CompressionAlgorithm::Gzip { level: None },
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
async fn gzip_compress_async(data: Vec<u8>, level: flate2::Compression) -> Result<(Vec<u8>, usize)> {
    let (tx, rx) = oneshot::channel();
    let original_size = data.len();
    
    std::thread::spawn(move || {
        let result = (|| {
            use flate2::write::GzEncoder;
            use std::io::Write;
            
            let mut encoder = GzEncoder::new(Vec::new(), level);
            encoder.write_all(&data)?;
            Ok((encoder.finish()?, original_size))
        })()
        .map_err(|e: std::io::Error| crate::CompressionError::internal(e.to_string()));
        
        let _ = tx.send(result);
    });
    
    rx.await.map_err(|_| crate::CompressionError::internal("Compression task failed"))?
}

async fn gzip_decompress_async(data: Vec<u8>) -> Result<Vec<u8>> {
    let (tx, rx) = oneshot::channel();
    
    std::thread::spawn(move || {
        let result = (|| {
            use flate2::read::GzDecoder;
            use std::io::Read;
            
            let mut decoder = GzDecoder::new(&data[..]);
            let mut output = Vec::new();
            decoder.read_to_end(&mut output)?;
            Ok(output)
        })()
        .map_err(|e: std::io::Error| crate::CompressionError::internal(e.to_string()));
        
        let _ = tx.send(result);
    });
    
    rx.await.map_err(|_| crate::CompressionError::internal("Decompression task failed"))?
}