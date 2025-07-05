//! ZIP archive builder following the new pattern

use crate::{CompressionResult, CompressionAlgorithm, Result};
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use std::collections::HashMap;

/// Type-state marker for no files added
pub struct NoFiles;

/// Type-state marker for files added
pub struct HasFiles {
    files: HashMap<String, Vec<u8>>,
}

/// Builder for ZIP archive operations
pub struct ZipBuilder<F> {
    pub(super) files: F,
    pub(super) result_handler: Option<Box<dyn Fn(Result<CompressionResult>) -> Result<CompressionResult> + Send + Sync>>,
    pub(super) chunk_handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
}

impl ZipBuilder<NoFiles> {
    /// Create a new ZIP builder
    pub fn new() -> Self {
        Self {
            files: NoFiles,
            result_handler: None,
            chunk_handler: None,
        }
    }
}

// Methods for adding result and chunk handlers
impl<F> ZipBuilder<F> {
    /// Apply on_result! handler
    pub fn on_result<H>(mut self, handler: H) -> Self
    where
        H: Fn(Result<CompressionResult>) -> Result<CompressionResult> + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }
    
    /// Apply on_chunk! handler for streaming
    pub fn on_chunk<H>(mut self, handler: H) -> Self
    where
        H: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.chunk_handler = Some(Box::new(handler));
        self
    }
}

// Methods for adding files
impl ZipBuilder<NoFiles> {
    /// Add the first file to the ZIP archive
    pub fn add_file<N: Into<String>, T: Into<Vec<u8>>>(self, name: N, data: T) -> ZipBuilder<HasFiles> {
        let mut files = HashMap::new();
        files.insert(name.into(), data.into());
        
        ZipBuilder {
            files: HasFiles { files },
            result_handler: self.result_handler,
            chunk_handler: self.chunk_handler,
        }
    }
}

impl ZipBuilder<HasFiles> {
    /// Add another file to the ZIP archive
    pub fn add_file<N: Into<String>, T: Into<Vec<u8>>>(mut self, name: N, data: T) -> Self {
        self.files.files.insert(name.into(), data.into());
        self
    }
}

// Compression methods for ZIP archives with files
impl ZipBuilder<HasFiles> {
    /// Create the ZIP archive from all added files
    pub async fn compress(self) -> Result<CompressionResult> {
        let files_count = self.files.files.len();
        let total_size: usize = self.files.files.values().map(|data| data.len()).sum();
        
        let compressed = zip_compress(self.files.files).await?;
        let result = CompressionResult::with_original_size(
            compressed,
            CompressionAlgorithm::Zip { 
                level: Some(6), // Default compression level
                files_count,
            },
            total_size,
        );
        
        if let Some(handler) = self.result_handler {
            handler(Ok(result))
        } else {
            Ok(result)
        }
    }
    
    /// Extract files from a ZIP archive (takes compressed data as input)
    pub async fn decompress<T: Into<Vec<u8>>>(self, data: T) -> Result<CompressionResult> {
        let data = data.into();
        let original_size = data.len();
        
        let files = zip_decompress(data.clone()).await?;
        let result = CompressionResult::with_original_size(
            data,
            CompressionAlgorithm::Zip { 
                level: None,
                files_count: files.len(),
            },
            original_size,
        );
        
        if let Some(handler) = self.result_handler {
            handler(Ok(result))
        } else {
            Ok(result)
        }
    }
    
    /// Create ZIP archive from a stream of file data
    pub fn compress_stream<S: Stream<Item = (String, Vec<u8>)> + Send + 'static>(
        self, 
        stream: S
    ) -> ZipStream {
        ZipStream::new(stream, self.chunk_handler)
    }
}

/// Stream of ZIP archive chunks
pub struct ZipStream {
    receiver: mpsc::Receiver<Result<Vec<u8>>>,
    handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>>,
}

impl ZipStream {
    /// Create a new ZIP stream from file pairs
    pub fn new<S>(
        stream: S,
        handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
    ) -> Self
    where
        S: Stream<Item = (String, Vec<u8>)> + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(100);
        
        // Spawn task to process stream
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            let mut stream = Box::pin(stream);
            let mut files = HashMap::new();
            
            // Collect all files from the stream
            while let Some((name, data)) = stream.next().await {
                files.insert(name, data);
            }
            
            // Create ZIP archive
            match zip_compress(files).await {
                Ok(compressed) => {
                    let _ = sender.send(Ok(compressed)).await;
                }
                Err(e) => {
                    let _ = sender.send(Err(e)).await;
                }
            }
        });
        
        ZipStream {
            receiver,
            handler: handler.map(|h| Box::new(h) as Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>),
        }
    }
}

impl Stream for ZipStream {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(result)) => {
                if let Some(handler) = &self.handler {
                    std::task::Poll::Ready(handler(result))
                } else {
                    match result {
                        Ok(chunk) => std::task::Poll::Ready(Some(chunk)),
                        Err(_) => std::task::Poll::Ready(None),
                    }
                }
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// Implement standard async iteration
impl ZipStream {
    /// Get the next chunk from the stream
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        use tokio_stream::StreamExt;
        StreamExt::next(self).await
    }
}

// Internal ZIP functions
async fn zip_compress(files: HashMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        crate::zip::compress_files(files).map_err(|e| {
            crate::CompressionError::internal(format!("ZIP compression failed: {}", e))
        })
    })
    .await
    .map_err(|e| crate::CompressionError::internal(e.to_string()))?
}

async fn zip_decompress(data: Vec<u8>) -> Result<HashMap<String, Vec<u8>>> {
    tokio::task::spawn_blocking(move || {
        crate::zip::decompress_files(&data).map_err(|e| {
            crate::CompressionError::internal(format!("ZIP decompression failed: {}", e))
        })
    })
    .await
    .map_err(|e| crate::CompressionError::internal(e.to_string()))?
}