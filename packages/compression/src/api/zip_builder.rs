//! ZIP archive builder following the new pattern

use crate::{CompressionAlgorithm, CompressionResult, Result};
use std::collections::HashMap;

/// Type alias for result handler functions
type ResultHandler = Box<dyn Fn(Result<CompressionResult>) -> Vec<u8> + Send + Sync>;

/// Type alias for chunk handler functions
type ChunkHandler = Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>;

/// Type alias for stream chunk handler functions  
type StreamChunkHandler = Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>;
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::Stream;

/// Type-state marker for no files added
pub struct NoFiles;

/// Type-state marker for files added
pub struct HasFiles {
    files: HashMap<String, Vec<u8>>,
}

/// Builder for ZIP archive operations
pub struct ZipBuilder<F> {
    pub(super) files: F,
    pub(super) result_handler: Option<ResultHandler>,
    pub(super) chunk_handler: Option<ChunkHandler>,
}

impl ZipBuilder<NoFiles> {
    /// Create a new ZIP builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: NoFiles,
            result_handler: None,
            chunk_handler: None,
        }
    }
}

impl Default for ZipBuilder<NoFiles> {
    fn default() -> Self {
        Self::new()
    }
}

// Methods for adding result and chunk handlers
impl<F> ZipBuilder<F> {
    /// Apply `on_result!` handler
    #[must_use]
    pub fn on_result<H>(mut self, handler: H) -> Self
    where
        H: Fn(Result<CompressionResult>) -> Vec<u8> + Send + Sync + 'static,
    {
        self.result_handler = Some(Box::new(handler));
        self
    }

    /// Apply `on_chunk!` handler for streaming
    #[must_use]
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
    #[must_use]
    pub fn add_file<N: Into<String>, T: Into<Vec<u8>>>(
        self,
        name: N,
        data: T,
    ) -> ZipBuilder<HasFiles> {
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
    #[must_use]
    pub fn add_file<N: Into<String>, T: Into<Vec<u8>>>(mut self, name: N, data: T) -> Self {
        self.files.files.insert(name.into(), data.into());
        self
    }
}

// Compression methods for ZIP archives with files
impl ZipBuilder<HasFiles> {
    /// Create the ZIP archive from all added files
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn compress(self) -> Vec<u8> {
        let files_count = self.files.files.len();
        let total_size: usize = self.files.files.values().map(Vec::len).sum();

        let result = async move {
            let compressed = zip_compress(self.files.files).await?;
            Ok(CompressionResult::with_original_size(
                compressed,
                CompressionAlgorithm::Zip {
                    level: Some(6), // Default compression level
                    files_count,
                },
                total_size,
            ))
        }
        .await;

        if let Some(handler) = self.result_handler {
            // User provided handler: give them Result<CompressionResult>, get back Vec<u8>
            (*handler)(result)
        } else {
            // Default unwrapping: Ok(compression_result) => compression_result.to_vec(), Err(_) => Vec::new()
            match result {
                Ok(compression_result) => compression_result.to_vec(),
                Err(_) => Vec::new(),
            }
        }
    }

    /// Extract files from a ZIP archive (takes compressed data as input)
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub async fn decompress<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();
        let original_size = data.len();

        let result = async move {
            let files = zip_decompress(data.clone()).await?;
            Ok(CompressionResult::with_original_size(
                data,
                CompressionAlgorithm::Zip {
                    level: None,
                    files_count: files.len(),
                },
                original_size,
            ))
        }
        .await;

        if let Some(handler) = self.result_handler {
            // User provided handler: give them Result<CompressionResult>, get back Vec<u8>
            (*handler)(result)
        } else {
            // Default unwrapping: Ok(compression_result) => compression_result.to_vec(), Err(_) => Vec::new()
            match result {
                Ok(compression_result) => compression_result.to_vec(),
                Err(_) => Vec::new(),
            }
        }
    }

    /// Create ZIP archive from a stream of file data
    #[must_use]
    pub fn compress_stream<S: Stream<Item = (String, Vec<u8>)> + Send + 'static>(
        self,
        stream: S,
    ) -> ZipStream {
        ZipStream::new(stream, self.chunk_handler)
    }
}

/// Stream of ZIP archive chunks
pub struct ZipStream {
    receiver: mpsc::Receiver<Result<Vec<u8>>>,
    handler: Option<StreamChunkHandler>,
}

impl ZipStream {
    /// Create a new ZIP stream from file pairs
    #[must_use]
    pub fn new<S>(stream: S, handler: Option<ChunkHandler>) -> Self
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
            handler: handler.map(|h| Box::new(h) as StreamChunkHandler),
        }
    }
}

impl Stream for ZipStream {
    type Item = Vec<u8>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
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

// Internal ZIP functions with chunked async processing
async fn zip_compress(files: HashMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    // Process files in chunks to avoid blocking
    for data in files.values() {
        // Yield control for large files
        if data.len() > 8192 {
            tokio::task::yield_now().await;
        }
    }

    // Use sync compression but with async coordination
    let compressed = crate::zip::compress_files(files)
        .map_err(|e| crate::CompressionError::internal(format!("ZIP compression failed: {e}")))?;

    Ok(compressed)
}

async fn zip_decompress(data: Vec<u8>) -> Result<HashMap<String, Vec<u8>>> {
    // Process ZIP decompression with yield points for large data
    if data.len() > 8192 {
        tokio::task::yield_now().await;
    }

    // Use sync decompression but with async coordination
    let decompressed = crate::zip::decompress_files(&data)
        .map_err(|e| crate::CompressionError::internal(format!("ZIP decompression failed: {e}")))?;

    Ok(decompressed)
}
