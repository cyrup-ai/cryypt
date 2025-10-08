//! Production-quality file transfer builder with immutable pattern and streaming support

use super::types::{FileOperation, FileProgress, FileTransferResult};
use crate::error::Result;
use futures::StreamExt as FuturesStreamExt;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio_stream::{Stream, StreamExt};

/// Type alias for file transfer result handlers
type ResultHandler =
    Box<dyn Fn(Result<FileTransferResult>) -> Result<FileTransferResult> + Send + Sync>;

/// Type alias for file transfer progress chunk handlers  
type ChunkHandler = Box<dyn Fn(Result<FileProgress>) -> Result<FileProgress> + Send + Sync>;

/// Immutable builder for file transfer operations following README patterns
pub struct FileTransferConfig {
    operation: FileOperation,
    path: PathBuf,
    addr: SocketAddr,
    compression: bool,
    resume: bool,
    result_handler: Option<ResultHandler>,
    chunk_handler: Option<ChunkHandler>,
}

/// Builder for upload operations
pub struct UploadConfig {
    config: FileTransferConfig,
}

/// Builder for download operations  
pub struct DownloadConfig {
    config: FileTransferConfig,
}

impl FileTransferConfig {
    /// Create a new upload configuration
    #[must_use]
    pub fn upload(path: String, addr: SocketAddr) -> UploadConfig {
        UploadConfig {
            config: FileTransferConfig {
                operation: FileOperation::Upload,
                path: PathBuf::from(path),
                addr,
                compression: false,
                resume: false,
                result_handler: None,
                chunk_handler: None,
            },
        }
    }

    /// Create a new download configuration
    #[must_use]
    pub fn download(path: String, addr: SocketAddr) -> DownloadConfig {
        DownloadConfig {
            config: FileTransferConfig {
                operation: FileOperation::Download,
                path: PathBuf::from(path),
                addr,
                compression: false,
                resume: false,
                result_handler: None,
                chunk_handler: None,
            },
        }
    }
}

impl UploadConfig {
    /// Enable compression for upload
    #[must_use]
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.config.compression = enabled;
        self
    }

    /// Enable resume capability for upload
    #[must_use]
    pub fn with_resume(mut self, enabled: bool) -> Self {
        self.config.resume = enabled;
        self
    }

    /// Set result handler following README `on_result` pattern
    #[must_use]
    pub fn on_result<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<FileTransferResult>) -> Result<FileTransferResult> + Send + Sync + 'static,
    {
        self.config.result_handler = Some(Box::new(handler));
        self
    }

    /// Set chunk handler for streaming following `README` `on_chunk` pattern
    #[must_use]
    pub fn on_chunk<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<FileProgress>) -> Result<FileProgress> + Send + Sync + 'static,
    {
        self.config.chunk_handler = Some(Box::new(handler));
        self
    }

    /// Execute upload and return Future
    pub fn execute(self) -> impl Future<Output = Result<FileTransferResult>> + Send {
        execute_file_transfer(self.config)
    }

    /// Execute upload with streaming progress
    pub fn execute_stream(
        self,
    ) -> (
        impl Future<Output = Result<FileTransferResult>> + Send,
        impl Stream<Item = FileProgress> + Send,
    ) {
        execute_file_transfer_stream(self.config)
    }
}

impl DownloadConfig {
    /// Enable compression for download
    #[must_use]
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.config.compression = enabled;
        self
    }

    /// Enable resume capability for download
    #[must_use]
    pub fn with_resume(mut self, enabled: bool) -> Self {
        self.config.resume = enabled;
        self
    }

    /// Set result handler following `README` `on_result` pattern
    #[must_use]
    pub fn on_result<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<FileTransferResult>) -> Result<FileTransferResult> + Send + Sync + 'static,
    {
        self.config.result_handler = Some(Box::new(handler));
        self
    }

    /// Set chunk handler for streaming following `README` `on_chunk` pattern
    #[must_use]
    pub fn on_chunk<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<FileProgress>) -> Result<FileProgress> + Send + Sync + 'static,
    {
        self.config.chunk_handler = Some(Box::new(handler));
        self
    }

    /// Execute download and return Future
    pub fn execute(self) -> impl Future<Output = Result<FileTransferResult>> + Send {
        execute_file_transfer(self.config)
    }

    /// Execute download with streaming progress
    pub fn execute_stream(
        self,
    ) -> (
        impl Future<Output = Result<FileTransferResult>> + Send,
        impl Stream<Item = FileProgress> + Send,
    ) {
        execute_file_transfer_stream(self.config)
    }
}

/// Execute file transfer operation (Future variant) using production implementation
async fn execute_file_transfer(config: FileTransferConfig) -> Result<FileTransferResult> {
    let result = match config.operation {
        FileOperation::Upload => {
            super::upload::execute_upload_streaming(
                config.path,
                config.addr,
                config.compression,
                config.resume,
                None, // No progress callback for Future variant
            )
            .await
        }
        FileOperation::Download => {
            super::download::execute_download_streaming(
                config.path,
                config.addr,
                config.compression,
                config.resume,
                None, // No progress callback for Future variant
            )
            .await
        }
    };

    // Apply result handler if provided
    if let Some(handler) = config.result_handler {
        handler(result)
    } else {
        result
    }
}

/// Execute file transfer operation with streaming (Stream variant)
fn execute_file_transfer_stream(
    config: FileTransferConfig,
) -> (
    impl Future<Output = Result<FileTransferResult>> + Send,
    impl Stream<Item = FileProgress> + Send,
) {
    let (progress_tx, progress_rx) = mpsc::unbounded_channel();

    let chunk_handler = config.chunk_handler;
    let result_handler = config.result_handler;

    let future = async move {
        let progress_callback = {
            let tx = progress_tx.clone();
            move |progress: FileProgress| {
                let _ = tx.send(progress);
            }
        };

        match config.operation {
            FileOperation::Upload => {
                let result = super::upload::execute_upload_streaming(
                    config.path,
                    config.addr,
                    config.compression,
                    config.resume,
                    Some(Box::new(progress_callback)),
                )
                .await;

                // Apply result handler if provided
                if let Some(handler) = result_handler {
                    handler(result)
                } else {
                    result
                }
            }
            FileOperation::Download => {
                let result = super::download::execute_download_streaming(
                    config.path,
                    config.addr,
                    config.compression,
                    config.resume,
                    Some(Box::new(progress_callback)),
                )
                .await;

                // Apply result handler if provided
                if let Some(handler) = result_handler {
                    handler(result)
                } else {
                    result
                }
            }
        }
    };

    // Create stream that applies chunk handler if provided
    let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(progress_rx);
    let processed_stream = if let Some(handler) = chunk_handler {
        FuturesStreamExt::filter_map(stream, move |progress| {
            let result = handler(Ok(progress));
            async move { result.ok() }
        })
        .boxed()
    } else {
        FuturesStreamExt::boxed(stream)
    };

    (future, processed_stream)
}
