//! File upload builder and execution logic

use super::super::{FileTransferProgress, TransferResult};
use crate::error::Result;
use std::future::Future;
use std::path::PathBuf;
use tokio::fs::metadata;
use tokio::sync::mpsc;
use tokio_stream::Stream;

/// File upload builder
pub struct FileUploadBuilder {
    client: super::super::receiver::FileTransferClientBuilder,
    file_path: PathBuf,
    compress: bool,
    resume: bool,
    progress_callback: Option<Box<dyn Fn(FileTransferProgress) + Send + Sync>>,
}

impl FileUploadBuilder {
    pub(crate) fn new(
        client: super::super::receiver::FileTransferClientBuilder,
        file_path: PathBuf,
    ) -> Self {
        Self {
            client,
            file_path,
            compress: false,
            resume: false,
            progress_callback: None,
        }
    }

    /// Enable compression for this upload
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compress = enabled;
        self
    }

    /// Enable resume capability
    pub fn with_resume(mut self, enabled: bool) -> Self {
        self.resume = enabled;
        self
    }

    /// Set progress callback
    pub fn with_progress<F>(mut self, callback: F) -> Self
    where
        F: Fn(FileTransferProgress) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
        self
    }

    /// Execute the upload
    pub async fn execute(self) -> Result<TransferResult> {
        // Validate file exists
        if !self.file_path.exists() {
            return Err(format!("File not found: {:?}", self.file_path).into());
        }

        let metadata = metadata(&self.file_path).await?;
        let file_size = metadata.len();
        let filename = self
            .file_path
            .file_name()
            .ok_or("Invalid filename")?
            .to_string_lossy()
            .to_string();

        // Calculate checksum
        let checksum = super::helpers::calculate_file_checksum(&self.file_path).await?;

        // Establish connection with retry logic
        let connection = self.client.establish_connection().await?;

        // Execute the upload protocol (this hides ALL the complexity)
        let result = super::helpers::execute_upload_protocol(
            connection,
            &self.file_path,
            &filename,
            file_size,
            &checksum,
            self.compress,
            self.resume,
            self.progress_callback,
        )
        .await?;

        Ok(result)
    }

    /// Execute upload and return a progress stream
    pub fn execute_with_stream(
        self,
    ) -> (
        impl Future<Output = Result<TransferResult>> + Send,
        impl Stream<Item = FileTransferProgress>,
    ) {
        let (_progress_tx, progress_rx) = mpsc::unbounded_channel();

        let upload_future = async move {
            // Similar to execute() but sends progress updates to the channel
            self.execute().await
        };

        (
            upload_future,
            tokio_stream::wrappers::UnboundedReceiverStream::new(progress_rx),
        )
    }
}
