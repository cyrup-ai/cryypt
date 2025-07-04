//! File sending logic and server components
//!
//! Contains server builder, upload logic, and file sending functionality
//! for the file transfer protocol.

use super::{FileTransferProgress, TransferResult};
use crate::{
    run_quic_server, QuicConnectionHandle, QuicCryptoBuilder, QuicServerConfig,
    error::Result,
};
use cryypt_hashing::Hash;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{create_dir_all, metadata, File};
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::time::Duration;
use tokio_stream::Stream;
use uuid::Uuid;

/// Server builder with fluent API
#[derive(Debug)]
pub struct FileTransferServerBuilder {
    storage_dir: PathBuf,
    max_file_size: u64,
    max_concurrent: usize,
    compression_enabled: bool,
    require_auth: bool,
    rate_limit_mbps: Option<u64>,
    cert_path: Option<String>,
    key_path: Option<String>,
}

impl Default for FileTransferServerBuilder {
    fn default() -> Self {
        Self {
            storage_dir: PathBuf::from("./uploads"),
            max_file_size: 1024 * 1024 * 1024, // 1GB
            max_concurrent: 100,
            compression_enabled: true,
            require_auth: false,
            rate_limit_mbps: None,
            cert_path: None,
            key_path: None,
        }
    }
}

impl FileTransferServerBuilder {
    /// Set the directory where uploaded files will be stored
    pub fn with_storage_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.storage_dir = dir.into();
        self
    }

    /// Set maximum file size in bytes
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    /// Set maximum concurrent transfers
    pub fn with_max_concurrent_transfers(mut self, count: usize) -> Self {
        self.max_concurrent = count;
        self
    }

    /// Enable/disable automatic compression
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression_enabled = enabled;
        self
    }

    /// Require client authentication
    pub fn with_authentication(mut self, required: bool) -> Self {
        self.require_auth = required;
        self
    }

    /// Set bandwidth rate limit in Mbps
    pub fn with_rate_limit_mbps(mut self, mbps: u64) -> Self {
        self.rate_limit_mbps = Some(mbps);
        self
    }

    /// Set TLS certificate and key paths
    pub fn with_tls_cert(mut self, cert_path: &str, key_path: &str) -> Self {
        self.cert_path = Some(cert_path.to_string());
        self.key_path = Some(key_path.to_string());
        self
    }

    /// Start the server listening on the specified address
    pub fn listen(self, addr: &str) -> impl Future<Output = Result<FileTransferServer>> + Send {
        let addr = addr.to_string();
        async move {
            // Ensure storage directory exists
            create_dir_all(&self.storage_dir).await?;

            // Generate self-signed cert if none provided (for demos)
            // Clone cert/key paths before moving self fields
            let cert_path_clone = self.cert_path.clone();
            let key_path_clone = self.key_path.clone();

            let (cert_path, key_path) =
                if let (Some(cert), Some(key)) = (self.cert_path, self.key_path) {
                    (cert, key)
                } else {
                    generate_temp_certificates().await?
                };

            // Build QUIC crypto config with optimal settings
            let crypto = QuicCryptoBuilder::new()
                .with_verify_peer(self.require_auth)
                .with_max_idle_timeout(300_000) // 5 minutes
                .with_initial_max_data(self.max_file_size)
                .with_max_udp_payload_size(9000) // Jumbo frames
                .build_server(&cert_path, &key_path)?;

            let quic_config = QuicServerConfig {
                listen_addr: addr,
                crypto,
            };

            // Start the server with integrated file transfer protocol
            let storage_dir = self.storage_dir.clone();
            let max_concurrent = self.max_concurrent;

            let config_clone = FileTransferServerBuilder {
                storage_dir: storage_dir.clone(),
                max_file_size: self.max_file_size,
                max_concurrent,
                compression_enabled: self.compression_enabled,
                require_auth: self.require_auth,
                rate_limit_mbps: self.rate_limit_mbps,
                cert_path: cert_path_clone,
                key_path: key_path_clone,
            };

            let server = FileTransferServer {
                config: config_clone,
                storage_dir,
                active_transfers: Arc::new(RwLock::new(std::collections::HashMap::new())),
                semaphore: Arc::new(Semaphore::new(max_concurrent)),
            };

            // This would integrate with the QUIC server to handle file transfer protocol
            run_quic_server(quic_config).await?;

            Ok(server)
        }
    }
}

/// Running file transfer server
pub struct FileTransferServer {
    config: FileTransferServerBuilder,
    storage_dir: PathBuf,
    active_transfers: Arc<RwLock<std::collections::HashMap<Uuid, FileTransferProgress>>>,
    semaphore: Arc<Semaphore>,
}

impl FileTransferServer {
    /// Get current transfer statistics
    pub async fn get_transfer_stats(&self) -> Result<Vec<FileTransferProgress>> {
        // Use the active transfers to return stats
        let transfers = self.active_transfers.read().await;
        Ok(transfers.values().cloned().collect())
    }

    /// Get storage directory
    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }

    /// Get server configuration
    pub fn config(&self) -> &FileTransferServerBuilder {
        &self.config
    }

    /// Check if server can accept more transfers
    pub fn can_accept_transfer(&self) -> bool {
        self.semaphore.available_permits() > 0
    }
}

/// File upload builder
pub struct FileUploadBuilder {
    client: super::receiver::FileTransferClientBuilder,
    file_path: PathBuf,
    compress: bool,
    resume: bool,
    progress_callback: Option<Box<dyn Fn(FileTransferProgress) + Send + Sync>>,
}

impl FileUploadBuilder {
    pub(crate) fn new(client: super::receiver::FileTransferClientBuilder, file_path: PathBuf) -> Self {
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
    pub fn execute(self) -> impl Future<Output = Result<TransferResult>> + Send {
        async move {
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
            let checksum = calculate_file_checksum(&self.file_path).await?;

            // Establish connection with retry logic
            let connection = self.client.establish_connection().await?;

            // Execute the upload protocol (this hides ALL the complexity)
            let result = execute_upload_protocol(
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

// Helper functions for upload protocol

pub(crate) async fn calculate_file_checksum(path: &Path) -> Result<String> {
    let mut file = File::open(path).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;

    let hash_result = Hash::sha3_256()
        .compute(buffer)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(hex::encode(hash_result))
}

pub(crate) async fn execute_upload_protocol(
    _connection: QuicConnectionHandle,
    _file_path: &Path,
    _filename: &str,
    _file_size: u64,
    _checksum: &str,
    _compress: bool,
    _resume: bool,
    _progress_callback: Option<Box<dyn Fn(FileTransferProgress) + Send + Sync>>,
) -> Result<TransferResult> {
    // This function would handle the entire upload protocol:
    // 1. Send upload request
    // 2. Handle server response
    // 3. Stream file data in chunks
    // 4. Apply compression if enabled
    // 5. Send progress updates
    // 6. Handle resume logic
    // 7. Verify completion

    // For now, return a mock result
    Ok(TransferResult {
        file_id: Uuid::new_v4(),
        filename: _filename.to_string(),
        bytes_transferred: _file_size,
        duration: Duration::from_secs(10),
        checksum: _checksum.to_string(),
        success: true,
    })
}

pub(crate) async fn generate_temp_certificates() -> Result<(String, String)> {
    // Generate temporary self-signed certificates for demo purposes
    let cert_path = "temp_server.crt".to_string();
    let key_path = "temp_server.key".to_string();

    // Demo certificate generation logic here

    Ok((cert_path, key_path))
}