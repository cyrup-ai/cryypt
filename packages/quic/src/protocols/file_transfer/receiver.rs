//! File receiving logic and client components
//!
//! Contains client builder, download logic, and file receiving functionality
//! for the file transfer protocol.

use super::{FileMetadata, FileTransferMessage, TransferResult};
use crate::{QuicConnectionHandle, QuicCryptoBuilder, connect_quic_client, error::Result};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::time::Duration;
use uuid::Uuid;

/// Client builder with fluent API
#[derive(Debug)]
pub struct FileTransferClientBuilder {
    server_addr: String,
    timeout_secs: u64,
    retry_attempts: u32,
    verify_server: bool,
    client_cert: Option<String>,
    client_key: Option<String>,
}

impl FileTransferClientBuilder {
    pub(crate) fn new(server_addr: String) -> Self {
        Self {
            server_addr,
            timeout_secs: 300,
            retry_attempts: 3,
            verify_server: true, // Production: always verify server certificates
            client_cert: None,
            client_key: None,
        }
    }

    /// Set connection timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_secs = seconds;
        self
    }

    /// Set retry attempts on connection failure
    pub fn with_retry_attempts(mut self, attempts: u32) -> Self {
        self.retry_attempts = attempts;
        self
    }

    /// Enable server certificate verification
    pub fn with_server_verification(mut self, verify: bool) -> Self {
        self.verify_server = verify;
        self
    }

    /// Set client certificate for authentication
    pub fn with_client_cert(mut self, cert_path: &str, key_path: &str) -> Self {
        self.client_cert = Some(cert_path.to_string());
        self.client_key = Some(key_path.to_string());
        self
    }

    /// Upload a file to the server
    pub fn upload(self, file_path: impl AsRef<Path>) -> super::sender::FileUploadBuilder {
        super::sender::FileUploadBuilder::new(self, file_path.as_ref().to_path_buf())
    }

    /// Download a file from the server
    pub fn download(self, remote_filename: &str) -> FileDownloadBuilder {
        FileDownloadBuilder::new(self, remote_filename.to_string())
    }

    /// List files available on the server
    pub async fn list_files(self) -> Result<Vec<FileMetadata>> {
        let connection = self.establish_connection().await?;

        // Send list request
        let list_request = FileTransferMessage::ListRequest;
        let request_data = serde_json::to_vec(&list_request)
            .map_err(|e| std::io::Error::other(format!("Serialization error: {e}")))?;

        connection.send_stream_data(&request_data, false)?;

        // Wait for response with timeout
        let mut event_rx = connection.subscribe_to_events();
        let file_list = tokio::time::timeout(Duration::from_secs(30), async {
            while let Ok(event) = event_rx.recv().await {
                if let crate::quic_conn::QuicConnectionEvent::InboundStreamData(_, data) = event
                    && let Ok(FileTransferMessage::ListResponse { files }) =
                        serde_json::from_slice(&data)
                {
                    return Ok(files);
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "No file list received",
            ))
        })
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "File list request timeout")
        })??;

        Ok(file_list)
    }

    /// Establish QUIC connection (internal helper)
    pub(crate) async fn establish_connection(self) -> Result<QuicConnectionHandle> {
        let mut crypto_builder = QuicCryptoBuilder::new()
            .with_verify_peer(self.verify_server)
            .with_max_idle_timeout(self.timeout_secs * 1000)
            .with_initial_max_data(10_000_000_000); // 10GB

        // Add certificate verification for production security
        if self.verify_server {
            // Parse server address to get hostname for certificate verification
            let server_hostname = if let Some(colon_pos) = self.server_addr.rfind(':') {
                &self.server_addr[..colon_pos]
            } else {
                &self.server_addr
            };

            crypto_builder = crypto_builder
                .with_server_name(server_hostname)
                .with_certificate_verification(true)
                .with_hostname_verification(true);

            // Load system certificate store for production
            let cert_result = rustls_native_certs::load_native_certs();
            for cert in cert_result.certs {
                crypto_builder = crypto_builder.add_root_certificate(cert);
            }
            if !cert_result.errors.is_empty() {
                tracing::warn!(
                    "Some certificate loading errors occurred: {:?}",
                    cert_result.errors
                );
            }
        }

        // Add client certificate authentication if provided
        if let (Some(cert_path), Some(key_path)) = (&self.client_cert, &self.client_key) {
            crypto_builder = crypto_builder
                .with_client_certificate_file(cert_path)
                .with_client_private_key_file(key_path);
        }

        let crypto = crypto_builder.build_client()?;

        let handle = connect_quic_client("0.0.0.0:0", &self.server_addr, crypto).await?;

        // Wait for handshake with timeout
        tokio::time::timeout(
            Duration::from_secs(self.timeout_secs),
            handle.wait_for_handshake(),
        )
        .await??;

        Ok(handle)
    }
}

/// File download builder
pub struct FileDownloadBuilder {
    client: FileTransferClientBuilder,
    remote_filename: String,
    output_path: Option<PathBuf>,
    verify_checksum: bool,
    resume: bool,
}

impl FileDownloadBuilder {
    fn new(client: FileTransferClientBuilder, remote_filename: String) -> Self {
        Self {
            client,
            remote_filename,
            output_path: None,
            verify_checksum: true,
            resume: false,
        }
    }

    /// Set output path for downloaded file
    pub fn to_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_path = Some(path.into());
        self
    }

    /// Enable checksum verification
    pub fn with_checksum_verification(mut self, verify: bool) -> Self {
        self.verify_checksum = verify;
        self
    }

    /// Enable resume capability
    pub fn with_resume(mut self, enabled: bool) -> Self {
        self.resume = enabled;
        self
    }

    /// Execute the download
    pub async fn execute(self) -> Result<TransferResult> {
        let output_path = self
            .output_path
            .unwrap_or_else(|| PathBuf::from(&self.remote_filename));

        let connection = self.client.establish_connection().await?;

        // Execute download protocol (hides all complexity)
        let result = execute_download_protocol(
            connection,
            &self.remote_filename,
            &output_path,
            self.verify_checksum,
            self.resume,
        )
        .await?;

        Ok(result)
    }
}

// Helper functions for download protocol

pub(crate) async fn execute_download_protocol(
    connection: QuicConnectionHandle,
    remote_filename: &str,
    output_path: &Path,
    verify_checksum: bool,
    resume: bool,
) -> Result<TransferResult> {
    let start_time = std::time::Instant::now();
    let file_id = Uuid::new_v4();

    // 1. Send download request
    let download_request = FileTransferMessage::DownloadRequest {
        file_id,
        filename: remote_filename.to_string(),
        resume_offset: if resume { Some(0) } else { None },
    };

    let request_data = serde_json::to_vec(&download_request)
        .map_err(|e| std::io::Error::other(format!("Serialization error: {e}")))?;

    connection.send_stream_data(&request_data, false)?;

    // 2. Create output file
    let mut file = File::create(output_path)
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to create output file: {e}")))?;

    let mut bytes_transferred = 0u64;
    let mut received_checksum = String::new();
    let mut transfer_success = false;

    // 3. Receive file data chunks from QUIC connection
    let mut event_rx = connection.subscribe_to_events();

    // Timeout for the entire download operation
    let download_timeout = tokio::time::timeout(Duration::from_secs(300), async {
        while let Ok(event) = event_rx.recv().await {
            if let crate::quic_conn::QuicConnectionEvent::InboundStreamData(_, data) = event {
                if data.is_empty() {
                    // End of stream
                    break;
                }

                // Try to parse as protocol message first
                if let Ok(message) = serde_json::from_slice::<FileTransferMessage>(&data) {
                    match message {
                        FileTransferMessage::DataChunk {
                            file_id: chunk_file_id,
                            data: chunk_data,
                            is_final,
                            ..
                        } => {
                            // Verify file_id matches our request
                            if chunk_file_id != file_id {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "File ID mismatch in data chunk",
                                ));
                            }

                            file.write_all(&chunk_data).await.map_err(|e| {
                                std::io::Error::other(format!("File write error: {e}"))
                            })?;
                            bytes_transferred += chunk_data.len() as u64;

                            if is_final {
                                break;
                            }
                        }
                        FileTransferMessage::TransferComplete {
                            file_id: complete_file_id,
                            checksum,
                            success,
                        } => {
                            // Verify file_id matches our request
                            if complete_file_id != file_id {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "File ID mismatch in transfer complete",
                                ));
                            }

                            received_checksum = checksum;
                            transfer_success = success;
                            break;
                        }
                        _ => {
                            // Ignore other message types
                            continue;
                        }
                    }
                } else {
                    // Treat as raw chunk data if not a protocol message
                    file.write_all(&data)
                        .await
                        .map_err(|e| std::io::Error::other(format!("File write error: {e}")))?;
                    bytes_transferred += data.len() as u64;
                }
            }
        }

        Ok::<(), std::io::Error>(())
    });

    // Handle timeout
    download_timeout.await.map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "Download operation timed out")
    })??;

    file.flush()
        .await
        .map_err(|e| std::io::Error::other(format!("File flush error: {e}")))?;

    // 4. Verify checksum if requested and available
    let checksum_verified = if verify_checksum && !received_checksum.is_empty() {
        use cryypt_hashing::Hash;
        use tokio::io::AsyncReadExt;

        let mut file_for_hash = File::open(output_path).await.map_err(|e| {
            std::io::Error::other(format!("Failed to reopen file for checksum: {e}"))
        })?;

        let mut buffer = Vec::new();
        file_for_hash.read_to_end(&mut buffer).await.map_err(|e| {
            std::io::Error::other(format!("Failed to read file for checksum: {e}"))
        })?;

        let computed_hash = Hash::sha3_256()
            .compute(buffer)
            .await
            .map_err(|e| std::io::Error::other(format!("Hash computation error: {e}")))?;

        let computed_checksum = hex::encode(computed_hash);
        computed_checksum == received_checksum
    } else {
        true // Skip verification if not requested or no checksum provided
    };

    let final_success = transfer_success && checksum_verified && bytes_transferred > 0;

    Ok(TransferResult {
        file_id,
        filename: remote_filename.to_string(),
        bytes_transferred,
        duration: start_time.elapsed(),
        checksum: received_checksum,
        success: final_success,
    })
}
