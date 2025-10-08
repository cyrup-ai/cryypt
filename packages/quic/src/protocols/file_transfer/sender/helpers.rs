//! Helper functions for upload protocol and utilities

use super::super::{FileTransferMessage, FileTransferProgress, TransferResult};
use crate::{QuicConnectionHandle, error::Result};
use cryypt_hashing::Hash;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::time::Duration;
use uuid::Uuid;

/// Calculate file checksum using SHA3-256
pub(crate) async fn calculate_file_checksum(path: &Path) -> Result<String> {
    let mut file = File::open(path).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;

    let hash_result = Hash::sha3_256()
        .compute(buffer)
        .await
        .map_err(std::io::Error::other)?;

    Ok(hex::encode(hash_result))
}

/// Configuration for upload protocol execution
pub(crate) struct UploadConfig<'a> {
    pub file_path: &'a Path,
    pub filename: &'a str,
    pub file_size: u64,
    pub checksum: &'a str,
    pub compress: bool,
    pub resume: bool,
    pub progress_callback: Option<Box<dyn Fn(FileTransferProgress) + Send + Sync>>,
}

/// Execute the complete upload protocol
///
/// # Errors
///
/// Returns an error if:
/// - Network communication fails
/// - File I/O operations fail  
/// - Serialization/deserialization fails
/// - Protocol handshake fails
/// - Progress reporting fails
pub(crate) async fn execute_upload_protocol(
    connection: QuicConnectionHandle,
    config: UploadConfig<'_>,
) -> Result<TransferResult> {
    let start_time = std::time::Instant::now();
    let file_id = Uuid::new_v4();

    // 1. Send upload request and wait for server response
    send_upload_request(&connection, file_id, &config)?;
    wait_for_server_response(&connection).await?;

    // 2. Stream file data and get completion confirmation
    let bytes_transferred = stream_file_data(&connection, &config, file_id, start_time).await?;
    let completion_confirmed = wait_for_upload_completion(&connection, file_id).await?;

    Ok(TransferResult {
        file_id,
        filename: config.filename.to_string(),
        bytes_transferred,
        duration: start_time.elapsed(),
        checksum: config.checksum.to_string(),
        success: completion_confirmed,
    })
}

/// Send upload request message to the connection
fn send_upload_request(
    connection: &QuicConnectionHandle,
    file_id: Uuid,
    config: &UploadConfig<'_>,
) -> Result<()> {
    let upload_request = FileTransferMessage::UploadRequest {
        file_id,
        filename: config.filename.to_string(),
        size: config.file_size,
        checksum: config.checksum.to_string(),
        compressed: config.compress,
        resume_offset: if config.resume { Some(0) } else { None },
    };

    let request_data = serde_json::to_vec(&upload_request)
        .map_err(|e| std::io::Error::other(format!("Serialization error: {e}")))?;

    connection.send_stream_data(&request_data, false)?;
    Ok(())
}

/// Wait for server response to upload request
async fn wait_for_server_response(connection: &QuicConnectionHandle) -> Result<()> {
    let mut event_rx = connection.subscribe_to_events();
    let _server_response = tokio::time::timeout(Duration::from_secs(30), async {
        while let Ok(event) = event_rx.recv().await {
            if let crate::quic_conn::QuicConnectionEvent::InboundStreamData(_, data) = event {
                return serde_json::from_slice::<FileTransferMessage>(&data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e));
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "No response received",
        ))
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Server response timeout"))??;

    Ok(())
}

/// Stream file data to the connection with progress updates
async fn stream_file_data(
    connection: &QuicConnectionHandle,
    config: &UploadConfig<'_>,
    file_id: Uuid,
    start_time: std::time::Instant,
) -> Result<u64> {
    let mut file = File::open(config.file_path).await?;
    let mut buffer = vec![0u8; 64 * 1024]; // 64KB chunks
    let mut bytes_transferred = 0u64;

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }

        let chunk = &buffer[..bytes_read];

        // Apply compression if enabled
        let final_chunk = if config.compress {
            use cryypt_compression::Compress;
            let compression_result = Compress::zstd()
                .with_level(3)
                .compress(chunk.to_vec())
                .await
                .map_err(std::io::Error::other)?;
            compression_result.to_vec()
        } else {
            chunk.to_vec()
        };

        connection.send_stream_data(&final_chunk, false)?;
        bytes_transferred += bytes_read as u64;

        // Send progress updates
        if let Some(ref callback) = config.progress_callback {
            let progress = FileTransferProgress {
                file_id,
                filename: config.filename.to_string(),
                bytes_transferred,
                total_bytes: config.file_size,
                #[allow(clippy::cast_precision_loss)]
                throughput_mbps: bytes_transferred as f64
                    / start_time.elapsed().as_secs_f64()
                    / 1_048_576.0,
                eta_seconds: if bytes_transferred > 0 {
                    let remaining = config.file_size - bytes_transferred;
                    #[allow(clippy::cast_precision_loss)]
                    let rate = bytes_transferred as f64 / start_time.elapsed().as_secs_f64();
                    #[allow(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        clippy::cast_precision_loss
                    )]
                    Some((remaining as f64 / rate) as u64)
                } else {
                    None
                },
            };
            callback(progress);
        }
    }

    // Send completion signal
    connection.send_stream_data(&[], true)?;
    Ok(bytes_transferred)
}

/// Wait for upload completion confirmation from server
async fn wait_for_upload_completion(
    connection: &QuicConnectionHandle,
    file_id: Uuid,
) -> Result<bool> {
    let mut event_rx = connection.subscribe_to_events();
    let completion_confirmed = tokio::time::timeout(Duration::from_secs(30), async {
        while let Ok(event) = event_rx.recv().await {
            if let crate::quic_conn::QuicConnectionEvent::InboundStreamData(_, data) = event {
                if data.is_empty() {
                    return true; // End of stream indicates completion
                }

                // Try to parse as protocol message
                if let Ok(FileTransferMessage::TransferComplete {
                    file_id: complete_file_id,
                    success,
                    ..
                }) = serde_json::from_slice::<FileTransferMessage>(&data)
                {
                    // Verify it's for our upload
                    return complete_file_id == file_id && success;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false);

    Ok(completion_confirmed)
}

/// Generate temporary self-signed certificates using TLS builder API  
pub(crate) async fn generate_temp_certificates() -> Result<(String, String)> {
    use crate::tls::QuicheCertificateProvider;

    tracing::info!("Generating temporary certificates for file transfer using TLS builder API");

    // Use TLS builder API to create certificates
    let temp_cert_dir = std::env::temp_dir().join("cryypt-file-transfer");
    let mut provider =
        QuicheCertificateProvider::create_self_signed("file-transfer-temp", temp_cert_dir)
            .await
            .map_err(|e| {
                std::io::Error::other(format!(
                    "Failed to create certificates via TLS builder: {e}"
                ))
            })?;

    // Create temporary PEM files that can be used by QUIC
    let (cert_path, key_path) = provider.create_temp_pem_files().await.map_err(|e| {
        std::io::Error::other(format!("Failed to create temporary certificate files: {e}"))
    })?;

    Ok((
        cert_path.to_string_lossy().to_string(),
        key_path.to_string_lossy().to_string(),
    ))
}
