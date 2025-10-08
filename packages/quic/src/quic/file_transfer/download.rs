//! Production-quality streaming file download over QUIC using existing protocol infrastructure

use super::types::{FileProgress, FileTransferResult};
use crate::error::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};

// Additional imports for certificate verification
use rustls_native_certs;
use tokio::time::Duration;
use tracing;

/// Context for download completion processing
struct DownloadCompletionContext<'a> {
    writer: BufWriter<File>,
    path: &'a PathBuf,
    bytes_transferred: u64,
    total_file_size: Option<u64>,
    received_checksum: String,
    transfer_success: bool,
    progress_callback: Option<&'a (dyn Fn(FileProgress) + Send + Sync)>,
    start: std::time::Instant,
}

/// Handle download completion, checksum verification, and result creation
async fn handle_download_completion(
    mut ctx: DownloadCompletionContext<'_>,
) -> Result<FileTransferResult> {
    use cryypt_hashing::Hash;

    // Flush and close file
    ctx.writer.flush().await?;
    drop(ctx.writer);

    // Final progress update
    if let Some(callback) = ctx.progress_callback {
        let elapsed = ctx.start.elapsed().as_secs_f64();
        let mbps = if elapsed > 0.0 {
            #[allow(clippy::cast_precision_loss)]
            let mbps_calc = (ctx.bytes_transferred as f64 * 8.0) / (elapsed * 1_000_000.0);
            mbps_calc
        } else {
            0.0
        };

        callback(FileProgress {
            percent: 100.0,
            bytes_transferred: ctx.bytes_transferred,
            total_bytes: ctx.total_file_size.unwrap_or(ctx.bytes_transferred),
            mbps,
        });
    }

    // Verify checksum if available and requested
    let checksum_verified = if ctx.received_checksum.is_empty() {
        true // Skip verification if no checksum provided
    } else {
        // Reopen file for checksum calculation
        let mut file_for_hash = File::open(ctx.path).await.map_err(|e| {
            crate::error::CryptoTransportError::Internal(format!(
                "Failed to reopen file for checksum: {e}"
            ))
        })?;

        let mut buffer = Vec::new();
        file_for_hash.read_to_end(&mut buffer).await.map_err(|e| {
            crate::error::CryptoTransportError::Internal(format!(
                "Failed to read file for checksum: {e}"
            ))
        })?;

        // Calculate SHA3-256 hash like production code
        let computed_hash = Hash::sha3_256().compute(buffer).await.map_err(|e| {
            crate::error::CryptoTransportError::Internal(format!("Hash computation error: {e}"))
        })?;

        let computed_checksum = hex::encode(computed_hash);
        computed_checksum == ctx.received_checksum
    };

    let success = ctx.transfer_success && checksum_verified && ctx.bytes_transferred > 0;

    Ok(FileTransferResult {
        bytes_transferred: ctx.bytes_transferred,
        duration: ctx.start.elapsed(),
        success,
    })
}

/// Context for download stream processing
struct DownloadStreamContext<'a> {
    writer: &'a mut BufWriter<File>,
    event_rx: &'a mut tokio::sync::broadcast::Receiver<crate::quic_conn::QuicConnectionEvent>,
    file_id: uuid::Uuid,
    compression: bool,
    progress_callback: &'a Option<Box<dyn Fn(FileProgress) + Send + Sync>>,
    bytes_transferred: &'a mut u64,
    total_file_size: &'a mut Option<u64>,
    received_checksum: &'a mut String,
    transfer_success: &'a mut bool,
    last_progress_update: &'a mut std::time::Instant,
    start: std::time::Instant,
}

/// Process download stream with timeout and handle all protocol messages
async fn process_download_stream(ctx: DownloadStreamContext<'_>) -> crate::error::Result<()> {
    use crate::protocols::file_transfer::FileTransferMessage;
    use tokio::time::Duration;

    let download_result = tokio::time::timeout(Duration::from_secs(300), async {
        while let Ok(event) = ctx.event_rx.recv().await {
            if let crate::quic_conn::QuicConnectionEvent::InboundStreamData(_, data) = event {
                if data.is_empty() {
                    break; // End of stream
                }

                // Parse protocol message
                if let Ok(message) = serde_json::from_slice::<FileTransferMessage>(&data) {
                    match message {
                        FileTransferMessage::DataChunk {
                            file_id: chunk_file_id,
                            data: chunk_data,
                            is_final,
                            ..
                        } => {
                            // Verify file_id matches our request
                            if chunk_file_id != ctx.file_id {
                                return Err(crate::error::CryptoTransportError::Internal(
                                    "File ID mismatch in data chunk".to_string(),
                                ));
                            }

                            // Apply decompression if requested
                            let data_to_write = if ctx.compression {
                                match cryypt_compression::zstd::decompress(&chunk_data) {
                                    Ok(decompressed) => decompressed,
                                    Err(e) => {
                                        return Err(crate::error::CryptoTransportError::Internal(
                                            format!("Decompression failed: {e}"),
                                        ));
                                    }
                                }
                            } else {
                                chunk_data
                            };

                            // Write chunk to file
                            ctx.writer.write_all(&data_to_write).await?;
                            *ctx.bytes_transferred += data_to_write.len() as u64;

                            // Send real-time progress updates
                            if ctx.progress_callback.is_some()
                                && ctx.last_progress_update.elapsed().as_millis() > 100
                            {
                                let elapsed = ctx.start.elapsed().as_secs_f64();
                                #[allow(clippy::cast_precision_loss)]
                                let mbps = if elapsed > 0.0 {
                                    (*ctx.bytes_transferred as f64 * 8.0) / (elapsed * 1_000_000.0)
                                } else {
                                    0.0
                                };

                                #[allow(clippy::cast_precision_loss)]
                                let percent = if let Some(total) = *ctx.total_file_size {
                                    (*ctx.bytes_transferred as f64 / total as f64) * 100.0
                                } else {
                                    // No total size known yet, show indeterminate progress
                                    0.0
                                };

                                if let Some(callback) = ctx.progress_callback {
                                    callback(FileProgress {
                                        percent: percent.min(100.0),
                                        bytes_transferred: *ctx.bytes_transferred,
                                        total_bytes: ctx
                                            .total_file_size
                                            .unwrap_or(*ctx.bytes_transferred),
                                        mbps,
                                    });
                                }

                                *ctx.last_progress_update = std::time::Instant::now();
                            }

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
                            if complete_file_id != ctx.file_id {
                                return Err(crate::error::CryptoTransportError::Internal(
                                    "File ID mismatch in transfer complete".to_string(),
                                ));
                            }

                            *ctx.received_checksum = checksum;
                            *ctx.transfer_success = success;

                            // Set final total size for progress calculation
                            *ctx.total_file_size = Some(*ctx.bytes_transferred);
                            break;
                        }
                        _ => {} // Ignore other message types
                    }
                } else {
                    // Treat as raw chunk data if not a protocol message
                    ctx.writer.write_all(&data).await?;
                    *ctx.bytes_transferred += data.len() as u64;
                }
            }
        }
        Ok::<(), crate::error::CryptoTransportError>(())
    });

    download_result.await.map_err(|_| {
        crate::error::CryptoTransportError::Internal("Download operation timed out".to_string())
    })?
}

/// Initialize download file writer and tracking variables
async fn initialize_download_writer(
    path: &PathBuf,
    connection: &crate::quic_conn::QuicConnectionHandle,
) -> Result<(
    BufWriter<File>,
    tokio::sync::broadcast::Receiver<crate::quic_conn::QuicConnectionEvent>,
    Option<u64>,
    std::time::Instant,
    String,
    bool,
)> {
    let file = File::create(path).await?;
    let writer = BufWriter::new(file);
    let event_rx = connection.subscribe_to_events();
    let total_file_size: Option<u64> = None;
    let last_progress_update = std::time::Instant::now();
    let received_checksum = String::new();
    let transfer_success = false;

    Ok((
        writer,
        event_rx,
        total_file_size,
        last_progress_update,
        received_checksum,
        transfer_success,
    ))
}

/// Send download request and establish connection
async fn send_download_request(
    path: &PathBuf,
    addr: SocketAddr,
    resume: bool,
) -> Result<(crate::quic_conn::QuicConnectionHandle, uuid::Uuid)> {
    use crate::protocols::file_transfer::FileTransferMessage;
    use uuid::Uuid;

    let file_id = Uuid::new_v4();

    // Get filename for the download request
    let filename = path
        .file_name()
        .ok_or_else(|| {
            crate::error::CryptoTransportError::Internal("Invalid filename".to_string())
        })?
        .to_string_lossy()
        .to_string();

    // Establish QUIC connection with proper certificate verification
    let connection = setup_download_connection(addr).await?;

    // Calculate resume offset if resume is enabled
    let resume_offset = calculate_resume_offset(path, resume).await;

    // Send download request using proper protocol
    let download_request = FileTransferMessage::DownloadRequest {
        file_id,
        filename: filename.clone(),
        resume_offset,
    };

    let request_data = serde_json::to_vec(&download_request).map_err(|e| {
        crate::error::CryptoTransportError::Internal(format!("Serialization error: {e}"))
    })?;

    connection.send_stream_data(&request_data, false)?;

    Ok((connection, file_id))
}

/// Execute production-quality streaming file download using existing protocol
pub(crate) async fn execute_download_streaming(
    path: PathBuf,
    addr: SocketAddr,
    compression: bool,
    resume: bool,
    progress_callback: Option<Box<dyn Fn(FileProgress) + Send + Sync>>,
) -> Result<FileTransferResult> {
    use tokio::time::Duration;

    let start = std::time::Instant::now();
    let mut bytes_transferred = 0u64;

    // Send download request and get connection
    let (connection, file_id) = send_download_request(&path, addr, resume).await?;

    // Initialize download file writer and tracking variables
    let (
        mut writer,
        mut event_rx,
        mut total_file_size,
        mut last_progress_update,
        mut received_checksum,
        mut transfer_success,
    ) = initialize_download_writer(&path, &connection).await?;

    // Receive file data in streaming chunks with proper protocol handling
    process_download_stream(DownloadStreamContext {
        writer: &mut writer,
        event_rx: &mut event_rx,
        file_id,
        compression,
        progress_callback: &progress_callback,
        bytes_transferred: &mut bytes_transferred,
        total_file_size: &mut total_file_size,
        received_checksum: &mut received_checksum,
        transfer_success: &mut transfer_success,
        last_progress_update: &mut last_progress_update,
        start,
    })
    .await?;

    // Complete download processing and return result
    handle_download_completion(DownloadCompletionContext {
        writer,
        path: &path,
        bytes_transferred,
        total_file_size,
        received_checksum,
        transfer_success,
        progress_callback: progress_callback.as_deref(),
        start,
    })
    .await
}

/// Setup QUIC connection with certificate verification for download
async fn setup_download_connection(
    addr: SocketAddr,
) -> Result<crate::quic_conn::QuicConnectionHandle> {
    // Parse server address to get hostname for certificate verification
    let server_hostname = if let Some(colon_pos) = addr.to_string().rfind(':') {
        &addr.to_string()[..colon_pos]
    } else {
        &addr.to_string()
    };

    let mut crypto_builder = crate::builder::QuicCryptoBuilder::new()
        .with_verify_peer(true)
        .with_max_idle_timeout(300 * 1000)
        .with_initial_max_data(10_000_000_000) // 10GB
        .with_server_name(server_hostname)
        .with_certificate_verification(true)
        .with_hostname_verification(true);

    // Load system certificate store for production security
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

    let crypto_config = crypto_builder.build_client()?;
    let connection =
        crate::connect_quic_client("0.0.0.0:0", &addr.to_string(), crypto_config).await?;

    // Wait for handshake completion with timeout
    tokio::time::timeout(Duration::from_secs(30), connection.wait_for_handshake()).await??;

    Ok(connection)
}

/// Calculate resume offset for download continuation
async fn calculate_resume_offset(path: &PathBuf, resume: bool) -> Option<u64> {
    if resume {
        match tokio::fs::metadata(path).await {
            Ok(metadata) => Some(metadata.len()),
            Err(_) => Some(0), // File doesn't exist, start from beginning
        }
    } else {
        None
    }
}

/// Context for download data processing
struct ProcessDownloadDataContext<'a> {
    writer: &'a mut BufWriter<File>,
    file_id: uuid::Uuid,
    compression: bool,
    progress_callback: Option<&'a (dyn Fn(FileProgress) + Send + Sync)>,
    bytes_transferred: &'a mut u64,
    total_file_size: &'a mut Option<u64>,
    received_checksum: &'a mut String,
    transfer_success: &'a mut bool,
    last_progress_update: &'a mut std::time::Instant,
}

/// Process download data reception and write to file
async fn process_download_data(
    mut event_rx: tokio::sync::broadcast::Receiver<crate::quic_conn::QuicConnectionEvent>,
    ctx: ProcessDownloadDataContext<'_>,
) -> Result<()> {
    use crate::protocols::file_transfer::FileTransferMessage;

    while let Ok(event) = event_rx.recv().await {
        if let crate::quic_conn::QuicConnectionEvent::InboundStreamData(_, data) = event {
            if data.is_empty() {
                break; // End of stream
            }

            // Parse protocol message
            if let Ok(message) = serde_json::from_slice::<FileTransferMessage>(&data) {
                match message {
                    FileTransferMessage::DataChunk {
                        file_id: chunk_file_id,
                        data: chunk_data,
                        is_final,
                        ..
                    } => {
                        // Verify file_id matches our request
                        if chunk_file_id != ctx.file_id {
                            return Err(crate::error::CryptoTransportError::Internal(
                                "File ID mismatch in data chunk".to_string(),
                            ));
                        }

                        // Apply decompression if requested
                        let data_to_write = if ctx.compression {
                            match cryypt_compression::zstd::decompress(&chunk_data) {
                                Ok(decompressed) => decompressed,
                                Err(e) => {
                                    return Err(crate::error::CryptoTransportError::Internal(
                                        format!("Decompression failed: {e}"),
                                    ));
                                }
                            }
                        } else {
                            chunk_data
                        };

                        // Write chunk to file
                        ctx.writer.write_all(&data_to_write).await?;
                        *ctx.bytes_transferred += data_to_write.len() as u64;

                        // Update progress periodically
                        if ctx.last_progress_update.elapsed() >= Duration::from_millis(100) {
                            if let Some(callback) = ctx.progress_callback {
                                let progress = FileProgress {
                                    bytes_transferred: *ctx.bytes_transferred,
                                    total_bytes: ctx
                                        .total_file_size
                                        .unwrap_or(*ctx.bytes_transferred),
                                    percent: ctx
                                        .total_file_size
                                        .map(|total| {
                                            #[allow(clippy::cast_precision_loss)]
                                            {
                                                (*ctx.bytes_transferred as f64 / total as f64
                                                    * 100.0)
                                                    .min(100.0)
                                            }
                                        })
                                        .unwrap_or(0.0),
                                    mbps: 0.0, // TODO: Calculate actual transfer rate
                                };
                                callback(progress);
                            }
                            *ctx.last_progress_update = std::time::Instant::now();
                        }

                        if is_final {
                            ctx.writer.flush().await?;
                            *ctx.transfer_success = true;
                            break;
                        }
                    }
                    FileTransferMessage::TransferComplete { checksum, .. } => {
                        *ctx.received_checksum = checksum;
                        ctx.writer.flush().await?;
                        *ctx.transfer_success = true;
                        break;
                    }
                    _ => {
                        // Ignore other message types during download
                    }
                }
            }
        }
    }

    Ok(())
}
