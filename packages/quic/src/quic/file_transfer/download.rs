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

/// Execute production-quality streaming file download using existing protocol
pub(crate) async fn execute_download_streaming(
    path: PathBuf,
    addr: SocketAddr,
    compression: bool,
    resume: bool,
    progress_callback: Option<Box<dyn Fn(FileProgress) + Send + Sync>>,
) -> Result<FileTransferResult> {
    use crate::protocols::file_transfer::FileTransferMessage;
    use tokio::time::Duration;
    use uuid::Uuid;

    let start = std::time::Instant::now();
    let mut bytes_transferred = 0u64;
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
    let mut crypto_builder = crate::builder::QuicCryptoBuilder::new()
        .with_verify_peer(true)
        .with_max_idle_timeout(300 * 1000)
        .with_initial_max_data(10_000_000_000); // 10GB

    // Parse server address to get hostname for certificate verification
    let server_hostname = if let Some(colon_pos) = addr.to_string().rfind(':') {
        &addr.to_string()[..colon_pos]
    } else {
        &addr.to_string()
    };

    crypto_builder = crypto_builder
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

    // Calculate resume offset if resume is enabled
    let resume_offset = if resume {
        match tokio::fs::metadata(&path).await {
            Ok(metadata) => Some(metadata.len()),
            Err(_) => Some(0), // File doesn't exist, start from beginning
        }
    } else {
        None
    };

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

    // Create output file for streaming write
    let mut event_rx = connection.subscribe_to_events();
    let mut total_file_size: Option<u64> = None;

    let file = File::create(&path).await?;
    let mut writer = BufWriter::new(file);
    let mut last_progress_update = std::time::Instant::now();
    let mut received_checksum = String::new();
    let mut transfer_success = false;

    // Receive file data in streaming chunks with proper protocol handling
    let download_timeout = tokio::time::timeout(Duration::from_secs(300), async {
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
                            if chunk_file_id != file_id {
                                return Err(crate::error::CryptoTransportError::Internal(
                                    "File ID mismatch in data chunk".to_string(),
                                ));
                            }

                            // Apply decompression if requested
                            let data_to_write = if compression {
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
                            writer.write_all(&data_to_write).await?;
                            bytes_transferred += data_to_write.len() as u64;

                            // Send real-time progress updates
                            if progress_callback.is_some()
                                && last_progress_update.elapsed().as_millis() > 100
                            {
                                let elapsed = start.elapsed().as_secs_f64();
                                let mbps = if elapsed > 0.0 {
                                    (bytes_transferred as f64 * 8.0) / (elapsed * 1_000_000.0)
                                } else {
                                    0.0
                                };

                                let percent = if let Some(total) = total_file_size {
                                    (bytes_transferred as f64 / total as f64) * 100.0
                                } else {
                                    // No total size known yet, show indeterminate progress
                                    0.0
                                };

                                if let Some(ref callback) = progress_callback {
                                    callback(FileProgress {
                                        percent: percent.min(100.0),
                                        bytes_transferred,
                                        total_bytes: total_file_size.unwrap_or(bytes_transferred),
                                        mbps,
                                    });
                                }

                                last_progress_update = std::time::Instant::now();
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
                            if complete_file_id != file_id {
                                return Err(crate::error::CryptoTransportError::Internal(
                                    "File ID mismatch in transfer complete".to_string(),
                                ));
                            }

                            received_checksum = checksum;
                            transfer_success = success;

                            // Set final total size for progress calculation
                            total_file_size = Some(bytes_transferred);
                            break;
                        }
                        _ => continue, // Ignore other message types
                    }
                } else {
                    // Treat as raw chunk data if not a protocol message
                    writer.write_all(&data).await?;
                    bytes_transferred += data.len() as u64;
                }
            }
        }
        Ok::<(), crate::error::CryptoTransportError>(())
    });

    // Handle timeout
    download_timeout.await.map_err(|_| {
        crate::error::CryptoTransportError::Internal("Download operation timed out".to_string())
    })??;

    // Flush and close file
    writer.flush().await?;
    drop(writer);

    // Final progress update
    if let Some(ref callback) = progress_callback {
        let elapsed = start.elapsed().as_secs_f64();
        let mbps = if elapsed > 0.0 {
            (bytes_transferred as f64 * 8.0) / (elapsed * 1_000_000.0)
        } else {
            0.0
        };

        callback(FileProgress {
            percent: 100.0,
            bytes_transferred,
            total_bytes: total_file_size.unwrap_or(bytes_transferred),
            mbps,
        });
    }

    // Verify checksum if available and requested
    let checksum_verified = if !received_checksum.is_empty() {
        // Reopen file for checksum calculation
        let mut file_for_hash = File::open(&path).await.map_err(|e| {
            crate::error::CryptoTransportError::Internal(format!(
                "Failed to reopen file for checksum: {}",
                e
            ))
        })?;

        let mut buffer = Vec::new();
        file_for_hash.read_to_end(&mut buffer).await.map_err(|e| {
            crate::error::CryptoTransportError::Internal(format!(
                "Failed to read file for checksum: {}",
                e
            ))
        })?;

        // Calculate SHA3-256 hash like production code
        use cryypt_hashing::Hash;
        let computed_hash = Hash::sha3_256().compute(buffer).await.map_err(|e| {
            crate::error::CryptoTransportError::Internal(format!("Hash computation error: {e}"))
        })?;

        let computed_checksum = hex::encode(computed_hash);
        computed_checksum == received_checksum
    } else {
        true // Skip verification if no checksum provided
    };

    let success = transfer_success && checksum_verified && bytes_transferred > 0;

    Ok(FileTransferResult {
        bytes_transferred,
        duration: start.elapsed(),
        success,
    })
}
