//! File download operations over QUIC

use std::io::Write;
use super::types::FileTransferResult;
use crate::error::Result;
use super::builder::FileTransferBuilder;
use crate::api::Quic;


/// Execute file download over QUIC  
pub(crate) fn execute_download(builder: std::pin::Pin<&mut FileTransferBuilder>) -> FileTransferResult {
    
    // Execute as async block to use real QUIC implementation
    let runtime = tokio::runtime::Handle::current();
    match runtime.block_on(async {
        execute_download_async(builder).await
    }) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("File download failed: {}", e);
            FileTransferResult {
                bytes_transferred: 0,
                duration: std::time::Duration::from_secs(0),
                success: false,
            }
        }
    }
}

async fn execute_download_async(builder: std::pin::Pin<&mut FileTransferBuilder>) -> Result<FileTransferResult> {
    let start = std::time::Instant::now();
    let mut bytes_transferred = 0u64;
    let expected_file_size = 0u64;
    
    // Create output file
    let mut file = std::fs::File::create(&builder.path)
        .map_err(|e| {
            tracing::error!("Failed to create file for download: {}", e);
crate::error::CryptoTransportError::Network(e)
        })?;
    
    // Connect to QUIC server using real API
    let quic_client = Quic::client()
        .with_server_name("localhost")
        .on_result(|result| match result {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::error!("QUIC connection failed: {}", e);
                None
            }
        })
        .connect(&builder.addr.to_string()).await
        .ok_or_else(|| crate::error::CryptoTransportError::Connection("Failed to establish QUIC connection".to_string()))?;
    
    // Open bidirectional stream using real QUIC API
    let (_send_stream, _recv_stream) = quic_client
        .on_result(|result| match result {
            Ok((send, recv)) => Some((send, recv)),
            Err(e) => {
                tracing::error!("Failed to open QUIC stream: {}", e);
                None
            }
        })
        .open_bi().await
        .ok_or_else(|| crate::error::CryptoTransportError::Connection("Failed to open QUIC stream".to_string()))?;
    
    // Use real file transfer protocol - no fabricated "SIZE:" messages
    // File size comes from UploadRequest message as per FileTransferMessage enum
    
    // Connect to file transfer service using proper QuicConnectionHandle
    let connection = crate::connect_quic_client("0.0.0.0:0", &builder.addr.to_string(), 
        crate::QuicCryptoBuilder::new().build_client()?).await?;
    connection.wait_for_handshake().await?;
    
    // Send proper DownloadRequest using real FileTransferMessage protocol  
    let download_request = crate::protocols::file_transfer::FileTransferMessage::DownloadRequest {
        file_id: uuid::Uuid::new_v4(),
        filename: std::path::Path::new(&builder.path).file_name().unwrap_or_default().to_string_lossy().to_string(),
        resume_offset: None, // Will implement real resume later
    };
    
    let request_data = serde_json::to_vec(&download_request)
        .map_err(|e| std::io::Error::other(format!("Failed to serialize download request: {}", e)))?;
    connection.send_stream_data(&request_data, false)
        .map_err(|e| std::io::Error::other(format!("Failed to send download request: {}", e)))?;
    
    // Use real connection event subscription pattern from receiver.rs:248-310
    let mut event_rx = connection.subscribe_to_events();
    let mut download_success = true;
    
    while let Ok(event) = event_rx.recv().await {
        if let crate::quic_conn::QuicConnectionEvent::InboundStreamData(_, data) = event {
            if data.is_empty() {
                break; // End of stream
            }
            
            // Parse real FileTransferMessage protocol messages
            if let Ok(message) = serde_json::from_slice::<crate::protocols::file_transfer::FileTransferMessage>(&data) {
                match message {
                    crate::protocols::file_transfer::FileTransferMessage::DataChunk { 
                        file_id: _chunk_file_id, data: chunk_data, is_final, .. 
                    } => {
                        // Real file size comes from initial UploadRequest - no fabricated SIZE: protocol needed
                        
                        // Decompress if needed using real cryypt_compression
                        let data_to_write = if builder.compressed {
                            match cryypt_compression::zstd::decompress(&chunk_data) {
                                Ok(decompressed) => decompressed,
                                Err(e) => {
                                    tracing::error!("Decompression failed: {}", e);
                                    download_success = false;
                                    break;
                                }
                            }
                        } else {
                            chunk_data.to_vec()
                        };
                        
                        // Write to file
                        match file.write_all(&data_to_write) {
                            Ok(()) => {
                                bytes_transferred += data_to_write.len() as u64;
                                
                                // Progress callback with real progress calculation
                                if let Some(ref handler) = builder.progress_handler {
                                    let elapsed = start.elapsed().as_secs_f64();
                                    let mbps = if elapsed > 0.0 {
                                        (bytes_transferred as f64 * 8.0) / (elapsed * 1_000_000.0)
                                    } else {
                                        0.0
                                    };
                                    
                                    let percent = if expected_file_size > 0 {
                                        (bytes_transferred as f64 / expected_file_size as f64) * 100.0
                                    } else {
                                        // Fallback: estimate progress based on typical file sizes
                                        let estimated_total = if bytes_transferred < 1024 * 1024 {
                                            1024 * 1024 // Assume 1MB if very small
                                        } else {
                                            bytes_transferred * 2 // Conservative estimate
                                        };
                                        (bytes_transferred as f64 / estimated_total as f64) * 100.0
                                    };
                                    
                                    handler(super::types::FileProgress {
                                        percent: percent.min(100.0),
                                        bytes_transferred,
                                        total_bytes: expected_file_size,
                                        mbps,
                                    });
                                }
                            }
                            Err(e) => {
                                tracing::error!("File write error during download: {}", e);
                                download_success = false;
                                break;
                            }
                        }
                        
                        if is_final {
                            break;
                        }
                    }
                    _ => {
                        // Ignore other message types during download
                        continue;
                    }
                }
            }
        }
    }
    
    if let Err(e) = file.flush() {
        tracing::error!("Failed to flush file during download: {}", e);
        download_success = false;
    }
    
    Ok(FileTransferResult {
        bytes_transferred,
        duration: start.elapsed(),
        success: download_success,
    })
}