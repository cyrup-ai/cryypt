//! File upload operations over QUIC

use std::io::Read;
use super::types::FileTransferResult;
use super::builder::FileTransferBuilder;
use crate::api::Quic;

/// Execute file upload over QUIC
pub(crate) fn execute_upload(builder: std::pin::Pin<&mut FileTransferBuilder>) -> FileTransferResult {
    
    // Execute as async block to use real QUIC implementation
    let runtime = tokio::runtime::Handle::current();
    runtime.block_on(async {
        execute_upload_async(builder).await
    })
}

async fn execute_upload_async(builder: std::pin::Pin<&mut FileTransferBuilder>) -> FileTransferResult {
    let start = std::time::Instant::now();
    let bytes_transferred: u64;
    
    // Open file first
    let mut file = match std::fs::File::open(&builder.path) {
        Ok(file) => file,
        Err(e) => {
            tracing::error!("Failed to open file for upload: {}", e);
            return FileTransferResult {
                bytes_transferred: 0,
                duration: start.elapsed(),
                success: false,
            };
        }
    };
    
    let metadata = file.metadata();
    let file_size = metadata.map(|m| m.len()).unwrap_or(0);
    
    // Connect to QUIC server using real API
    let quic_client = match Quic::client()
        .with_server_name("localhost")
        .on_result(|result| match result {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::error!("QUIC connection failed: {}", e);
                None
            }
        })
        .connect(&builder.addr.to_string()).await
    {
        Some(client) => client,
        None => {
            return FileTransferResult {
                bytes_transferred: 0,
                duration: start.elapsed(),
                success: false,
            };
        }
    };
    
    // Open bidirectional stream using real QUIC API
    let (send_stream, _recv_stream) = match quic_client
        .on_result(|result| match result {
            Ok((send, recv)) => Some((send, recv)),
            Err(e) => {
                tracing::error!("Failed to open QUIC stream: {}", e);
                None
            }
        })
        .open_bi().await
    {
        Some(streams) => streams,
        None => {
            return FileTransferResult {
                bytes_transferred: 0,
                duration: start.elapsed(),
                success: false,
            };
        }
    };
    
    // Read entire file into memory
    let mut file_data = Vec::new();
    match file.read_to_end(&mut file_data) {
        Ok(total_read) => {
            // Apply compression if requested using real cryypt_compression
            let data_to_send = if builder.compressed {
                match cryypt_compression::zstd::compress(&file_data, 3) {
                    Ok(compressed) => {
                        bytes_transferred = compressed.len() as u64;
                        compressed
                    },
                    Err(e) => {
                        tracing::error!("Compression failed: {}", e);
                        return FileTransferResult {
                            bytes_transferred: 0,
                            duration: start.elapsed(),
                            success: false,
                        };
                    }
                }
            } else {
                bytes_transferred = total_read as u64;
                file_data
            };
            
            // Send entire file over QUIC stream in one write
            let write_result = send_stream.write_all(&data_to_send).await;
            let upload_success = match write_result {
                Ok(()) => {
                    // Progress callback - show 100% completion
                    if let Some(ref handler) = builder.progress_handler {
                        let elapsed = start.elapsed().as_secs_f64();
                        let mbps = if elapsed > 0.0 {
                            (bytes_transferred as f64 * 8.0) / (elapsed * 1_000_000.0)
                        } else {
                            0.0
                        };
                        
                        handler(super::types::FileProgress {
                            percent: 100.0,
                            bytes_transferred: total_read as u64,
                            total_bytes: file_size,
                            mbps,
                        });
                    }
                    true
                },
                Err(e) => {
                    tracing::error!("QUIC stream write failed: {}", e);
                    false
                }
            };
            
            FileTransferResult {
                bytes_transferred,
                duration: start.elapsed(),
                success: upload_success,
            }
        },
        Err(e) => {
            tracing::error!("Failed to read file: {}", e);
            FileTransferResult {
                bytes_transferred: 0,
                duration: start.elapsed(),
                success: false,
            }
        }
    }
}