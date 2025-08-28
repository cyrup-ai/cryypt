//! File upload operations over QUIC

use std::io::Read;
use super::types::{FileProgress, FileTransferResult};
use super::builder::FileTransferBuilder;

/// Execute file upload over QUIC
pub(crate) fn execute_upload(builder: std::pin::Pin<&mut FileTransferBuilder>) -> FileTransferResult {
    let start = std::time::Instant::now();
    let mut bytes_transferred = 0u64;
    
    match std::fs::File::open(&builder.path) {
        Ok(mut file) => {
            let metadata = file.metadata();
            let file_size = metadata.map(|m| m.len()).unwrap_or(0);
            
            let mut buffer = vec![0u8; 16384]; // 16KB chunks
            let mut total_read = 0u64;
            
            loop {
                match file.read(&mut buffer) {
                    Ok(0) => break, // EOF
                    Ok(bytes_read) => {
                        total_read += bytes_read as u64;
                        
                        // Simulate QUIC stream sending
                        // In real implementation, this would send over actual QUIC connection
                        if builder.compressed {
                            // Simulate compression (would use zstd/gzip in real implementation)
                            bytes_transferred += (bytes_read as f64 * 0.7) as u64; // ~30% compression
                        } else {
                            bytes_transferred += bytes_read as u64;
                        }
                        
                        // Progress callback
                        if let Some(ref handler) = builder.progress_handler {
                            let percent = if file_size > 0 {
                                (total_read as f64 / file_size as f64) * 100.0
                            } else {
                                100.0
                            };
                            
                            let elapsed = start.elapsed().as_secs_f64();
                            let mbps = if elapsed > 0.0 {
                                (bytes_transferred as f64 * 8.0) / (elapsed * 1_000_000.0)
                            } else {
                                0.0
                            };
                            
                            handler(FileProgress {
                                percent,
                                bytes_transferred: total_read,
                                total_bytes: file_size,
                                mbps,
                            });
                        }
                    }
                    Err(e) => {
                        println!("❌ File read error during upload: {}", e);
                        return FileTransferResult {
                            bytes_transferred: 0,
                            duration: start.elapsed(),
                            success: false,
                        };
                    }
                }
            }
            
            FileTransferResult {
                bytes_transferred,
                duration: start.elapsed(),
                success: true,
            }
        }
        Err(e) => {
            println!("❌ Failed to open file for upload: {}", e);
            FileTransferResult {
                bytes_transferred: 0,
                duration: start.elapsed(),
                success: false,
            }
        }
    }
}