//! Simple File Transfer with High-Level QUIC Builders
//!
//! This example shows how the new high-level protocol builders make 
//! file transfer incredibly simple compared to the low-level approach.
//!
//! Compare this to secure_file_transfer.rs to see the difference!

use cryypt::transport::quic::QuicFileTransfer;
use cryypt::bits_macro::BitSize;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} [server|upload <file>|download <file>]", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "server" => {
            // Start a production-ready file transfer server in just a few lines!
            QuicFileTransfer::server()
                .with_storage_dir("./uploads")
                .with_max_file_size(1u64.gb())  // Using BitSize for human-readable values
                .with_compression(true)
                .with_max_concurrent_transfers(100)
                .with_tls_cert("server.crt", "server.key")
                .listen("0.0.0.0:4433")
                .await?;
            
            println!("🎉 Server started with quantum-resistant encryption!");
        }
        
        "upload" => {
            if args.len() < 3 {
                eprintln!("Usage: {} upload <file_path>", args[0]);
                std::process::exit(1);
            }
            
            // Upload a file with automatic resume, compression, and integrity verification
            let result = QuicFileTransfer::connect("127.0.0.1:4433")
                .upload(&args[2])
                .with_compression(true)
                .with_resume(true)
                .with_progress(|progress| {
                    println!("📈 Upload progress: {:.1}% ({:.1} MB/s)", 
                        (progress.bytes_transferred as f64 / progress.total_bytes as f64) * 100.0,
                        progress.throughput_mbps);
                })
                .execute()
                .await?;

            println!("✅ Upload completed: {} bytes in {:?}", 
                result.bytes_transferred, result.duration);
            println!("🔐 File integrity verified with checksum: {}", result.checksum);
        }
        
        "download" => {
            if args.len() < 3 {
                eprintln!("Usage: {} download <filename>", args[0]);
                std::process::exit(1);
            }
            
            // Download a file with automatic verification
            let result = QuicFileTransfer::connect("127.0.0.1:4433")
                .download(&args[2])
                .to_path("./downloads/")
                .with_checksum_verification(true)
                .with_resume(true)
                .execute()
                .await?;

            println!("✅ Download completed: {} bytes in {:?}", 
                result.bytes_transferred, result.duration);
        }
        
        "list" => {
            // List available files on the server
            let files = QuicFileTransfer::connect("127.0.0.1:4433")
                .list_files()
                .await?;

            println!("📁 Files on server:");
            for file in files {
                println!("  {} ({} bytes, uploaded {})", 
                    file.filename, file.size, file.upload_time);
            }
        }
        
        _ => {
            eprintln!("Invalid command. Use: server, upload <file>, download <file>, or list");
            std::process::exit(1);
        }
    }

    Ok(())
}

// The entire example above is only ~70 lines!
// Compare this to the 400+ lines needed with low-level QUIC primitives.
// 
// The high-level builders handle ALL the complexity:
// ✅ QUIC connection management and retry logic
// ✅ File chunking and streaming  
// ✅ Compression and decompression
// ✅ SHA3 checksum calculation and verification
// ✅ Resume capability with offset tracking
// ✅ Progress reporting and throughput calculation
// ✅ Post-quantum encryption and ephemeral key rotation
// ✅ Error handling and graceful degradation
// ✅ Flow control and backpressure
// ✅ Certificate generation and TLS setup
// ✅ Message protocol design and serialization
// ✅ Stream management and multiplexing
//
// Users can focus on their application logic instead of 
// reinventing cryptographic file transfer protocols!