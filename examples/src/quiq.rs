//! Beautiful QUIC Transport with Quique
//!
//! This example demonstrates the new Quique API for QUIC transport with:
//! - Explicit UDP transport specification  
//! - Persistent connections with multiplexed protocols
//! - Post-quantum cryptography by default
//! - Clean, typed, fluent interface
//!
//! Usage:
//!   cargo run --example quiq -- server
//!   cargo run --example quiq -- client upload file.zip
//!   cargo run --example quiq -- client download remote.zip

use cryypt::transport::{Auth, Quique, Transport};
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [server|client] [operation] [file]", args[0]);
        eprintln!("Examples:");
        eprintln!("  {} server", args[0]);
        eprintln!("  {} client upload file.zip", args[0]);
        eprintln!("  {} client download remote.zip", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "server" => run_server().await,
        "client" => {
            if args.len() < 4 {
                eprintln!(
                    "Client requires operation and file: {} client [upload|download] <file>",
                    args[0]
                );
                std::process::exit(1);
            }
            match args[2].as_str() {
                "upload" => run_client_upload(&args[3]).await,
                "download" => run_client_download(&args[3]).await,
                _ => {
                    eprintln!("Invalid operation. Use 'upload' or 'download'");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("Invalid mode. Use 'server' or 'client'");
            std::process::exit(1);
        }
    }
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 Starting beautiful Quique server...");
    println!("🌐 Transport: UDP (QUIC protocol)");
    println!("🔐 Crypto: Post-quantum ML-KEM + ML-DSA");

    // Beautiful, explicit server configuration
    Quique::server(Transport::UDP)
        .port(11443)
        .auth(Auth::Anonymous) // For demo - use Auth::MutualTLS in production
        .handle_streams(|stream| async move {
            println!(
                "📡 New stream {} using {:?} protocol",
                stream.stream_id(),
                stream.protocol()
            );
            Ok(())
        })
        .listen()
        .await?;

    Ok(())
}

async fn run_client_upload(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 Beautiful Quique client upload");
    println!("📁 File: {}", file_path);
    println!("🌐 Transport: UDP (QUIC protocol)");

    // Establish persistent QUIC connection
    let connection = Quique::client(Transport::UDP)
        .auth(Auth::Anonymous)
        .connect("127.0.0.1:11443")
        .await?;

    println!("✅ Connected! Using multiplexed protocols over persistent QUIC connection");

    // Example 1: Single file upload (convenience method)
    println!("📤 Method 1: Convenience upload");
    let result = connection.upload_file(file_path).compressed().await?;
    println!(
        "✅ Uploaded {} bytes in {:?}",
        result.bytes_transferred, result.duration
    );

    // Example 2: Multiplexed protocol dispatch over same connection
    println!("📤 Method 2: Multiplexed protocol dispatch");
    connection
        .stream(|stream| async move {
            // File transfer protocol
            let result = stream
                .file_transfer()
                .upload(file_path)
                .with_progress(|p| println!("📊 {}% ({:.1} MB/s)", p.percent, p.mbps))
                .await?;
            println!("✅ Upload completed: {} bytes", result.bytes_transferred);

            // Messaging protocol over same connection
            stream
                .messaging()
                .send("Upload completed successfully!")
                .reliable()
                .await?;
            println!("✅ Notification sent");

            // RPC protocol over same connection
            let response = stream
                .rpc()
                .call("process_uploaded_file", file_path)
                .timeout(Duration::from_secs(30))
                .await?;
            println!("✅ RPC response: {}", response);

            Ok(())
        })
        .await?;

    println!("🎉 All operations completed over single persistent QUIC connection!");
    Ok(())
}

async fn run_client_download(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 Beautiful Quique client download");
    println!("📁 Remote file: {}", file_path);
    println!("🌐 Transport: UDP (QUIC protocol)");

    // Establish persistent QUIC connection
    let connection = Quique::client(Transport::UDP)
        .auth(Auth::Anonymous)
        .connect("127.0.0.1:11443")
        .await?;

    println!("✅ Connected! Downloading over QUIC...");

    // Download with progress tracking
    let result = connection.download_file(file_path).await?;

    println!(
        "✅ Downloaded {} bytes in {:?}",
        result.bytes_transferred, result.duration
    );
    println!("🎉 Download completed!");
    Ok(())
}

// That's it! Beautiful, clean, and powerful.
//
// Key benefits of the new Quique API:
// 1. Explicit Transport::UDP - no confusion about protocol
// 2. Persistent connections - establish once, use for multiple operations
// 3. Multiplexed protocols - file transfer, messaging, RPC over same connection
// 4. Type-safe builders - fluent interface with compile-time guarantees
// 5. Post-quantum crypto by default - ML-KEM + ML-DSA built-in
// 6. Zero configuration - auto-generates ephemeral certs and keys
// 7. Clean error handling - single Result type throughout
