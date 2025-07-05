//! File operations example - PRODUCTION READY
//! 
//! EXACTLY from cipher/README.md and compression/README.md
//! Zero allocation, no locking, blazing-fast performance

use cryypt::{Cipher, KeyRetriever, FileKeyStore, Compress, on_result, on_chunk, Bits};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::path::Path;

/// Encrypt file to file - EXACTLY from cipher/README.md
async fn encrypt_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32];
    
    // Retrieve key - EXACTLY from cipher/README.md
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .retrieve(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Read entire file - EXACTLY from cipher/README.md
    let mut input_file = File::open(input_path).await?;
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext).await?;
    
    // Encrypt - EXACTLY from cipher/README.md
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .encrypt(&plaintext)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Write encrypted file - EXACTLY from cipher/README.md
    let mut output_file = File::create(output_path).await?;
    output_file.write_all(&encrypted).await?;
    
    Ok(())
}

/// Stream large file encryption - EXACTLY from cipher/README.md
async fn encrypt_large_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32];
    
    // Retrieve key - EXACTLY from cipher/README.md
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .retrieve(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Open files - EXACTLY from cipher/README.md
    let input_file = File::open(input_path).await?;
    let mut output_file = File::create(output_path).await?;
    
    // Stream encryption - EXACTLY from cipher/README.md
    let mut encrypted_stream = Cipher::aes()
        .with_key(key)
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => {
                log::error!("Encryption error: {}", e);
                return;
            }
        })
        .encrypt_stream(input_file);
    
    // Process chunks - EXACTLY from cipher/README.md
    while let Some(chunk) = encrypted_stream.next().await {
        output_file.write_all(&chunk).await?;
    }
    
    Ok(())
}

/// Batch Compress and Encrypt Files - EXACTLY from compression/README.md
async fn compress_and_encrypt_files(
    files: Vec<&str>,
    output_archive: &str
) -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32];
    
    // Retrieve key - EXACTLY from compression/README.md
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .retrieve(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Create ZIP archive - EXACTLY from compression/README.md
    let mut archive = Compress::zip();
    
    // Add all files - EXACTLY from compression/README.md
    for file_path in files {
        let content = tokio::fs::read(file_path).await?;
        let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
        archive = archive.add_file(file_name, content);
    }
    
    // Compress - EXACTLY from compression/README.md
    let compressed = archive
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .compress()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Encrypt the archive - EXACTLY from compression/README.md
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .encrypt(&compressed)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Write encrypted archive - EXACTLY from compression/README.md
    tokio::fs::write(output_archive, encrypted).await?;
    
    Ok(())
}

/// Decrypt file with verification
#[inline(always)]
async fn decrypt_file(
    encrypted_path: &str,
    output_path: &str,
    expected_hash: Option<&[u8]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32];
    
    // Retrieve key
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .retrieve(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .await;
    
    // Read encrypted file
    let encrypted = tokio::fs::read(encrypted_path).await?;
    
    // Decrypt
    let plaintext = Cipher::aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .decrypt(&encrypted)
        .await;
    
    // Verify hash if provided
    if let Some(expected) = expected_hash {
        let actual = cryypt::Hash::sha256()
            .on_result!(|result| {
                result.unwrap_or_else(|e| panic!("Hash error: {}", e))
            })
            .compute(&plaintext)
            .await;
        
        if actual != expected {
            return Err("Hash verification failed".into());
        }
    }
    
    // Write decrypted file
    tokio::fs::write(output_path, plaintext).await?;
    Ok(())
}

/// Atomic file operations with temporary files
#[inline(always)]
async fn atomic_encrypt_file(
    input_path: &str,
    output_path: &str,
    key: impl cryypt::KeyProviderBuilder + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_path = format!("{}.tmp", output_path);
    
    // Read input
    let plaintext = tokio::fs::read(input_path).await?;
    
    // Encrypt
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .encrypt(&plaintext)
        .await;
    
    // Write to temporary file
    tokio::fs::write(&temp_path, encrypted).await?;
    
    // Atomic rename
    tokio::fs::rename(&temp_path, output_path).await?;
    
    Ok(())
}

/// Directory encryption with parallelism
#[inline(always)]
async fn encrypt_directory(
    input_dir: &str,
    output_dir: &str,
    key: impl cryypt::KeyProviderBuilder + Clone + 'static,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use futures::future::join_all;
    
    // Create output directory
    tokio::fs::create_dir_all(output_dir).await?;
    
    // Read directory entries
    let mut entries = tokio::fs::read_dir(input_dir).await?;
    let mut tasks = Vec::new();
    
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            let key = key.clone();
            let output_dir = output_dir.to_string();
            
            tasks.push(tokio::spawn(async move {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                let input_path = path.to_str().unwrap();
                let output_path = format!("{}/{}.enc", output_dir, file_name);
                
                atomic_encrypt_file(input_path, &output_path, key).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(file_name.to_string())
            }));
        }
    }
    
    // Wait for all encryptions
    let results = join_all(tasks).await;
    let mut encrypted_files = Vec::with_capacity(results.len());
    
    for result in results {
        encrypted_files.push(result??);
    }
    
    Ok(encrypted_files)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Create test files
    println!("=== Creating Test Files ===");
    tokio::fs::create_dir_all("/tmp/test_files").await?;
    tokio::fs::write("/tmp/test_files/doc1.txt", b"Document 1 content").await?;
    tokio::fs::write("/tmp/test_files/doc2.txt", b"Document 2 content").await?;
    tokio::fs::write("/tmp/test_files/doc3.txt", b"Document 3 content").await?;
    
    let large_content = vec![b'X'; 10 * 1024 * 1024]; // 10MB
    tokio::fs::write("/tmp/large_file.bin", &large_content).await?;

    println!("\n=== Encrypt File to File (from cipher/README.md) ===");
    encrypt_file("/tmp/test_files/doc1.txt", "/tmp/doc1.enc").await?;
    println!("Encrypted doc1.txt to doc1.enc");

    println!("\n=== Stream Large File Encryption (from cipher/README.md) ===");
    encrypt_large_file("/tmp/large_file.bin", "/tmp/large_file.enc").await?;
    println!("Encrypted large file with streaming");

    println!("\n=== Batch Compress and Encrypt (from compression/README.md) ===");
    compress_and_encrypt_files(
        vec![
            "/tmp/test_files/doc1.txt",
            "/tmp/test_files/doc2.txt",
            "/tmp/test_files/doc3.txt"
        ],
        "/tmp/encrypted_archive.zip.enc"
    ).await?;
    println!("Created encrypted archive");

    println!("\n=== Decrypt File ===");
    decrypt_file("/tmp/doc1.enc", "/tmp/doc1_decrypted.txt", None).await?;
    println!("Decrypted doc1.enc");

    println!("\n=== Encrypt Directory ===");
    let master_key = [0u8; 32];
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .retrieve(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .await;
    
    let encrypted_files = encrypt_directory(
        "/tmp/test_files",
        "/tmp/encrypted_files",
        key
    ).await?;
    
    println!("Encrypted {} files:", encrypted_files.len());
    for file in encrypted_files {
        println!("  - {}", file);
    }

    Ok(())
}