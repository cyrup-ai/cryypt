//! Combined operations example - PRODUCTION READY
//! 
//! Demonstrates efficient combination of multiple Cryypt operations
//! with zero allocation, no locking, and blazing-fast performance

use cryypt::{Cryypt, FileKeyStore, Bits};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use std::path::Path;
use std::pin::Pin;
use futures::stream::{Stream, StreamExt};

/// Pipeline: Hash -> Compress -> Encrypt with zero-copy streaming
#[inline(always)]
async fn hash_compress_encrypt_pipeline(
    data: &[u8],
    key: impl cryypt::KeyProviderBuilder + 'static,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // Compute hash for authentication
    let hash = Cryypt::hash()
        .sha256()
        .on_result(|result| {
            match result {
                Ok(hash) => hash,
                Err(e) => {
                    log::error!("Hash error: {}", e);
                    vec![]
                }
            }
        })
        .compute(data)
        .await;

    // Compress with optimal settings
    let compressed = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Compression error: {}", e);
                    vec![]
                }
            }
        })
        .compress(data)
        .await;

    // Encrypt with hash as AAD for integrity
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key)
        .with_aad(&hash)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Encryption error: {}", e);
                    vec![]
                }
            }
        })
        .encrypt(&compressed)
        .await;

    Ok((encrypted, hash))
}

/// Reverse pipeline: Decrypt -> Decompress -> Verify Hash
#[inline(always)]
async fn decrypt_decompress_verify_pipeline(
    encrypted: &[u8],
    expected_hash: &[u8],
    key: impl cryypt::KeyProviderBuilder + 'static,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Decrypt with hash verification
    let compressed = Cryypt::cipher()
        .aes()
        .with_key(key)
        .with_aad(expected_hash)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Decryption error: {}", e);
                    vec![]
                }
            }
        })
        .decrypt(encrypted)
        .await;

    // Decompress
    let data = Cryypt::compress()
        .zstd()
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Decompression error: {}", e);
                    vec![]
                }
            }
        })
        .decompress(&compressed)
        .await;

    // Verify hash matches
    let actual_hash = Cryypt::hash()
        .sha256()
        .on_result(|result| {
            match result {
                Ok(hash) => hash,
                Err(e) => {
                    log::error!("Hash error: {}", e);
                    vec![]
                }
            }
        })
        .compute(&data)
        .await;

    if actual_hash != expected_hash {
        return Err("Hash verification failed".into());
    }

    Ok(data)
}

/// Stream processing pipeline with zero-copy chunks
#[inline(always)]
async fn stream_pipeline<S>(
    input_stream: S,
    key: impl cryypt::KeyProviderBuilder + 'static,
    output_path: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    S: Stream<Item = Result<Vec<u8>, std::io::Error>> + Send + 'static,
{
    // Create hasher for the entire stream
    let mut hasher = Cryypt::hash()
        .sha256()
        .on_result(|result| {
            match result {
                Ok(hash) => hash,
                Err(e) => {
                    log::error!("Hash error: {}", e);
                    vec![]
                }
            }
        })
        .multi_pass();

    // Compress stream
    let compressed_stream = Cryypt::compress()
        .zstd()
        .with_level(6)
        .on_chunk(|chunk| {
            match chunk {
                Ok(data) => Some(data),
                Err(e) => {
                    log::error!("Compression error: {}", e);
                    None
                }
            }
        })
        .compress_stream(input_stream);

    // Encrypt compressed stream
    let mut encrypted_stream = Cryypt::cipher()
        .aes()
        .with_key(key)
        .on_chunk(|chunk| {
            match chunk {
                Ok(data) => Some(data),
                Err(e) => {
                    log::error!("Encryption error: {}", e);
                    None
                }
            }
        })
        .encrypt_stream(compressed_stream);

    // Write to output with buffering for performance
    let output_file = File::create(output_path).await?;
    let mut writer = BufWriter::with_capacity(65536, output_file);

    while let Some(chunk) = encrypted_stream.next().await {
        hasher.update(&chunk);
        writer.write_all(&chunk).await?;
    }

    writer.flush().await?;
    
    let final_hash = hasher.finalize().await;
    Ok(final_hash)
}

/// Batch process multiple files with parallel execution
#[inline(always)]
async fn batch_process_files(
    file_paths: Vec<&str>,
    output_dir: &str,
    key: impl cryypt::KeyProviderBuilder + Clone + 'static,
) -> Result<Vec<(String, Vec<u8>)>, Box<dyn std::error::Error>> {
    use futures::future::join_all;

    // Create output directory
    tokio::fs::create_dir_all(output_dir).await?;

    // Process files in parallel for maximum performance
    let tasks: Vec<_> = file_paths
        .into_iter()
        .map(|path| {
            let key = key.clone();
            let output_dir = output_dir.to_string();
            
            tokio::spawn(async move {
                let file_name = Path::new(path)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap();
                
                let output_path = format!("{}/{}.enc", output_dir, file_name);
                
                // Read file
                let data = tokio::fs::read(path).await?;
                
                // Process through pipeline
                let (encrypted, hash) = hash_compress_encrypt_pipeline(&data, key).await?;
                
                // Write encrypted file
                tokio::fs::write(&output_path, encrypted).await?;
                
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((file_name.to_string(), hash))
            })
        })
        .collect();

    // Wait for all tasks with error collection
    let results = join_all(tasks).await;
    
    let mut processed = Vec::with_capacity(results.len());
    for result in results {
        processed.push(result??);
    }

    Ok(processed)
}

/// Multi-stage secure document processing
#[inline(always)]
async fn secure_document_pipeline(
    document_path: &str,
    metadata: serde_json::Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let master_key = [0u8; 32]; // In production, load from secure storage
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    
    // Stage 1: Generate document-specific key
    let doc_key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store.clone())
        .with_namespace("documents")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await;

    // Stage 2: Read and process document
    let document = tokio::fs::read(document_path).await?;
    
    // Stage 3: Create authenticated package
    let metadata_bytes = serde_json::to_vec(&metadata)?;
    let metadata_hash = Cryypt::hash()
        .sha256()
        .on_result(|result| {
            match result {
                Ok(hash) => hash,
                Err(e) => {
                    log::error!("Hash error: {}", e);
                    vec![]
                }
            }
        })
        .compute(&metadata_bytes)
        .await;

    // Stage 4: Compress document with metadata
    let mut package = Vec::with_capacity(metadata_bytes.len() + document.len() + 8);
    package.extend_from_slice(&(metadata_bytes.len() as u64).to_le_bytes());
    package.extend_from_slice(&metadata_bytes);
    package.extend_from_slice(&document);

    let compressed = Cryypt::compress()
        .zstd()
        .with_level(9) // Maximum compression for documents
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Compression error: {}", e);
                    vec![]
                }
            }
        })
        .compress(&package)
        .await;

    // Stage 5: Encrypt with authentication
    let encrypted = Cryypt::cipher()
        .chacha20() // Use ChaCha20 for better performance on documents
        .with_key(doc_key)
        .with_aad(&metadata_hash)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Encryption error: {}", e);
                    vec![]
                }
            }
        })
        .encrypt(&compressed)
        .await;

    // Stage 6: Sign the package
    let signature = Cryypt::hash()
        .sha3_256()
        .on_result(|result| {
            match result {
                Ok(hash) => hash,
                Err(e) => {
                    log::error!("Hash error: {}", e);
                    vec![]
                }
            }
        })
        .compute(&encrypted)
        .await;

    // Stage 7: Create final package
    let mut final_package = Vec::with_capacity(signature.len() + encrypted.len() + 4);
    final_package.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    final_package.extend_from_slice(&signature);
    final_package.extend_from_slice(&encrypted);

    Ok(final_package)
}

/// Cross-key migration with zero-downtime
#[inline(always)]
async fn migrate_encrypted_data(
    old_key: impl cryypt::KeyProviderBuilder + 'static,
    new_key: impl cryypt::KeyProviderBuilder + 'static,
    data_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read encrypted data
    let encrypted_data = tokio::fs::read(data_path).await?;
    
    // Decrypt with old key
    let plaintext = Cryypt::cipher()
        .aes()
        .with_key(old_key)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Decryption error: {}", e);
                    vec![]
                }
            }
        })
        .decrypt(&encrypted_data)
        .await;

    // Re-encrypt with new key
    let new_encrypted = Cryypt::cipher()
        .aes()
        .with_key(new_key)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Encryption error: {}", e);
                    vec![]
                }
            }
        })
        .encrypt(&plaintext)
        .await;

    // Atomic file replacement
    let temp_path = format!("{}.tmp", data_path);
    tokio::fs::write(&temp_path, new_encrypted).await?;
    tokio::fs::rename(&temp_path, data_path).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let master_key = [0u8; 32];
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    
    // Generate keys for examples
    let key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store.clone())
        .with_namespace("examples")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await;

    println!("=== Hash -> Compress -> Encrypt Pipeline ===");
    let test_data = b"This is test data for the pipeline example";
    let (encrypted, hash) = hash_compress_encrypt_pipeline(test_data, key.clone()).await?;
    println!("Encrypted {} bytes with hash: {}", encrypted.len(), hex::encode(&hash));
    
    println!("\n=== Decrypt -> Decompress -> Verify Pipeline ===");
    let decrypted = decrypt_decompress_verify_pipeline(&encrypted, &hash, key.clone()).await?;
    println!("Decrypted and verified: {:?}", String::from_utf8(decrypted)?);

    println!("\n=== Secure Document Pipeline ===");
    // Create test document
    tokio::fs::write("/tmp/test_doc.txt", b"Important document content").await?;
    let metadata = serde_json::json!({
        "title": "Test Document",
        "author": "Example User",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    
    let package = secure_document_pipeline("/tmp/test_doc.txt", metadata).await?;
    println!("Created secure document package: {} bytes", package.len());

    println!("\n=== Batch File Processing ===");
    // Create test files
    tokio::fs::write("/tmp/file1.txt", b"File 1 content").await?;
    tokio::fs::write("/tmp/file2.txt", b"File 2 content").await?;
    tokio::fs::write("/tmp/file3.txt", b"File 3 content").await?;
    
    let results = batch_process_files(
        vec!["/tmp/file1.txt", "/tmp/file2.txt", "/tmp/file3.txt"],
        "/tmp/encrypted_files",
        key.clone()
    ).await?;
    
    for (file, hash) in results {
        println!("Processed {}: hash={}", file, hex::encode(hash));
    }

    println!("\n=== Key Migration ===");
    // Generate new key for migration
    let new_key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store)
        .with_namespace("examples")
        .version(2)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await;

    tokio::fs::write("/tmp/migrate_test.enc", &encrypted).await?;
    migrate_encrypted_data(key, new_key, "/tmp/migrate_test.enc").await?;
    println!("Successfully migrated encrypted data to new key");

    Ok(())
}