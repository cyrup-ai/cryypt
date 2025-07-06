//! Cipher API examples - EXACTLY matching cipher/README.md

use cryypt::{Cryypt, FileKeyStore, Cipher, KeyRetriever, Bits, Key};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// AES-256-GCM Encryption example from README
async fn aes_encryption_example() -> Result<(), Box<dyn std::error::Error>> {
    // Retrieve key for encryption/decryption
    let master_key = [0u8; 32]; // Example master key
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = Key::size(256u32.bits())
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            match result {
                Ok(key) => key,
                Err(e) => {
                    log::error!("Key generation error: {}", e);
                    Vec::new()
                }
            }
        })
        .retrieve()
        .await; // Returns fully unwrapped value - no Result wrapper

    // Encrypt data
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    Vec::new()
                }
            }
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Decrypt data  
    let plaintext = Cryypt::cipher()
        .aes()
        .with_key(key)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    Vec::new()
                }
            }
        })
        .decrypt(&encrypted)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Decrypted: {:?}", String::from_utf8(plaintext)?);
    Ok(())
}

/// ChaCha20-Poly1305 Encryption example from README
async fn chacha_encryption_example() -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32];
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = Key::size(256u32.bits())
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            match result {
                Ok(key) => key,
                Err(e) => {
                    log::error!("Key generation error: {}", e);
                    Vec::new()
                }
            }
        })
        .retrieve()
        .await;

    // Encrypt with ChaCha20
    let encrypted = Cryypt::cipher()
        .chachapoly()
        .with_key(key)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    Vec::new()
                }
            }
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Decrypt with custom error handling
    let plaintext = Cryypt::cipher()
        .chachapoly()
        .with_key(key) 
        .on_result!(|result| {
            result.unwrap_or_else(|e| {
                log::error!("Decryption failed: {}", e);
                panic!("Decryption failed: {}", e)
            })
        })
        .decrypt(&encrypted)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Decrypted: {:?}", String::from_utf8(plaintext)?);
    Ok(())
}

/// Encrypt file to file example from README
async fn encrypt_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32];
    
    // Retrieve key
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = Key::size(256u32.bits())
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key retrieval error: {}", e))
        })
        .retrieve()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Read entire file
    let mut input_file = File::open(input_path).await?;
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext).await?;
    
    // Encrypt
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .encrypt(&plaintext)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Write encrypted file
    let mut output_file = File::create(output_path).await?;
    output_file.write_all(&encrypted).await?;
    
    Ok(())
}

/// Stream large file encryption example from README
async fn encrypt_large_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let master_key = [0u8; 32];
    
    // Retrieve key
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = Key::size(256u32.bits())
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key retrieval error: {}", e))
        })
        .retrieve()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Open files
    let input_file = File::open(input_path).await?;
    let mut output_file = File::create(output_path).await?;
    
    // Stream encryption
    let mut encrypted_stream = Cipher::aes()
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
        .encrypt_stream(input_file);
    
    // Process chunks
    while let Some(chunk) = encrypted_stream.next().await {
        output_file.write_all(&chunk).await?;
    }
    
    Ok(())
}

/// Pipeline Processing example from README
async fn pipeline_example() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"Large text data...";
    let master_key = [0u8; 32];
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = Key::size(256u32.bits())
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            match result {
                Ok(key) => key,
                Err(e) => {
                    log::error!("Key generation error: {}", e);
                    Vec::new()
                }
            }
        })
        .retrieve()
        .await;

    // Hash -> Compress -> Encrypt pipeline
    let hash = Cryypt::hash()
        .sha256()
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    Vec::new()
                }
            }
        })
        .compute(data)
        .await; // Returns fully unwrapped value - no Result wrapper

    let compressed = Cryypt::compress()
        .zstd()
        .with_level(3)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    Vec::new()
                }
            }
        })
        .compress(data)
        .await; // Returns fully unwrapped value - no Result wrapper

    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(key)
        .with_aad(&hash) // Use hash as additional authenticated data
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    Vec::new()
                }
            }
        })
        .encrypt(&compressed)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Pipeline complete: {} bytes encrypted", encrypted.len());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== AES Encryption Example ===");
    aes_encryption_example().await?;
    
    println!("\n=== ChaCha20 Encryption Example ===");
    chacha_encryption_example().await?;
    
    println!("\n=== Pipeline Example ===");
    pipeline_example().await?;
    
    Ok(())
}