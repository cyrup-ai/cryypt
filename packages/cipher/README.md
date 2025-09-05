# cryypt_cipher

Symmetric encryption algorithms (AES-GCM and ChaCha20-Poly1305) for the Cryypt cryptography suite.

## Installation

```toml
[dependencies]
cryypt_cipher = "0.1"
```

## API Examples

### AES-256-GCM Encryption

```rust
use cryypt::{Cryypt, FileKeyStore};

// Retrieve key for encryption/decryption
let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
let key = Cryypt::key()
    .retrieve()
    .with_store(store)
    .with_namespace("my-app")
    .version(1)
    .on_result(|result| {
        Ok(result) => result.into(),
        Err(e) => {
            log::error!("Key generation failed: {}", e);
            Vec::new()
        }
    }))
    .await; // Returns fully unwrapped value - no Result wrapper

// Encrypt data
let encrypted = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result(|result| {
        Ok(result) => result.into(),
        Err(e) => {
            log::error!("Cipher operation failed: {}", e);
            Vec::new()
        }
    }))
    .encrypt(b"Secret message")
    .await; // Returns fully unwrapped value - no Result wrapper

// Decrypt data  
let plaintext = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result(|result| {
        Ok(result) => result.into(),
        Err(e) => {
            log::error!("Cipher operation failed: {}", e);
            Vec::new()
        }
    }))
    .decrypt(&encrypted)
    .await; // Returns fully unwrapped value - no Result wrapper

// Stream encryption for large files
let mut encrypted_stream = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_chunk(|chunk| {
        Ok => chunk.into(),
        Err(e) => {
            log::error!("Encryption chunk error: {}", e);
            BadChunk::from_error(e)
        }
    }))
    .encrypt_stream(input_stream); // Returns Stream<Item = Vec<u8>> - fully unwrapped encrypted chunks

// Write encrypted chunks
while let Some(chunk) = encrypted_stream.next().await {
    // chunk is Vec<u8> - already unwrapped by on_chunk handler
    output_file.write_all(&chunk).await;
}

// Stream decryption (from encrypted file)
let mut decrypted_stream = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_chunk(|chunk| {
        Ok => chunk.into(),
        Err(e) => {
            log::error!("Decryption chunk error: {}", e);
            BadChunk::from_error(e)
        }
    }))
    .decrypt_stream(encrypted_file_stream);

// Write decrypted chunks
while let Some(chunk) = decrypted_stream.next().await {
    decrypted_file.write_all(&chunk).await;
}
```

### ChaCha20-Poly1305 Encryption

```rust
use cryypt::Cryypt;

// Encrypt with ChaCha20
let encrypted = Cryypt::cipher()
    .chacha20()
    .with_key(key)
    .on_result(|result| {
        Ok(result) => result.into(),
        Err(e) => {
            log::error!("Cipher operation failed: {}", e);
            Vec::new()
        }
    }))
    .encrypt(b"Secret message")
    .await; // Returns fully unwrapped value - no Result wrapper

// Decrypt with custom error handling
let plaintext = Cryypt::cipher()
    .chacha20()
    .with_key(key) 
    .on_result(|result| {
        Ok(result) => result.into(),
        Err(e) => {
            log::error!("Decryption failed: {}", e);
            Vec::new()
        }
    }))
    .decrypt(&encrypted)
    .await; // Returns fully unwrapped value - no Result wrapper
```

### High-Level File Operations

```rust
use cryypt::{Cipher, KeyRetriever, FileKeyStore, on_result, Bits};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Encrypt file to file
async fn encrypt_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Retrieve key
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Key retrieval failed: {}", e);
                Vec::new()
            }
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Read entire file
    let mut input_file = File::open(input_path).await;
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext).await;
    
    // Encrypt
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Encryption failed: {}", e);
                Vec::new()
            }
        })
        .encrypt(&plaintext)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Write encrypted file
    let mut output_file = File::create(output_path).await;
    output_file.write_all(&encrypted).await;
    
    Ok(())
}

// Stream large file encryption
async fn encrypt_large_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Retrieve key
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = KeyRetriever::new()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Key retrieval failed: {}", e);
                Vec::new()
            }
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Open files
    let input_file = File::open(input_path).await;
    let mut output_file = File::create(output_path).await;
    
    // Stream encryption
    let mut encrypted_stream = Cipher::aes()
        .with_key(key)
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("Encryption error: {}", e);
                return
            }
        })
        .encrypt_stream(input_file);
    
    // Process chunks
    while let Some(chunk) = encrypted_stream.next().await {
        output_file.write_all(&chunk).await;
    }
    
    Ok(())
}
```

### Pipeline Processing

```rust
use cryypt::{Cryypt, on_result};

// Hash -> Compress -> Encrypt pipeline
let hash = Cryypt::hash()
    .sha256()
    .on_result(|result| {
        Ok(result) => result.into(),
        Err(e) => {
            log::error!("Cipher operation failed: {}", e);
            Vec::new()
        }
    }))
    .compute(data)
    .await; // Returns fully unwrapped value - no Result wrapper

let compressed = Cryypt::compress()
    .zstd()
    .with_level(3)
    .on_result(|result| {
        Ok(result) => result.into(),
        Err(e) => {
            log::error!("Cipher operation failed: {}", e);
            Vec::new()
        }
    }))
    .compress(data)
    .await; // Returns fully unwrapped value - no Result wrapper

let encrypted = Cryypt::cipher()
    .aes()
    .with_key(key)
    .with_aad(&hash) // Use hash as additional authenticated data
    .on_result(|result| {
        Ok(result) => result.into(),
        Err(e) => {
            log::error!("Cipher operation failed: {}", e);
            Vec::new()
        }
    }))
    .encrypt(&compressed)
    .await; // Returns fully unwrapped value - no Result wrapper
```
