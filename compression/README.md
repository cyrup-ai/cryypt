# cryypt_compression

Data compression algorithms (Zstandard, Gzip, Bzip2, ZIP) for the Cryypt cryptography suite.

## Installation

```toml
[dependencies]
cryypt_compression = "0.1"
```

## API Examples

### Zstandard (Recommended)

```rust
use cryypt::{Cryypt, on_result};

// Compress data
let compressed = Cryypt::compress()
    .zstd()
    .with_level(3)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Compression error: {}", e))
    })
    .compress(b"Large text data...")
    .await; // Returns fully unwrapped value - no Result wrapper // Returns Vec<u8> - the compressed bytes, fully unwrapped

// Decompress
let decompressed = Cryypt::compress()
    .zstd()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Decompression error: {}", e))
    })
    .decompress(&compressed)
    .await; // Returns fully unwrapped value - no Result wrapper // Returns Vec<u8> - the decompressed bytes, fully unwrapped

// Stream compression
let mut compressed_stream = Cryypt::compress()
    .zstd()
    .with_level(6)
    .on_chunk!(|chunk| {
        Ok => chunk,  // Unwrapped compressed bytes
        Err(e) => {
            log::error!("Compression error: {}", e);
            return;
        }
    })
    .compress_stream(input_stream); // Returns Stream<Item = Vec<u8>> - fully unwrapped compressed chunks

// Process compressed chunks
while let Some(chunk) = compressed_stream.next().await {
    // chunk is Vec<u8> - compressed bytes ready to write
    output_file.write_all(&chunk).await;
}

// Stream decompression
let mut decompressed_stream = Cryypt::compress()
    .zstd()
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => {
            log::error!("Decompression error: {}", e);
            return;
        }
    })
    .decompress_stream(compressed_input);
```

### Other Compression Formats

```rust
use cryypt::{Cryypt, on_result};

// Gzip
let compressed = Cryypt::compress()
    .gzip()
    .with_level(6)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Compression error: {}", e))
    })
    .compress(data)
    .await; // Returns fully unwrapped value - no Result wrapper

// Bzip2
let compressed = Cryypt::compress()
    .bzip2()
    .with_level(9)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compress(data)
    .await; // Returns fully unwrapped value - no Result wrapper

// ZIP archive
let archive = Cryypt::compress()
    .zip()
    .add_file("readme.txt", readme_data)
    .add_file("data.json", json_data)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compress()
    .await; // Returns Vec<u8> - the ZIP archive bytes, fully unwrapped

// Alternative: Direct builders work too
use cryypt::Compress;
let compressed = Compress::zstd()
    .with_level(3)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compress(data)
    .await; // Returns fully unwrapped value - no Result wrapper
```

### Batch Compress and Encrypt Files

```rust
async fn compress_and_encrypt_files(
    files: Vec<&str>,
    output_archive: &str
) -> Result<(), Box<dyn std::error::Error>> {
    use cryypt::{Compress, on_result};
    
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
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Create ZIP archive
    let mut archive = Compress::zip();
    
    // Add all files
    for file_path in files {
        let content = tokio::fs::read(file_path).await;
        let file_name = Path::new(file_path).file_name().unwrap().to_str().unwrap();
        archive = archive.add_file(file_name, content);
    }
    
    // Compress
    let compressed = archive
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .compress()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Encrypt the archive
    let encrypted = Cipher::aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .encrypt(&compressed)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Write encrypted archive
    tokio::fs::write(output_archive, encrypted).await;
    
    Ok(())
}
```