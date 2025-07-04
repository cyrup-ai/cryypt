# cryypt_hashing

Cryptographic hash functions (SHA-256, SHA3, BLAKE2b) for the Cryypt cryptography suite.

## Installation

```toml
[dependencies]
cryypt_hashing = "0.1"
```

## API Examples

### SHA-256 Hashing

```rust
use cryypt::{Cryypt, on_result};

// Simple hash
let hash = Cryypt::hash()
    .sha256()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Hash error: {}", e))
    })
    .compute(b"Hello, World!")
    .await; // Returns fully unwrapped value - no Result wrapper // Returns Vec<u8> - the actual hash bytes, fully unwrapped

// Hash entire file at once (Future)
let hash = Cryypt::hash()
    .sha256()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Hash error: {}", e))
    })
    .compute(&file_data)
    .await; // Returns fully unwrapped value - no Result wrapper // Returns Vec<u8> - the actual hash bytes, fully unwrapped

// Stream hashing
let mut hash_stream = Cryypt::hash()
    .sha256()
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => {
            log::error!("Hash chunk error: {}", e);
            return;
        }
    })
    .compute_stream(file_stream); // Returns Stream<Item = Vec<u8>> - fully unwrapped hash chunks

// Process the hash stream
while let Some(partial_hash) = hash_stream.next().await {
    // partial_hash is Vec<u8> - the hash bytes at this point in the stream
    println!("Hash update: {:?}", partial_hash);
}

// HMAC with key
let hmac = Cryypt::hash()
    .sha256()
    .with_key(b"secret_key")
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compute(b"Message")
    .await; // Returns fully unwrapped value - no Result wrapper

// Alternative: Direct builder is also available
use cryypt::Hash;
let hash = Hash::sha256()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compute(b"Direct builder example")
    .await; // Returns fully unwrapped value - no Result wrapper
```

### SHA3 and BLAKE2b

```rust
use cryypt::{Cryypt, on_result};

// SHA3-256
let hash = Cryypt::hash()
    .sha3_256()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compute(b"Hello, World!")
    .await; // Returns fully unwrapped value - no Result wrapper

// SHA3-512 with custom handling
let hash = Cryypt::hash()
    .sha3_512()
    .on_result!(|result| {
        result.map(|hash| {
            println!("Hash computed: {:?}", hash);
            hash
        }).unwrap_or_else(|e| panic!("Hash error: {}", e))
    })
    .compute(b"Hello, World!")
    .await; // Returns fully unwrapped value - no Result wrapper

// BLAKE2b with output size
let hash = Cryypt::hash()
    .blake2b()
    .with_output_size(32) // 32 bytes
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compute(b"Hello, World!")
    .await; // Returns fully unwrapped value - no Result wrapper
```

### Parallel Processing

```rust
use cryypt::{Cryypt, on_result};
use futures::future::try_join_all;

// Hash multiple files in parallel
let files = vec!["file1.txt", "file2.txt", "file3.txt"];
let hashes = try_join_all(
    files.into_iter().map(|file|  
        Cryypt::hash()
            .sha256()
            .on_result!(|result| {
                result.unwrap_or_else(|e| panic!("Hash error: {}", e))
            })
            .compute(tokio::fs::read(file).await?)
            .await
    })
).await;
```

### Streaming vs Future Pattern

```rust
use cryypt::{Hash, on_result};

// FUTURE PATTERN: Single operation returning Future<Output = Result<T>>
// on_result! handles Result<T> and returns Result<T>
let hash = Hash::sha256()
    .on_result!(|result| {
        Ok => Ok(result),    // Pass through success
        Err(e) => Err(e)     // Pass through or transform error
    })
    .compute(data)
    .await; // Returns fully unwrapped value - no Result wrapper  // Await the Future

// STREAMING PATTERN: Operations returning Stream<Item = T>
// on_chunk! unwraps each Result<chunk> to give you chunk directly
let mut hash_stream = Hash::sha256()
    .on_chunk!(|chunk| {
        Ok => chunk,         // Returns T (unwrapped chunk data)
        Err(e) => {
            log::error!("Chunk error: {}", e);
            return;          // Skip bad chunk
        }
    })
    .compute_stream(file_stream);  // Returns Stream, not Future

// Process unwrapped chunks from the Stream
while let Some(chunk) = hash_stream.next().await {
    // chunk is already unwrapped by on_chunk!
    process_chunk(&chunk);
}
```