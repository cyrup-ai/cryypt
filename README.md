# `cryypt`

Immutable builders for encryption, hashing, compression.

## Installation

```toml
[dependencies]
# Core features
cryypt = { version = "0.1", features = ["aes", "sha256", "zstd", "key", "file-store"] }

# Or use feature groups
cryypt = { version = "0.1", features = ["encryption", "hashing", "compression"] }
```

## API Design

Cryypt offers two equivalent APIs:

1. **Master Builder**: `Cryypt::cipher()`, `Cryypt::hash()`, `Cryypt::compress()`
2. **Direct Builders**: `Cipher::aes()`, `Hash::sha256()`, `Compress::zstd()`

Both are fully supported - use whichever feels more natural for your use case.

## Key API Examples

### Key Generation and Retrieval

```rust
use cryypt::{Cryypt, FileKeyStore, on_result, Bits};

// Generate a NEW key (one-time setup)
let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
let key = Cryypt::key()
    .generate()
    .size(256.bits())
    .with_store(store.clone())
    .with_namespace("my-app")
    .version(1)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
    })
    .await; // Returns Key - the actual key object, fully unwrapped

// Retrieve EXISTING key (normal usage)
let key = Cryypt::key()
    .retrieve()
    .with_store(store)
    .with_namespace("my-app")
    .version(1)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
    })
    .await; // Returns fully unwrapped value - no Result wrapper

// Use key directly for encryption
let encrypted = key
    .aes()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt(b"Secret message")
    .await; // Returns Vec<u8> - the encrypted bytes, fully unwrapped

// Use key directly for decryption
let plaintext = key
    .aes()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .decrypt(&encrypted)
    .await; // Returns Vec<u8> - the decrypted plaintext bytes, fully unwrapped

// Or use ChaCha20
let encrypted = key
    .chacha20()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt(b"Secret message")
    .await; // Returns fully unwrapped value - no Result wrapper

// Alternative: Direct builders are also available
use cryypt::{KeyGenerator, KeyRetriever};
let key = KeyRetriever::new()
    .with_store(store)
    .with_namespace("my-app")
    .version(1)
    .retrieve(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .await; // Returns fully unwrapped value - no Result wrapper
```

## Cipher API Examples

### AES-256-GCM Encryption

```rust
use cryypt::{Cryypt, FileKeyStore, on_result};

// Retrieve key for encryption/decryption
let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
let key = Cryypt::key()
    .retrieve()
    .with_store(store)
    .with_namespace("my-app")
    .version(1)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
    })
    .await; // Returns fully unwrapped value - no Result wrapper

// Encrypt data
let encrypted = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt(b"Secret message")
    .await; // Returns fully unwrapped value - no Result wrapper

// Decrypt data  
let plaintext = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .decrypt(&encrypted)
    .await; // Returns fully unwrapped value - no Result wrapper

// Stream encryption for large files
let mut encrypted_stream = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_chunk!(|chunk| {
        Ok => chunk,  // Unwrapped encrypted bytes
        Err(e) => {
            log::error!("Encryption chunk error: {}", e);
            return;
        }
    })
    .encrypt_stream(input_stream); // Returns Stream<Item = Vec<u8>> - fully unwrapped encrypted chunks

// Write encrypted chunks
while let Some(chunk) = encrypted_stream.next().await {
    // chunk is Vec<u8> - already unwrapped by on_chunk!
    output_file.write_all(&chunk).await;
}

// Stream decryption (from encrypted file)
let mut decrypted_stream = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => {
            log::error!("Decryption chunk error: {}", e);
            return;
        }
    })
    .decrypt_stream(encrypted_file_stream);

// Write decrypted chunks
while let Some(chunk) = decrypted_stream.next().await {
    decrypted_file.write_all(&chunk).await;
}
```

### ChaCha20-Poly1305 Encryption

```rust
use cryypt::{Cryypt, on_result};

// Encrypt with ChaCha20
let encrypted = Cryypt::cipher()
    .chacha20()
    .with_key(key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt(b"Secret message")
    .await; // Returns fully unwrapped value - no Result wrapper

// Decrypt with custom error handling
let plaintext = Cryypt::cipher()
    .chacha20()
    .with_key(key) 
    .on_result!(|result| {
        result.unwrap_or_else(|e| {
            log::error!("Decryption failed: {}", e);
            panic!("Decryption failed: {}", e)
        })
    })
    .decrypt(&encrypted)
    .await; // Returns fully unwrapped value - no Result wrapper
```

## Hashing API Examples

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

## Compression API Examples

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

## Combined Operations

```rust
use cryypt::{Cryypt, on_result};

// Compress, encrypt, and hash
let compressed = Cryypt::compress()
    .zstd()
    .with_level(3)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compress(large_data)
    .await; // Returns fully unwrapped value - no Result wrapper

let encrypted = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt(&compressed)
    .await; // Returns fully unwrapped value - no Result wrapper

let hash = Cryypt::hash()
    .sha256()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compute(&encrypted)
    .await; // Returns fully unwrapped value - no Result wrapper
```

## Advanced Error Handling

```rust
use cryypt::{KeyGenerator, on_result};

// Retry on specific errors
let key = KeyGenerator::new()
    .size(256.bits())
    .with_store(store)
    .with_namespace("my-app")
    .version(1)
    .generate(|result| {
        Ok => Ok(result),
        Err(e) => {
            if e.is_transient() {
                retry_with_backoff()
            } else {
                Err(e)
            }
        }
    })
    .await; // Returns fully unwrapped value - no Result wrapper

// Custom error conversion
let key = KeyGenerator::new()
    .size(256.bits())
    .with_store(store)
    .with_namespace("my-app")
    .version(1)
    .generate(|result| {
        Ok => Ok(result),
        Err(e) => {
            metrics.record_error(&e);
            Err(MyError::from(e))
        }
    })
    .await; // Returns fully unwrapped value - no Result wrapper
```

## Streaming Operations

```rust
use cryypt::{Cipher, Hash, on_result};

// Stream encryption
let mut encrypted_stream = Cipher::aes()
    .with_key(key)
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => {
            log::error!("Encryption error: {}", e);
            return;
        }
    })
    .encrypt_stream(input_stream);

// Process stream chunk by chunk
while let Some(encrypted_bytes) = encrypted_stream.next().await {
    // encrypted_bytes is Vec<u8>, not Result<Vec<u8>> - already unwrapped by on_chunk!
    output_file.write_all(&encrypted_bytes).await;
}
```

## JWT API Examples

```rust
use cryypt::{Cryypt, on_result};

// Create and sign JWT
let claims = Claims {
    sub: "user123".to_string(),
    exp: 3600,
    custom: json!({"role": "admin"}),
};

let token = Cryypt::jwt()
    .with_algorithm("HS256")
    .with_secret(b"secret_key")
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .sign(claims)
    .await; // Returns fully unwrapped value - no Result wrapper

// Verify and decode JWT
let claims = Cryypt::jwt()
    .with_secret(b"secret_key")
    .on_result!(|result| {
        Ok => Ok(result),
        Err(e) => {
            log::error!("JWT verification failed: {}", e);
            Err(e)
        }
    })
    .verify(token)
    .await; // Returns fully unwrapped value - no Result wrapper

// RS256 with key pair
let token = Cryypt::jwt()
    .with_algorithm("RS256")
    .with_private_key(private_key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .sign(claims)
    .await; // Returns fully unwrapped value - no Result wrapper
```

## Post-Quantum Cryptography Examples

```rust
use cryypt::{Cryypt, on_result};

// Kyber key exchange
let (public_key, secret_key) = Cryypt::pqcrypto()
    .kyber()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .generate_keypair()
    .await; // Returns fully unwrapped value - no Result wrapper

// Encapsulate shared secret
let (ciphertext, shared_secret) = Cryypt::pqcrypto()
    .kyber()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encapsulate(public_key)
    .await; // Returns fully unwrapped value - no Result wrapper

// Decapsulate shared secret
let shared_secret = Cryypt::pqcrypto()
    .kyber()
    .with_secret_key(secret_key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .decapsulate(ciphertext)
    .await; // Returns fully unwrapped value - no Result wrapper

// Dilithium signatures
let (public_key, secret_key) = Cryypt::pqcrypto()
    .dilithium()
    .with_security_level(3)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .generate_keypair()
    .await; // Returns fully unwrapped value - no Result wrapper

let signature = Cryypt::pqcrypto()
    .dilithium()
    .with_secret_key(secret_key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .sign(message)
    .await; // Returns fully unwrapped value - no Result wrapper

let valid = Cryypt::pqcrypto()
    .dilithium()
    .with_public_key(public_key)
    .with_signature(signature)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .verify(message)
    .await; // Returns fully unwrapped value - no Result wrapper
```

## Vault API Examples

```rust
use cryypt::{Cryypt, on_result};

// Create and unlock vault
let vault = Cryypt::vault()
    .create("./my-vault")
    .with_passphrase("strong_passphrase")
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
    })
    .await; // Returns fully unwrapped value - no Result wrapper

// Store secret
vault
    .with_key("api_key")
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .set(VaultValue::Secret("sk-1234567890"))
    .await; // Returns fully unwrapped value - no Result wrapper

// Store with TTL
vault
    .with_key("temp_token")
    .with_ttl(3600)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .set(VaultValue::Secret("tmp-abc123"))
    .await; // Returns fully unwrapped value - no Result wrapper

// Retrieve secret
let api_key = vault
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .get("api_key")
    .await; // Returns fully unwrapped value - no Result wrapper

// Stream all secrets
let mut secret_stream = vault
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => {
            log::error!("Vault stream error: {}", e);
            return;
        }
    })
    .find(".*");

// Collect all secrets
let mut secrets = Vec::new();
while let Some(secret) = secret_stream.next().await {
    secrets.push(secret);
}

// Batch operations  
vault
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .put_all({
        "db_host" => "localhost",
        "db_port" => 5432,
        "db_ssl" => true,
        "db_user" => "admin",
        "api_key" => "sk-1234567890",
    })
    .await; // Returns fully unwrapped value - no Result wrapper

// Lock vault
vault
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .lock()
    .await; // Returns fully unwrapped value - no Result wrapper
```

## QUIC Transport Examples

```rust
use cryypt::{Cryypt, on_result};

// QUIC server
let server = Cryypt::quic()
    .server()
    .with_cert(cert)
    .with_key(private_key)
    .on_connection!(|conn| {
        Ok => {
            tokio::spawn(handle_connection(conn));
            Ok(())
        },
        Err(e) => Err(e)
    })
    .bind("127.0.0.1:4433")
    .await; // Returns fully unwrapped value - no Result wrapper

// QUIC client
let client = Cryypt::quic()
    .client()
    .with_server_name("example.com")
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .connect("127.0.0.1:4433")
    .await; // Returns fully unwrapped value - no Result wrapper

// Open bidirectional stream
let (send, recv) = client
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .open_bi()
    .await; // Returns fully unwrapped value - no Result wrapper

// Send data
send
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .write_all(b"Hello QUIC")
    .await; // Returns fully unwrapped value - no Result wrapper

// Receive streamed data
let mut data = Vec::new();
let mut recv_stream = recv
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => {
            log::error!("Receive error: {}", e);
            return;
        }
    })
    .stream();

while let Some(chunk) = recv_stream.next().await {
    data.extend_from_slice(&chunk);
}
```

## Advanced Patterns

### Custom Error Recovery

```rust
use cryypt::{Cryypt, on_result};

// Retry with exponential backoff
let encrypted = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result!(|result| {
        Ok => Ok(result),
        Err(e) => {
            if e.is_transient() {
                // Handle transient error
                retry_operation()
            } else {
                Err(e)
            }
        }
    })
    .encrypt(data)
    .await; // Returns fully unwrapped value - no Result wrapper
```

### Pipeline Processing

```rust
use cryypt::{Cryypt, on_result};

// Hash -> Compress -> Encrypt pipeline
let hash = Cryypt::hash()
    .sha256()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compute(data)
    .await; // Returns fully unwrapped value - no Result wrapper

let compressed = Cryypt::compress()
    .zstd()
    .with_level(3)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .compress(data)
    .await; // Returns fully unwrapped value - no Result wrapper

let encrypted = Cryypt::cipher()
    .aes()
    .with_key(key)
    .with_aad(&hash) // Use hash as additional authenticated data
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt(&compressed)
    .await; // Returns fully unwrapped value - no Result wrapper
```

### Parallel Processing

```rust
use cryypt::{Cryypt, on_result};
use futures::future::try_join_all;

// Hash multiple files in parallel
let files = vec!["file1.txt", "file2.txt", "file3.txt"];
let hashes = try_join_all(
    files.into_iter().map(|file| async move {
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

### Key Rotation

```rust
use cryypt::{Cryypt, on_result, Bits};

// Generate new key version
let new_key = Cryypt::key()
    .generate()
    .size(256.bits())
    .with_store(store)
    .with_namespace("my-app")
    .version(2) // New version
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
    })
    .await; // Returns fully unwrapped value - no Result wrapper

// Re-encrypt data with new key
let old_key = Cryypt::key()
    .retrieve()
    .with_store(store)
    .with_namespace("my-app")
    .version(1) // Old version
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
    })
    .await; // Returns fully unwrapped value - no Result wrapper

// Decrypt with old key
let plaintext = Cryypt::cipher()
    .aes()
    .with_key(old_key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .decrypt(ciphertext)
    .await; // Returns fully unwrapped value - no Result wrapper

// Re-encrypt with new key
let new_ciphertext = Cryypt::cipher()
    .aes()
    .with_key(new_key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt(plaintext)
    .await; // Returns fully unwrapped value - no Result wrapper
```

### Secure Multi-party Communication

```rust
use cryypt::{Cryypt, on_result};

// Alice generates keypair
let (alice_public, alice_secret) = Cryypt::pqcrypto()
    .kyber()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .generate_keypair()
    .await; // Returns fully unwrapped value - no Result wrapper

// Bob encapsulates shared secret
let (ciphertext, bob_shared_secret) = Cryypt::pqcrypto()
    .kyber()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encapsulate(alice_public)
    .await; // Returns fully unwrapped value - no Result wrapper

// Alice decapsulates to get same shared secret
let alice_shared_secret = Cryypt::pqcrypto()
    .kyber()
    .with_secret_key(alice_secret)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .decapsulate(ciphertext)
    .await; // Returns fully unwrapped value - no Result wrapper

// Now both can use shared secret for symmetric encryption
let encrypted = Cryypt::cipher()
    .aes()
    .with_key(bob_shared_secret)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt(b"Secret message")
    .await; // Returns fully unwrapped value - no Result wrapper
```

## Streaming vs Future Pattern Summary

```rust
use cryypt::{Hash, Cipher, Compress, on_result};

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

// Complete streaming pipeline example
let mut pipeline = file_stream
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => {
            metrics.record_error();
            return;
        }
    });

let compressed = Compress::zstd()
    .with_level(3)
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => return
    })
    .compress_stream(pipeline);

let encrypted = Cipher::aes()
    .with_key(key)
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => return
    })
    .encrypt_stream(compressed);

let hash = Hash::sha256()
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => return
    })
    .compute_stream(encrypted);

// All chunks are unwrapped at each stage
```

## High-Level File Operations

```rust
use cryypt::{Cryypt, KeyRetriever, FileKeyStore, on_result};

// Retrieve key for file operations
let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
let key = KeyRetriever::new()
    .with_store(store)
    .with_namespace("my-app")
    .version(1)
    .retrieve(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .await; // Returns fully unwrapped value - no Result wrapper

// Encrypt file with default zstd compression (saves as document.pdf.zst)
Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt_file("document.pdf")
    .await; // Returns fully unwrapped value - no Result wrapper

// Decrypt file (saves as document.pdf)
Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .decrypt_file("document.pdf.zst")
    .await; // Returns fully unwrapped value - no Result wrapper

// Encrypt with specific compression (saves as data.csv.gz)
Cryypt::cipher()
    .aes()
    .with_key(key)
    .with_compression(Cryypt::compress().gzip().with_level(6))
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt_file("data.csv")
    .await; // Returns fully unwrapped value - no Result wrapper

// Encrypt with base64 encoding (saves as message.txt.b64)
Cryypt::cipher()
    .chacha20()
    .with_key(key)
    .with_encoding("base64")
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt_file("message.txt")
    .await; // Returns fully unwrapped value - no Result wrapper

// Custom output path
Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt_file("report.doc")
    .save("secure/report-backup.zst")
    .await; // Returns fully unwrapped value - no Result wrapper

// Stream large files
Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_chunk!(|chunk| {
        Ok => chunk,
        Err(e) => {
            log::error!("Encryption error: {}", e);
            return;
        }
    })
    .encrypt_file_stream("movie.mp4")
    .await; // Returns fully unwrapped value - no Result wrapper
```

## High-Level File Operations

### Single File Encryption/Decryption

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
        .retrieve(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Read entire file
    let mut input_file = File::open(input_path).await;
    let mut plaintext = Vec::new();
    input_file.read_to_end(&mut plaintext).await;
    
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
    let mut output_file = File::create(output_path).await;
    output_file.write_all(&encrypted).await;
    
    Ok(())
}

// Decrypt file to file
async fn decrypt_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
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
    
    // Read encrypted file
    let mut input_file = File::open(input_path).await;
    let mut ciphertext = Vec::new();
    input_file.read_to_end(&mut ciphertext).await;
    
    // Decrypt
    let plaintext = Cipher::aes()
        .with_key(key)
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .decrypt(&ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Write decrypted file
    let mut output_file = File::create(output_path).await;
    output_file.write_all(&plaintext).await;
    
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
        .retrieve(|result| {
            Ok => Ok(result),
            Err(e) => Err(e)
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    // Open files
    let input_file = File::open(input_path).await;
    let mut output_file = File::create(output_path).await;
    
    // Stream encryption
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
    
    // Process chunks
    while let Some(chunk) = encrypted_stream.next().await {
        output_file.write_all(&chunk).await;
    }
    
    Ok(())
}
```

### Multiple Files Processing

```rust
use cryypt::{Cipher, KeyRetriever, FileKeyStore, on_result};
use futures::future::try_join_all;
use std::path::Path;

// Encrypt multiple files in parallel
async fn encrypt_files(input_dir: &str, output_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Retrieve key once
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
    
    // Get all files
    let mut entries = tokio::fs::read_dir(input_dir).await;
    let mut tasks = Vec::new();
    
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            let input_path = path.clone();
            let output_path = Path::new(output_dir)
                .join(format!("{}.enc", path.file_name().unwrap().to_str().unwrap()));
            let key = key.clone();
            
            // Spawn encryption task
            tasks.push(tokio::spawn(async move {
                encrypt_file_with_key(input_path, output_path, key).await
            }));
        }
    }
    
    // Wait for all encryptions to complete
    try_join_all(tasks).await;
    Ok(())
}

// Helper function
async fn encrypt_file_with_key(
    input_path: std::path::PathBuf,
    output_path: std::path::PathBuf,
    key: Key
) -> Result<(), Box<dyn std::error::Error>> {
    // Read file
    let plaintext = tokio::fs::read(&input_path).await;
    
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
    tokio::fs::write(&output_path, encrypted).await;
    
    println!("Encrypted: {} -> {}", input_path.display(), output_path.display());
    Ok(())
}

// Batch compress and encrypt files
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
