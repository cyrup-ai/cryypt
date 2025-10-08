# CRYYPT

This document provides comprehensive API documentation for the `cryypt` library, a Rust cryptography library with immutable builders for encryption, hashing, and compression.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Core Concepts](#core-concepts)
3. [Cipher API](#cipher-api)
4. [Key Management API](#key-management-api)
5. [Hashing API](#hashing-api)
6. [Compression API](#compression-api)
7. [Encoding & File Operations](#encoding--file-operations)
8. [Error Handling](#error-handling)
9. [Async Patterns](#async-patterns)

## Quick Start

### Generate a MasterKey

```rust
    let master_key_hex = MasterKey::size(256.bits())
        .with_store(KeychainStore::for_app("MyApp"))
        .with_namespace("master")
        .version(1)
        .generate()?;
```

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load master key from hex (after initial setup)
    let master_key = MasterKey::from_hex("your-master-key-hex")?;

    // Use it for your encryption keys
    let key = Key::size(256.bits())
        .with_store(FileKeyStore::at("/keys").with_master_key(master_key))
        .with_namespace("data")
        .version(1);

    // Encrypt
    let ciphertext = Cipher::aes()
        .with_key(key.clone())
        .with_text("Hello, World!")
        .encrypt()
        .await?;

    println!("Encrypted: {}", ciphertext.to_base64());

    // Decrypt
    let plaintext = Cipher::aes()
        .with_key(key)
        .with_ciphertext(ciphertext.to_bytes())
        .decrypt()
        .await?;

    println!("Decrypted: {}", plaintext.to_string()?);
    Ok(())
}
```

## Core Concepts

### Immutable Builders

The library uses immutable builder patterns where each method returns a new instance:

```rust
let cipher = Cipher::aes()           // Returns AesBuilder
    .with_key(key_builder)           // Returns AesWithKey
    .with_data(b"data");             // Returns AesWithKeyAndData
```

### Type Safety

Builders use compile-time type checking to ensure required parameters:

```rust
// ✅ This compiles - all required parameters provided
Cipher::aes().with_key(key).with_data(data).encrypt().await?;

// ❌ This won't compile - missing data
Cipher::aes().with_key(key).encrypt().await?;
```

### Async by Default

All operations return `impl Future` for zero-allocation async:

```rust
// No boxing or heap allocation
let result = cipher.encrypt().await?;
```

## Cipher API

### AES-GCM Encryption

```rust
use cryypt::prelude::*;

// Basic encryption
let ciphertext = Cipher::aes()
    .with_key(key_builder)
    .with_data(b"sensitive data")
    .encrypt()
    .await?;

// Decryption
let plaintext = Cipher::aes()
    .with_key(key_builder)
    .with_ciphertext(ciphertext.to_bytes())
    .decrypt()
    .await?;
```

### ChaCha20-Poly1305 Encryption

```rust
// ChaCha20-Poly1305 encryption
let ciphertext = Cipher::chachapoly()
    .with_key(key_builder)
    .with_text("Hello, ChaCha!")
    .encrypt()
    .await?;
```

### Data Input Methods

```rust
let cipher = Cipher::aes().with_key(key_builder);

// Binary data
cipher.with_data(b"binary data").encrypt().await?;

// Text input (UTF-8)
cipher.with_text("Hello, World!").encrypt().await?;

// From file
cipher.with_file("input.txt").await?.encrypt().await?;

// From base64
cipher.with_data_base64("SGVsbG8gV29ybGQ=")?.encrypt().await?;

// From hex
cipher.with_data_hex("48656c6c6f20576f726c64")?.encrypt().await?;
```

### Ciphertext Input Methods

```rust
let cipher = Cipher::aes().with_key(key_builder);

// Raw bytes
cipher.with_ciphertext(ciphertext_bytes).decrypt().await?;

// From base64
cipher.with_ciphertext_base64("base64_ciphertext")?.decrypt().await?;

// From hex
cipher.with_ciphertext_hex("hex_ciphertext")?.decrypt().await?;

// From file
cipher.with_ciphertext_file("encrypted.bin").await?.decrypt().await?;
```

### Two-Pass Encryption

```rust
// Encrypt with AES, then ChaCha
let ciphertext = Cipher::aes()
    .with_key(first_key)
    .with_data(b"sensitive data")
    .second_pass(
        Cipher::chachapoly().with_key(second_key)
    )
    .encrypt()
    .await?;

// Decrypt in reverse order (ChaCha first, then AES)
let plaintext = Cipher::chachapoly()
    .with_key(second_key)
    .with_ciphertext(ciphertext.to_bytes())
    .second_pass(
        Cipher::aes().with_key(first_key)
    )
    .decrypt()
    .await?;
```

## Key Management API

### Key Builders - Secure by Default

```rust
// THIS IS HOW YOU GENERATE KEYS - Let our builder handle it!
// Key::size() uses rand::rng() internally for cryptographically secure generation
let key = Key::size(256.bits())  // ← Generates NEW secure key automatically
    .with_store(store)
    .with_namespace("app-name")
    .version(1);

// The key is:
// - Generated using rand::rng().fill_bytes()
// - Stored encrypted with your master key
// - Retrieved by namespace + version
// - Automatically rotated when you increment version

// Only use from_bytes() for importing existing keys
let imported_key = Key::from_bytes(key_from_hsm); // Import from HSM/KMS
```

### File-Based Key Store

```rust
// For user applications: derive from user's passphrase
let store = FileKeyStore::at("/secure/keys")
    .with_master_key(MasterKeyBuilder::from_passphrase("user-passphrase"));

// For servers: retrieve from secure key management service
let master_key = your_kms_client.get_secret("master-key").await?;
let store = FileKeyStore::at("/secure/keys")
    .with_master_key(MasterKeyBuilder::from_hex(&master_key)?);

// Keys are automatically generated using secure RNG and encrypted on disk
let key = Key::size(256.bits())
    .with_store(store)
    .with_namespace("production")
    .version(1);
```

### OS Keychain Store

```rust
// Uses OS keychain (macOS Keychain, Windows Credential Store, Linux Secret Service)
let store = KeychainStore::for_app("MyApp");

let key = Key::size(256.bits())
    .with_store(store)
    .with_namespace("user-keys")
    .version(1);
```

### Key Versioning and Namespaces

```rust
// Different namespaces for different purposes
let user_key = Key::size(256.bits())
    .with_store(store)
    .with_namespace("user-data")
    .version(1);

let admin_key = Key::size(256.bits())
    .with_store(store)
    .with_namespace("admin-data")
    .version(1);

// Version upgrades
let old_key = Key::size(256.bits())
    .with_store(store)
    .with_namespace("app")
    .version(1);

let new_key = Key::size(256.bits())
    .with_store(store)
    .with_namespace("app")
    .version(2);  // New version generates different key
```

## Hashing API

### SHA-256 Hashing

```rust
use cryypt::hashing::Hash;

// Basic hash
let hash = Hash::sha256()
    .with_data(b"Hello, World!")
    .hash()
    .await?;

// With salt
let hash = Hash::sha256()
    .with_text("password")
    .with_salt(b"random_salt")
    .hash()
    .await?;

// Key stretching with multiple passes
let hash = Hash::sha256()
    .with_text("password")
    .with_salt(b"salt")
    .with_passes(10_000)
    .hash()
    .await?;
```

### SHA-3 Hashing

```rust
// SHA3-256 (default)
let hash = Hash::sha3()
    .with_data(b"data")
    .hash()
    .await?;

// With salt and passes
let hash = Hash::sha3()
    .with_text("password")
    .with_salt(b"salt")
    .with_passes(1_000)
    .hash()
    .await?;
```

### Blake2b Hashing

```rust
// Blake2b (64-byte output)
let hash = Hash::blake2b()
    .with_data(b"data")
    .hash()
    .await?;

// Blake2b with salt (acts as key for MAC)
let hash = Hash::blake2b()
    .with_text("message")
    .with_salt(b"secret_key")
    .hash()
    .await?;
```

## Compression API

### Zstd Compression (Recommended)

```rust
use cryypt::compression::Compress;

// Standalone compression
let compressed = Compress::zstd()
    .with_data(b"Large text that compresses well...")
    .compress()
    .await?;

// Decompress
let original = Compress::zstd()
    .with_data(compressed)
    .decompress()
    .await?;
```

### Compression with Encryption

```rust
// Compress then encrypt
let result = Cipher::aes()
    .with_key(key_builder)
    .with_compression(Compress::zstd())
    .with_data(b"Large sensitive data...")
    .encrypt()
    .await?;

// Decrypt then decompress (automatic)
let original = Cipher::aes()
    .with_key(key_builder)
    .with_compression(Compress::zstd())
    .with_ciphertext(result.to_bytes())
    .decrypt()
    .await?;
```

### Other Compression Algorithms

```rust
// Bzip2 with compression level
let compressed = Compress::bzip2()
    .with_data(b"data")
    .balanced_compression()  // Level 6
    .compress()
    .await?;

// Gzip compression
let compressed = Compress::gzip()
    .with_data(b"data")
    .compress()
    .await?;
```

## Encoding & File Operations

### Output Encoding

```rust
let encrypted_result = Cipher::aes()
    .with_key(key_builder)
    .with_text("Hello, World!")
    .encrypt()
    .await?;

// Get as base64
let base64 = encrypted_result.to_base64();

// Get as hex
let hex = encrypted_result.to_hex();

// Get raw bytes
let bytes = encrypted_result.to_bytes();

// Save to file
encrypted_result.to_file("output.enc").await?;

// Convert to UTF-8 string (for text data)
let text = encrypted_result.to_string()?;
```

### File Operations

```rust
// Encrypt file contents
Cipher::aes()
    .with_key(key_builder)
    .with_file("secret.txt")
    .await?
    .encrypt()
    .await?
    .to_file("secret.enc")
    .await?;

// Decrypt from file
let plaintext = Cipher::aes()
    .with_key(key_builder)
    .with_ciphertext_file("secret.enc")
    .await?
    .decrypt()
    .await?;
```

### Encoded Input Sources

```rust
// Encrypt data from base64 input
let ciphertext = Cipher::aes()
    .with_key(key_builder)
    .with_data_base64("SGVsbG8gV29ybGQ=")?  // "Hello World"
    .encrypt()
    .await?;

// Encrypt data from hex input
let ciphertext = Cipher::aes()
    .with_key(key_builder)
    .with_data_hex("48656c6c6f20576f726c64")?  // "Hello World"
    .encrypt()
    .await?;
```

## Error Handling

### Error Types

```rust
use cryypt::CryptError;

match result {
    Err(CryptError::EncryptionFailed(msg)) => {
        eprintln!("Encryption failed: {}", msg);
    }
    Err(CryptError::DecryptionFailed(msg)) => {
        eprintln!("Decryption failed: {}", msg);
    }
    Err(CryptError::KeyNotFound(id)) => {
        eprintln!("Key not found: {}", id);
    }
    Err(CryptError::InvalidKey(msg)) => {
        eprintln!("Invalid key: {}", msg);
    }
    Err(CryptError::Io(msg)) => {
        eprintln!("I/O error: {}", msg);
    }
    Ok(result) => {
        // Success
    }
}
```

### Result Handling

```rust
// Using ? operator
let result = cipher.encrypt().await?;

// Using match
match cipher.encrypt().await {
    Ok(ciphertext) => println!("Success!"),
    Err(e) => eprintln!("Error: {}", e),
}

// Using unwrap_or_else
let ciphertext = cipher.encrypt().await
    .unwrap_or_else(|e| {
        eprintln!("Encryption failed: {}", e);
        std::process::exit(1);
    });
```

## Async Patterns

### Future Composition

```rust
use futures::future::try_join;

// Parallel operations
let (hash1, hash2) = try_join(
    Hash::sha256().with_data(b"data1").hash(),
    Hash::sha256().with_data(b"data2").hash(),
).await?;
```

### Streaming Operations

```rust
use futures::stream::{self, StreamExt, TryStreamExt};

// Process multiple files
let files = vec!["file1.txt", "file2.txt", "file3.txt"];
let results: Vec<_> = stream::iter(files)
    .map(|file| async move {
        Cipher::aes()
            .with_key(key_builder.clone())
            .with_file(file)
            .await?
            .encrypt()
            .await
    })
    .buffer_unordered(3)  // Process 3 files concurrently
    .try_collect()
    .await?;
```

### Cancellation

```rust
use tokio::time::{timeout, Duration};

// With timeout
let result = timeout(
    Duration::from_secs(30),
    cipher.encrypt()
).await??;  // Note: double ? for timeout and operation errors

// With cancellation token
let result = tokio::select! {
    result = cipher.encrypt() => result?,
    _ = cancellation_token.cancelled() => {
        return Err("Operation cancelled".into());
    }
};
```

## Performance Considerations

### Memory Usage

- All operations use zero-copy where possible
- Sensitive data is automatically zeroized on drop
- No heap allocations for async returns (uses `impl Future`)

### Concurrency

```rust
// Safe concurrent access to the same key
let futures: Vec<_> = (0..10)
    .map(|i| {
        let key = key_builder.clone();
        async move {
            Cipher::aes()
                .with_key(key)
                .with_data(format!("data_{}", i).as_bytes())
                .encrypt()
                .await
        }
    })
    .collect();

let results = futures::future::try_join_all(futures).await?;
```

### Optimization Tips

1. **Reuse key builders** when possible to avoid redundant key resolution
2. **Use compression** for large, repetitive data
3. **Batch operations** using streams for multiple files
4. **Choose appropriate algorithms**: ChaCha20 for high-performance, AES for broad compatibility
5. **Use appropriate key storage**: FileKeyStore for servers, KeychainStore for desktop apps
