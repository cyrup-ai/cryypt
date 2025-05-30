# `crypt`

Immutable builders for encryption, hashing, compression.

## Cipher API Examples

### AES-GCM Encryption

```rust
use cyrup_crypt::{Cipher, Key, FileKeyStore};

// Simple encryption with key
let ciphertext = Cipher::aes()
    .with_key(Key::size(256.bits)
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("my-app")
        .version(1))
    .with_data(b"Hello, World!")
    .encrypt()
    .await?;

// Decrypt
let plaintext = Cipher::aes()
    .with_key(Key::size(256.bits)
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("my-app")
        .version(1))
    .with_ciphertext(ciphertext)
    .decrypt()
    .await?;
```

### ChaCha20-Poly1305 Encryption
```rust
use cyrup_crypt::{Cipher, Key, KeychainStore};

// Encrypt with ChaCha20-Poly1305
let ciphertext = Cipher::chachapoly()
    .with_key(Key::size(256.bits)
        .with_store(KeychainStore::for_app("MyApp"))
        .with_namespace("secure-app")
        .version(1))
    .with_data(b"Secret message")
    .encrypt()
    .await?;

// Decrypt
let plaintext = Cipher::chachapoly()
    .with_key(Key::size(256.bits)
        .with_store(KeychainStore::for_app("MyApp"))
        .with_namespace("secure-app")
        .version(1))
    .with_ciphertext(ciphertext)
    .decrypt()
    .await?;
```

### Two-Pass Encryption (AES then ChaCha)
```rust
use cyrup_crypt::{Cipher, Key, FileKeyStore};

// Double encryption: AES-GCM followed by ChaCha20-Poly1305
let ciphertext = Cipher::aes()
    .with_key(Key::size(256.bits)
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_data(b"Top secret")
    .second_pass(Cipher::chachapoly()
        .with_key(Key::size(256.bits)
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("app")
            .version(2)))
    .encrypt()
    .await?;

// Decrypt in reverse order (ChaCha first, then AES)
let plaintext = Cipher::chachapoly()
    .with_key(Key::size(256.bits)
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(2))
    .with_ciphertext(ciphertext)
    .second_pass(Cipher::aes()
        .with_key(Key::size(256.bits)
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("app")
            .version(1)))
    .decrypt()
    .await?;
```

## Hashing API Examples

### SHA-256 Hashing
```rust
use cyrup_crypt::hashing::Hash;

// Simple hash
let hash = Hash::sha256()
    .with_data(b"Hello, World!")
    .hash()
    .await?;

// Hash with salt
let hash = Hash::sha256()
    .with_data(b"password")
    .with_salt(b"random_salt")
    .hash()
    .await?;

// Hash with multiple passes (key stretching)
let hash = Hash::sha256()
    .with_data(b"password")
    .with_salt(b"random_salt")
    .with_passes(10_000)
    .hash()
    .await?;
```

### Blake2b Hashing
```rust
use cyrup_crypt::hashing::Hash;

// Blake2b with default 64-byte output
let hash = Hash::blake2b()
    .with_data(b"Hello, World!")
    .hash()
    .await?;

// Blake2b with key (for MAC)
let hash = Hash::blake2b()
    .with_data(b"message")
    .with_salt(b"secret_key") // salt acts as key in Blake2b
    .hash()
    .await?;
```

### SHA3 Hashing
```rust
use cyrup_crypt::hashing::Hash;

// SHA3-256 (default)
let hash = Hash::sha3()
    .with_data(b"data")
    .hash()
    .await?;

// SHA3 with salt and passes
let hash = Hash::sha3()
    .with_data(b"password")
    .with_salt(b"salt")
    .with_passes(1_000)
    .hash()
    .await?;
```

### Text Input
```rust
use cyrup_crypt::hashing::Hash;

// Hash text directly
let hash = Hash::sha256()
    .with_text("Hello, World!")
    .hash()
    .await?;

// Combine with other options
let hash = Hash::blake2b()
    .with_text("user@example.com")
    .with_salt(b"app_specific_salt")
    .hash()
    .await?;
```

## Full Integrated Examples

### Generate Key and Encrypt in One Chain
```rust
use cyrup_crypt::{Cipher, Key, FileKeyStore};

// Setup key store (one time)
let master_key = [0u8; 32]; // In practice: derive from secure source

// Generate key and encrypt data in one beautiful chain
let ciphertext = Cipher::aes()
    .with_key(Key::size(256.bits)
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("production")
        .version(1))
    .with_data(b"Secret data")
    .encrypt()
    .await?;

// Later: decrypt (key automatically retrieved)
let plaintext = Cipher::aes()
    .with_key(Key::size(256.bits)
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("production")
        .version(1))
    .with_ciphertext(ciphertext)
    .decrypt()
    .await?;
```

### AWS KMS Integration
```rust
use cyrup_crypt::{Cipher, Key, AwsKmsDataKeyStore, AwsSecretsManagerStore};

// Encrypt with KMS-managed key (generates on first use)
let ciphertext = Cipher::chachapoly()
    .with_key(Key::size(256.bits)
        .with_store(AwsKms::with_cmk("alias/production-cmk")
            .using_secrets_manager("prod/keys"))
        .with_namespace("api-service")
        .version(1))
    .with_data(b"Customer PII")
    .encrypt()
    .await?;
```

### OS Keychain Storage
```rust
use cyrup_crypt::{Cipher, Key, KeychainStore};

// Encrypt user data (key generated/retrieved automatically)
let encrypted = Cipher::aes()
    .with_key(Key::size(256.bits)
        .with_store(KeychainStore::for_app("MyApp"))
        .with_namespace("user-keys")
        .version(1))
    .with_data(b"User secrets")
    .encrypt()
    .await?;
```

## Compression API Examples

### Zstd Compression (Recommended)
```rust
use cyrup_crypt::compression::Compress;

// Simple compression (defaults to high compression)
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
use cyrup_crypt::{compression::Compress, Cipher, Key, FileKeyStore};

// Compress then encrypt in the cipher builder
let result = Cipher::aes()
    .with_key(Key::size(256.bits)
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_compression(Compress::zstd()) // Defaults to high compression
    .with_data(b"Large sensitive data that compresses well...")
    .encrypt()
    .await?;

// Decrypt then decompress automatically
let original = Cipher::aes()
    .with_key(Key::size(256.bits)
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_compression(Compress::zstd())
    .with_ciphertext(result)
    .decrypt()
    .await?;

// Standalone compression operations
let compressed = Compress::bzip2()
    .with_data(b"Large text that compresses well...")
    .balanced_compression() // Level 6
    .compress()
    .await?;
```

## Features

- **Zero-Copy Security**: All sensitive data is automatically zeroized on drop
- **Type-Safe Builder Pattern**: Compile-time verification of required parameters
- **Async by Default**: Non-blocking operations with `impl Future` returns
- **No Boxing**: Zero-allocation async returns using `impl Trait`
- **Flexible Chaining**: Compose multiple encryption/hashing operations
