# `cryypt`

Immutable builders for encryption, hashing, compression.

## Cipher API Examples

### AES-GCM Encryption

```rust
use cryypt::{Cipher, Key, FileKeyStore};

// Simple encryption with key
let ciphertext = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("my-app")
        .version(1))
    .with_data(b"Hello, World!")
    .encrypt()
    .await?;

// Decrypt
let plaintext = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("my-app")
        .version(1))
    .with_ciphertext(ciphertext)
    .decrypt()
    .await?;
```

### ChaCha20-Poly1305 Encryption
```rust
use cryypt::{Cipher, Key, KeychainStore};

// Encrypt with ChaCha20-Poly1305
let ciphertext = Cipher::chachapoly()
    .with_key(Key::size(256.bits())
        .with_store(KeychainStore::for_app("MyApp"))
        .with_namespace("secure-app")
        .version(1))
    .with_data(b"Secret message")
    .encrypt()
    .await?;

// Decrypt
let plaintext = Cipher::chachapoly()
    .with_key(Key::size(256.bits())
        .with_store(KeychainStore::for_app("MyApp"))
        .with_namespace("secure-app")
        .version(1))
    .with_ciphertext(ciphertext)
    .decrypt()
    .await?;
```

### Two-Pass Encryption (AES then ChaCha)
```rust
use cryypt::{Cipher, Key, FileKeyStore};

// Double encryption: AES-GCM followed by ChaCha20-Poly1305
let ciphertext = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_data(b"Top secret")
    .second_pass(Cipher::chachapoly()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("app")
            .version(2)))
    .encrypt()
    .await?;

// Decrypt in reverse order (ChaCha first, then AES)
let plaintext = Cipher::chachapoly()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(2))
    .with_ciphertext(ciphertext)
    .second_pass(Cipher::aes()
        .with_key(Key::size(256.bits())
            .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
            .with_namespace("app")
            .version(1)))
    .decrypt()
    .await?;
```

## Hashing API Examples

### SHA-256 Hashing
```rust
use cryypt::hashing::Hash;

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
use cryypt::hashing::Hash;

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
use cryypt::hashing::Hash;

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
use cryypt::hashing::Hash;

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
use cryypt::{Cipher, Key, FileKeyStore};

// Setup key store (one time)
let master_key = [0u8; 32]; // In practice: derive from secure source

// Generate key and encrypt data in one beautiful chain
let ciphertext = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("production")
        .version(1))
    .with_data(b"Secret data")
    .encrypt()
    .await?;

// Later: decrypt (key automatically retrieved)
let plaintext = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("production")
        .version(1))
    .with_ciphertext(ciphertext)
    .decrypt()
    .await?;
```

### AWS KMS Integration
```rust
use cryypt::{Cipher, Key, AwsKmsDataKeyStore, AwsSecretsManagerStore};

// Encrypt with KMS-managed key (generates on first use)
let ciphertext = Cipher::chachapoly()
    .with_key(Key::size(256.bits())
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
use cryypt::{Cipher, Key, KeychainStore};

// Encrypt user data (key generated/retrieved automatically)
let encrypted = Cipher::aes()
    .with_key(Key::size(256.bits())
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
use cryypt::compression::Compress;

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
use cryypt::{compression::Compress, Cipher, Key, FileKeyStore};

// Compress then encrypt in the cipher builder
let result = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_compression(Compress::zstd()) // Defaults to high compression
    .with_data(b"Large sensitive data that compresses well...")
    .encrypt()
    .await?;

// Decrypt then decompress automatically
let original = Cipher::aes()
    .with_key(Key::size(256.bits())
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

## Encoding & File Operations

### Base64 and Hex Encoding
```rust
use cryypt::{Cipher, Key, FileKeyStore};

// Encrypt and get base64 result
let base64_result = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_text("Hello, World!")
    .encrypt()
    .await?
    .to_base64();

// Decrypt from base64
let plaintext = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_ciphertext_base64(&base64_result)?
    .decrypt()
    .await?;

// Hex encoding
let hex_result = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_data(b"Binary data")
    .encrypt()
    .await?
    .to_hex();

// Decrypt from hex
let plaintext = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_ciphertext_hex(&hex_result)?
    .decrypt()
    .await?;
```

### File Encryption
```rust
use cryypt::{Cipher, Key, FileKeyStore};

// Encrypt file contents and save to another file
Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_file("secret.txt")
    .await?
    .encrypt()
    .await?
    .to_file("secret.enc")
    .await?;

// Decrypt from file
let plaintext = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_ciphertext_file("secret.enc")
    .await?
    .decrypt()
    .await?;

// Convert decrypted result to string
let text = String::from_utf8(plaintext)?;
```

### Data Input from Encoded Sources
```rust
use cryypt::{Cipher, Key, FileKeyStore};

// Encrypt data from base64 input
let ciphertext = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_data_base64("SGVsbG8gV29ybGQ=")?  // "Hello World" in base64
    .encrypt()
    .await?;

// Encrypt data from hex input
let ciphertext = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_data_hex("48656c6c6f20576f726c64")?  // "Hello World" in hex
    .encrypt()
    .await?;
```

### Multiple Output Formats
```rust
use cryypt::{Cipher, Key, FileKeyStore};

let encrypted_result = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_text("Secret message")
    .encrypt()
    .await?;

// Get in different formats
let base64 = encrypted_result.to_base64();
let hex = encrypted_result.to_hex();
let bytes = encrypted_result.to_bytes();

// Or save directly to file
encrypted_result.to_file("output.enc").await?;
```

### Compression with Encoding
```rust
use cryypt::{compression::Compress, Cipher, Key, FileKeyStore};

// Compress, encrypt, and encode in one chain
let base64_result = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_compression(Compress::zstd())
    .with_text("Large text that will be compressed then encrypted...")
    .encrypt()
    .await?
    .to_base64();

// Decrypt and decompress automatically
let original_text = Cipher::aes()
    .with_key(Key::size(256.bits())
        .with_store(FileKeyStore::at("/secure/keys").with_master_key(master_key))
        .with_namespace("app")
        .version(1))
    .with_compression(Compress::zstd())
    .with_ciphertext_base64(&base64_result)?
    .decrypt()
    .await?;

let text = String::from_utf8(original_text)?;
```

## Features

- **Zero-Copy Security**: All sensitive data is automatically zeroized on drop
- **Type-Safe Builder Pattern**: Compile-time verification of required parameters
- **Async by Default**: Non-blocking operations with `impl Future` returns
- **No Boxing**: Zero-allocation async returns using `impl Trait`
- **Flexible Chaining**: Compose multiple encryption/hashing operations

ACKNOWLEDGEMENTS

- [Cloudflare Team](https://www.cloudflare.com/) - Thank you for your support and contributions to Rust, especially [Quique](https://github.com/cloudflare/quiche) which was our choice for a quiq client/server pairing.
- We also want to thank the entire Rust community for their support and contributions.

CONTRIBUTING

We welcome contributions to the project! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for details on how to contribute.
