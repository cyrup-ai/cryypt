# Cryypt

A comprehensive cryptography library for Rust, providing immutable builders for encryption, hashing, compression, and key management.

## Crates

This workspace contains the following crates:

### Core Cryptography
- **[cipher](./cipher/)** - Symmetric encryption algorithms (AES-GCM, ChaCha20-Poly1305)
- **[hashing](./hashing/)** - Cryptographic hash functions (SHA-256, SHA3, BLAKE2b)
- **[key](./key/)** - Key generation and management

### Data Processing
- **[compression](./compression/)** - Data compression algorithms (Zstandard, Gzip, Bzip2, ZIP)

### Advanced Features
- **[jwt](./jwt/)** - JSON Web Token creation and verification
- **[pqcrypto](./pqcrypto/)** - Post-quantum cryptography algorithms (Kyber, Dilithium, Falcon, SPHINCS+)
- **[quic](./quic/)** - QUIC transport protocol with built-in encryption
- **[vault](./vault/)** - Secure encrypted storage vault

### Main API
- **[cryypt](./cryypt/)** - Unified API with feature flags for selective functionality

### Supporting Crates
- **[common](./common/)** - Common infrastructure and error types
- **[map_macro](./map_macro/)** - Ergonomic map/set macros
- **[examples](./examples/)** - Example applications demonstrating usage

## Installation

Add the main crate with the features you need:

```toml
[dependencies]
# Core features
cryypt = { version = "0.1", features = ["aes", "sha256", "zstd", "key", "file-store"] }

# Or use feature groups
cryypt = { version = "0.1", features = ["encryption", "hashing", "compression"] }

# All features
cryypt = { version = "0.1", features = ["full"] }
```

Or use individual crates directly:

```toml
[dependencies]
cryypt_cipher = "0.1"
cryypt_hashing = "0.1"
cryypt_compression = "0.1"
cryypt_key = "0.1"
```

## API Design

Cryypt offers two equivalent APIs:

1. **Master Builder**: `Cryypt::cipher()`, `Cryypt::hash()`, `Cryypt::compress()`
2. **Direct Builders**: `Cipher::aes()`, `Hash::sha256()`, `Compress::zstd()`

Both are fully supported - use whichever feels more natural for your use case.

## Quick Examples

### Encryption
```rust
use cryypt::{Cryypt, on_result};

let encrypted = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Operation error: {}", e))
    })
    .encrypt(b"Secret message")
    .await;
```

### Hashing
```rust
let hash = Cryypt::hash()
    .sha256()
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Hash error: {}", e))
    })
    .compute(b"Hello, World!")
    .await;
```

### Compression
```rust
let compressed = Cryypt::compress()
    .zstd()
    .with_level(3)
    .on_result!(|result| {
        result.unwrap_or_else(|e| panic!("Compression error: {}", e))
    })
    .compress(b"Large text data...")
    .await;
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.