//! # Cryypt - Unified Cryptography Library
//!
//! Best-in-class encryption, hashing, compression, and key management with feature-gated algorithms.
//!
//! ## Features
//!
//! All algorithms are feature-gated for minimal dependency footprint:
//!
//! ### Encryption
//! - `aes` - AES-256-GCM encryption
//! - `chacha20` - ChaCha20-Poly1305 encryption
//!
//! ### Hashing
//! - `sha256` - SHA-256 hashing
//! - `sha3` - SHA3-256 hashing (also enables sha3-384, sha3-512)
//! - `blake2b` - BLAKE2b hashing
//!
//! ### Compression
//! - `zstd` - Zstandard compression (recommended)
//! - `gzip` - Gzip compression
//! - `bzip2` - Bzip2 compression
//! - `zip` - ZIP compression
//!
//! ### Key Management
//! - `key` - Core key management (required for encryption)
//! - `file-store` - File-based key storage
//! - `keychain-store` - OS keychain storage
//!
//! ## Usage
//!
//! Add specific algorithms to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! cryypt = { version = "0.1", features = ["aes", "sha256"] }
//! ```
//!
//! Or use convenience groups:
//!
//! ```toml
//! cryypt = { version = "0.1", features = ["encryption", "hashing"] }
//! ```
//!
//! ## Example
//!
//! ```rust,no_run
//! # #[cfg(all(feature = "aes", feature = "file-store"))]
//! # {
//! use cryypt::prelude::*;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let master_key = [1u8; 32]; // In production, generate this securely
//!
//! // Encrypt data
//! let ciphertext = Cipher::aes()
//!     .with_key(
//!         Key::size(256u32.bits())
//!             .with_store(FileKeyStore::at("./keys").with_master_key(master_key))
//!             .with_namespace("my-app")
//!             .version(1),
//!     )
//!     .with_data(b"Hello, World!")
//!     .encrypt()
//!     .await?;
//!
//! // Decrypt data
//! let decrypted = Cipher::aes()
//!     .with_key(
//!         Key::size(256u32.bits())
//!             .with_store(FileKeyStore::at("./keys").with_master_key(master_key))
//!             .with_namespace("my-app")
//!             .version(1),
//!     )
//!     .with_ciphertext(ciphertext)
//!     .decrypt()
//!     .await?;
//!
//! assert_eq!(decrypted, b"Hello, World!");
//! # Ok(())
//! # }
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

// === Core Re-exports ===

#[cfg(feature = "key")]
#[cfg_attr(docsrs, doc(cfg(feature = "key")))]
pub use cryypt_key::{Key, KeyId, KeyResult};

#[cfg(feature = "file-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "file-store")))]
pub use cryypt_key::store::FileKeyStore;

#[cfg(feature = "keychain-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "keychain-store")))]
pub use cryypt_key::store::KeychainStore;

// === Cipher Re-exports ===

#[cfg(any(feature = "aes", feature = "chacha20"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "aes", feature = "chacha20"))))]
pub use cryypt_cipher::{Cipher, EncodableResult, CryptError};

// === Hashing Re-exports ===

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))))]
pub use cryypt_hashing::{Hash, HashError};

// === Compression Re-exports ===

#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))))]
pub use cryypt_compression::{Compress, CompressionError};

// === Higher Level Re-exports ===

#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub use cryypt_jwt as jwt;

#[cfg(feature = "pqcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "pqcrypto")))]
pub use cryypt_pqcrypto as pqcrypto;

#[cfg(feature = "quiq")]
#[cfg_attr(docsrs, doc(cfg(feature = "quiq")))]
pub use cryypt_quiq as quiq;

#[cfg(feature = "vault")]
#[cfg_attr(docsrs, doc(cfg(feature = "vault")))]
pub use cryypt_vault as vault;

/// Prelude module for convenient imports
pub mod prelude {
    #[cfg(feature = "key")]
    pub use crate::Key;

    #[cfg(feature = "file-store")]
    pub use crate::FileKeyStore;

    #[cfg(feature = "keychain-store")]
    pub use crate::KeychainStore;

    #[cfg(any(feature = "aes", feature = "chacha20"))]
    pub use crate::{Cipher, EncodableResult};

    #[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
    pub use crate::Hash;

    #[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
    pub use crate::Compress;

    #[cfg(feature = "key")]
    pub use cryypt_key::bits_macro::Bits;

    // Re-export builder traits needed for method chaining
    #[cfg(any(feature = "aes", feature = "chacha20"))]
    pub use cryypt_cipher::prelude::*;

    #[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
    pub use cryypt_hashing::api::*;

    #[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
    pub use cryypt_compression::api::*;
}