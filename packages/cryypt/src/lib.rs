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
//! - `blake2b` - `BLAKE2b` hashing
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
//! ```rust,ignore
//! use cryypt::{Cryypt, Key, FileKeyStore};
//!
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let master_key = [1u8; 32]; // In production, generate this securely
//!
//! // Encrypt data - NEW PATTERN: action takes data as argument
//! let ciphertext = Cryypt::cipher()
//!     .aes()
//!     .with_key(
//!         Key::size(256u32.bits())
//!             .with_store(FileKeyStore::at("./keys").with_master_key(master_key))
//!             .with_namespace("my-app")
//!             .version(1),
//!     )
//!     .on_result(|result| {
//!         match result {
//!             Ok(ciphertext) => ciphertext,
//!             Err(e) => {
//!                 log::error!("Encryption error: {}", e);
//!                 Vec::new()
//!             }
//!         }
//!     })
//!     .encrypt(b"Hello, World!")
//!     .await;
//!
//! // Decrypt data - NEW PATTERN: action takes data as argument
//! let decrypted = Cryypt::cipher()
//!     .aes()
//!     .with_key(
//!         Key::size(256u32.bits())
//!             .with_store(FileKeyStore::at("./keys").with_master_key(master_key))
//!             .with_namespace("my-app")
//!             .version(1),
//!     )
//!     .on_result(|result| {
//!         match result {
//!             Ok(decrypted) => decrypted,
//!             Err(e) => {
//!                 log::error!("Decryption error: {}", e);
//!                 Vec::new()
//!             }
//!         }
//!     })
//!     .decrypt(ciphertext)
//!     .await;
//!
//! assert_eq!(decrypted, b"Hello, World!");
//! Ok(())
//! }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

// === Core Modules ===

#[cfg(any(
    feature = "key",
    feature = "aes",
    feature = "chacha20",
    feature = "sha256",
    feature = "sha3",
    feature = "blake2b",
    feature = "zstd",
    feature = "gzip",
    feature = "bzip2",
    feature = "zip",
    feature = "vault",
    feature = "pqcrypto",
    feature = "quic"
))]
mod master;

#[cfg(any(
    feature = "key",
    feature = "aes",
    feature = "chacha20",
    feature = "sha256",
    feature = "sha3",
    feature = "blake2b",
    feature = "zstd",
    feature = "gzip",
    feature = "bzip2",
    feature = "zip",
    feature = "vault",
    feature = "pqcrypto",
    feature = "quic"
))]
pub use master::Cryypt;

#[cfg(any(feature = "aes", feature = "chacha20"))]
pub use master::CipherMasterBuilder;

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
pub use master::HashMasterBuilder;

#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
pub use master::CompressMasterBuilder;

#[cfg(feature = "jwt")]
pub use cryypt_jwt::api::JwtMasterBuilder;

#[cfg(feature = "key")]
pub use master::KeyMasterBuilder;

#[cfg(feature = "vault")]
pub use master::VaultMasterBuilder;

#[cfg(feature = "pqcrypto")]
pub use master::PqcryptoMasterBuilder;

#[cfg(feature = "quic")]
pub use master::QuicMasterBuilder;

// === Core Re-exports ===

// Re-export common utilities only (no macros exposed)
pub use cryypt_common::*;

#[cfg(feature = "key")]
#[cfg_attr(docsrs, doc(cfg(feature = "key")))]
pub use cryypt_key::{Key, KeyGenerator, KeyId, KeyResult, KeyRetriever};

#[cfg(feature = "key")]
#[cfg_attr(docsrs, doc(cfg(feature = "key")))]
pub use cryypt_key::api::KeyBuilder;

#[cfg(feature = "key")]
#[cfg_attr(docsrs, doc(cfg(feature = "key")))]
pub use cryypt_key::on_result;

#[cfg(feature = "key")]
#[cfg_attr(docsrs, doc(cfg(feature = "key")))]
pub use cryypt_key::bits_macro::Bits;

#[cfg(feature = "file-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "file-store")))]
pub use cryypt_key::store::FileKeyStore;

#[cfg(feature = "keychain-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "keychain-store")))]
pub use cryypt_key::store::KeychainStore;

// === Cipher Re-exports ===

#[cfg(any(feature = "aes", feature = "chacha20"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "aes", feature = "chacha20"))))]
pub use cryypt_cipher::{Cipher, CryptError};

// === Hashing Re-exports ===

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b")))
)]
pub use cryypt_hashing::{Hash, HashError, HashResult};

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b")))
)]
pub use cryypt_hashing::on_result as hash_on_result;

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b")))
)]
// === Compression Re-exports ===
#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip")))
)]
pub use cryypt_compression::{Compress, CompressionError};

// === Higher Level Re-exports ===

#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub use cryypt_jwt as jwt;

#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub use cryypt_jwt::{Jwt, JwtError, JwtResult};

#[cfg(feature = "pqcrypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "pqcrypto")))]
pub use cryypt_pqcrypto as pqcrypto;

#[cfg(feature = "quic")]
#[cfg_attr(docsrs, doc(cfg(feature = "quic")))]
pub use cryypt_quic as quic;

#[cfg(feature = "vault")]
#[cfg_attr(docsrs, doc(cfg(feature = "vault")))]
pub use cryypt_vault as vault;

#[cfg(feature = "quic")]
#[cfg_attr(docsrs, doc(cfg(feature = "quic")))]
pub use cryypt_quic::{QuicClient, QuicRecv, QuicSend, QuicServer};

/// Prelude module for convenient imports
pub mod prelude {
    #[cfg(feature = "key")]
    pub use crate::{Key, KeyBuilder, KeyGenerator, KeyRetriever, on_result};

    #[cfg(feature = "key")]
    pub use crate::Cryypt;

    #[cfg(feature = "file-store")]
    pub use crate::FileKeyStore;

    #[cfg(feature = "keychain-store")]
    pub use crate::KeychainStore;

    #[cfg(any(feature = "aes", feature = "chacha20"))]
    pub use crate::Cipher;

    #[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
    pub use crate::{Hash, HashResult, hash_on_result};

    #[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
    pub use Compress;

    #[cfg(feature = "key")]
    pub use cryypt_key::bits_macro::Bits;

    // Re-export builder traits needed for method chaining
    #[cfg(any(feature = "aes", feature = "chacha20"))]
    pub use cryypt_cipher::prelude::*;

    #[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
    pub use cryypt_hashing::api::*;

    #[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
    pub use cryypt_compression::api::*;

    #[cfg(feature = "jwt")]
    pub use crate::Jwt;
}
