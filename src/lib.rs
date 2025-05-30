//! # Cyrup Crypt
//!
//! Best-in-class encryption library with key rotation and defense-in-depth security.
//!
//! ## Features
//!
//! - **Multiple Cipher Support**: AES-GCM, ChaCha20-Poly1305, and cascade algorithm for dual-layer encryption
//! - **Key Management**: Built-in key rotation, versioning, and namespace support
//! - **Zero-Copy Security**: All sensitive data is zeroized on drop
//! - **Async Support**: Optional async/await support with tokio
//! - **Time-Based Encryption**: Optional rotation-duration key rotation and expiration
//! - **Flexible Architecture**: Trait-based design for easy extension
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use cryypt::prelude::*;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod bits_macro;
/// Encryption and decryption primitives with multiple cipher support
pub mod cipher;
/// Data compression algorithms including gzip, bzip2, zstd, and zip
pub mod compression;
pub mod error;
pub mod hashing;
pub mod jwt;
/// Key management, derivation, and storage with rotation support
pub mod key;
pub mod pqcrypto;
pub mod transport;

// Re-export core types
pub use cipher::{
    CipherAlgorithm, DecryptionResultImpl, EncryptionResultImpl, encryption_result::EncodableResult,
};
pub use error::{CryptError, Result};
pub use key::{KeyId, SimpleKeyId};

// Re-export the fluent API
pub use bits_macro::{BitSize, Bits};
pub use cipher::api::Cipher;
pub use key::api::Key;
pub use pqcrypto::api::{KemBuilder, SignatureBuilder};

pub use jwt::{
    Claims, ClaimsBuilder, Es256Key, Generator, Header, Hs256Key, JwtError, JwtResult, Revocation,
    Rotator, Signer, TokenGenerationFuture, TokenVerificationFuture, ValidationOptions,
};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        BitSize, Bits, Cipher, CryptError, EncodableResult, KemBuilder, Key, SignatureBuilder,
        cipher::api::builder_traits::{
            CiphertextBuilder, DataBuilder as CipherDataBuilder, DecryptBuilder, DecryptSecondPass,
            EncryptBuilder, EncryptSecondPass, KeyBuilder, WithCompression,
        },
        compression::{
            Compress,
            api::{CompressExecutor, DataBuilder as CompressDataBuilder, DecompressExecutor},
        },
        hashing::{
            Hash,
            api::{DataBuilder as HashDataBuilder, HashExecutor, PassesBuilder, SaltBuilder},
        },
        key::store::{FileKeyStore, KeychainStore},
        pqcrypto::prelude::*,
    };
}
