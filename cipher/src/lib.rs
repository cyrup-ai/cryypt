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
//! use cryypt_cipher::{Cipher, prelude::*};
//! use cryypt_key::{Key, store::FileKeyStore, bits_macro::Bits};
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
pub mod error;

// Re-export core types
pub use cipher::{
    encryption_result::EncodableResult, CipherAlgorithm, DecryptionResultImpl, EncryptionResultImpl,
};
pub use error::{CryptError, Result};

// Re-export the fluent API
pub use bits_macro::{BitSize, Bits};
pub use cipher::api::Cipher;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        cipher::api::builder_traits::{
            CiphertextBuilder, DataBuilder as CipherDataBuilder, DecryptBuilder, DecryptSecondPass,
            EncryptBuilder, EncryptSecondPass, KeyBuilder, WithCompression,
        },
        BitSize, Bits, Cipher, CryptError, EncodableResult,
    };
}
