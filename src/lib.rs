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
//! ```rust
//! use cyrup_crypt::{Cipher, KeyId, CipherAlgorithm, factory::CipherFactory};
//!
//! // Create a cipher
//! let factory = CipherFactory::new();
//! let cipher = factory.create_cipher(CipherAlgorithm::Aes256Gcm)?;
//!
//! // Create a key
//! let key_id = KeyId::new("my-app", 1);
//!
//! // Encrypt data
//! let plaintext = b"Hello, World!";
//! let encrypted = cipher.encrypt(plaintext, Some(&key_id))?;
//!
//! // Decrypt data
//! let decrypted = cipher.decrypt(&encrypted, Some(&key_id))?;
//! assert_eq!(plaintext, &decrypted[..]);
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod cipher;
pub mod compression;
pub mod error;
pub mod hashing;
pub mod key;
pub mod bits_macro;

// Re-export core types
pub use cipher::{CipherAlgorithm, EncryptionResultImpl, DecryptionResultImpl};
pub use error::{CryptError, Result};
pub use key::{KeyId, SimpleKeyId};

// Re-export the fluent API
pub use cipher::api::Cipher;
pub use key::api::Key;
pub use bits_macro::{Bits, BitSize};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        Cipher, Key, CryptError, Bits, BitSize,
        key::store::{FileKeyStore, KeychainStore},
        hashing::Hash,
        compression::Compress,
    };
}
