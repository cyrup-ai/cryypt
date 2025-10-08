#![feature(negative_impls)]
#![feature(marker_trait_attr)]

//! # Cyrup Cipher
//!
//! Encryption library following README.md patterns exactly.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Internal macro implementations (hidden from users per ARCHITECTURE.md)
mod chunk_macro;
mod cipher_result;
mod result_macro;

pub mod bits_macro;
/// Encryption and decryption primitives
pub mod cipher;
pub mod error;

// Re-export core types
pub use cipher_result::{CipherResult, CipherResultWithHandler};
pub use error::{CipherError, Result};

/// Legacy error type alias for backwards compatibility
pub type CryptError = CipherError;

// Re-export the main APIs per README.md
pub use cipher::CipherAlgorithm;
pub use cipher::api::chacha_builder::{ChaChaBuilder, ChaChaWithKey};
pub use cipher::api::{
    Cipher,
    aes_builder::{AesBuilder, AesWithKey, AesWithKeyAndHandler},
};

// Re-export common handlers from cryypt_common
pub use cryypt_common::{on_error, on_result};

/// Main entry point - README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Master builder for cipher operations - README.md pattern
    #[must_use]
    pub fn cipher() -> CipherMasterBuilder {
        CipherMasterBuilder
    }
}

/// Master builder for cipher operations
pub struct CipherMasterBuilder;

impl CipherMasterBuilder {
    /// Use AES-256-GCM encryption - README.md pattern
    #[must_use]
    pub fn aes(self) -> AesBuilder {
        AesBuilder::new()
    }

    /// Use ChaCha20-Poly1305 encryption - README.md pattern
    #[must_use]
    pub fn chacha20(self) -> ChaChaBuilder {
        ChaChaBuilder::new()
    }
}

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        Cipher, CryptError, Cryypt, Result,
        cipher::api::aes_builder::{AesBuilder, AesWithKey},
    };
}
