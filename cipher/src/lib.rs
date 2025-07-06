#![feature(negative_impls)]
#![feature(marker_trait_attr)]

//! # Cyrup Cipher
//!
//! Encryption library following README.md patterns exactly.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Internal macro implementations (hidden from users per ARCHITECTURE.md)
mod result_macro;
mod chunk_macro;
mod cipher_result;

pub mod bits_macro;
/// Encryption and decryption primitives
pub mod cipher;
pub mod error;

// Re-export core types
pub use error::{CryptError, Result};
pub use cipher_result::{CipherResult, CipherResultWithHandler};

// Re-export the main APIs per README.md
pub use cipher::api::{Cipher, aes_builder::{AesBuilder, AesWithKey, AesWithKeyAndHandler}};
pub use cipher::CipherAlgorithm;

// Re-export common handlers from cryypt_common
pub use cryypt_common::{on_result, on_chunk, on_error};

/// Main entry point - README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Master builder for cipher operations - README.md pattern
    pub fn cipher() -> CipherMasterBuilder {
        CipherMasterBuilder
    }
}

/// Master builder for cipher operations
pub struct CipherMasterBuilder;

impl CipherMasterBuilder {
    /// Use AES-256-GCM encryption - README.md pattern
    pub fn aes(self) -> AesBuilder {
        AesBuilder::new()
    }
}

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        Cipher, Cryypt, CryptError, Result,
        cipher::api::aes_builder::{AesBuilder, AesWithKey},
    };
}