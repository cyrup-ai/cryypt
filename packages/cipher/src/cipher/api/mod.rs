//! Fluent cipher API following README.md patterns
//!
//! NEW PATTERN: Actions take data as arguments
//! Usage: `Cipher::aes().with_key(key).on_result(handler).encrypt(data).await`

pub mod aes_builder;
pub mod chacha_builder;
mod cipher;
mod cipher_builder_traits;

use crate::Result;
use crate::cipher::encryption_result::EncodableResult;
use std::future::Future;

/// Trait for async encryption results that can be awaited
pub trait AsyncEncryptionResult: Future<Output = Result<EncodableResult>> + Send {}

/// Trait for async decryption results that can be awaited
pub trait AsyncDecryptionResult: Future<Output = Result<Vec<u8>>> + Send {}

// Blanket implementations for any type that meets the bounds
impl<T> AsyncEncryptionResult for T where T: Future<Output = Result<EncodableResult>> + Send {}
impl<T> AsyncDecryptionResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}

// Export the main API
pub use aes_builder::{AesBuilder, AesWithKey};
pub use chacha_builder::{ChaChaBuilder, ChaChaWithKey};
pub use cipher::Cipher;

// Export traits for compatibility
pub use cipher_builder_traits::KeyBuilder;

/// Streaming cryptographic operations for processing large data sets
///
/// `CryptoStream` provides an interface for streaming encryption and decryption
/// operations that can handle data larger than memory in chunks. This is useful
/// for processing files, network streams, or other large data sources without
/// loading everything into memory at once.
///
/// # Examples
///
/// ```no_run
/// use cryypt_cipher::cipher::api::CryptoStream;
///
/// let stream = CryptoStream::new();
/// // Use stream for chunk-based crypto operations
/// ```
#[derive(Debug)]
pub struct CryptoStream;

impl Default for CryptoStream {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoStream {
    /// Create a new crypto stream
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}
