//! Fluent cipher API following README.md patterns
//!
//! NEW PATTERN: Actions take data as arguments
//! Usage: `Cipher::aes().with_key(key).on_result(handler).encrypt(data).await`

pub mod aes_builder;
mod chacha_builder;
mod cipher;
mod cipher_builder_traits;

use crate::cipher::encryption_result::EncodableResult;
use crate::Result;
use std::future::Future;

/// Trait for async encryption results that can be awaited
pub trait AsyncEncryptionResult: Future<Output = Result<EncodableResult>> + Send {}

/// Trait for async decryption results that can be awaited
pub trait AsyncDecryptionResult: Future<Output = Result<Vec<u8>>> + Send {}

// Blanket implementations for any type that meets the bounds
impl<T> AsyncEncryptionResult for T where T: Future<Output = Result<EncodableResult>> + Send {}
impl<T> AsyncDecryptionResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}

// Export the main API
pub use cipher::Cipher;
pub use aes_builder::{AesBuilder, AesWithKey};
pub use chacha_builder::{ChaChaBuilder, ChaChaWithKey};

// Export traits for compatibility
pub use cipher_builder_traits::KeyBuilder;

// Export crypto stream
#[derive(Debug)]
pub struct CryptoStream;

impl CryptoStream {
    /// Create a new crypto stream
    pub fn new() -> Self {
        Self
    }
}