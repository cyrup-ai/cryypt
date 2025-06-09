//! Fluent cipher API with zero boxing
//!
//! Usage: `let result = Cipher::chachapoly().with_key(key_id).with_data(data).encrypt().await`

mod aes_builder;
pub mod builder_traits;
mod chacha_builder;
mod cipher;
mod decryption_builder;
mod states;

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

pub use builder_traits::{DataBuilder, EncryptBuilder, KeyBuilder};
pub use cipher::Cipher;
pub use states::{HasData, HasKey, NoData, NoKey};
