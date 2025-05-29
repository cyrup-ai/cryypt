//! Fluent cipher API with zero boxing
//! 
//! Usage: `let result = Cipher::chachapoly().with_key(key_id).with_data(data).encrypt().await`

mod states;
mod cipher;
pub mod builder_traits;
mod aes_builder;
mod chacha_builder;
mod decryption_builder;

use crate::Result;
use std::future::Future;

/// Trait for async encryption results that can be awaited
pub trait AsyncEncryptionResult: Future<Output = Result<Vec<u8>>> + Send {}

/// Trait for async decryption results that can be awaited
pub trait AsyncDecryptionResult: Future<Output = Result<Vec<u8>>> + Send {}

// Blanket implementations for any type that meets the bounds
impl<T> AsyncEncryptionResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}
impl<T> AsyncDecryptionResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}

pub use states::{NoData, HasData, NoKey, HasKey};
pub use cipher::Cipher;
pub use builder_traits::{KeyBuilder, DataBuilder, EncryptBuilder};