//! AES encryption builders core module
//!
//! Contains the main builder structures and core implementations for AES encryption.
//! Follows the patterns defined in README.md and ARCHITECTURE.md.

use super::{
    builder_traits::{
        AadBuilder, CiphertextBuilder, DataBuilder, DecryptBuilder, EncryptBuilder, KeyBuilder,
        KeyProviderBuilder,
    },
    AsyncDecryptionResult, AsyncEncryptionResult, CipherOnResultExt, CipherProducer, CryptoStream,
};
use crate::{cipher::encryption_result::EncryptionResultImpl, CryptError, Result};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm,
};
use rand::RngCore;
use tokio::sync::oneshot;
use zeroize::Zeroizing;
use std::pin::Pin;
use std::future::Future;

// Declare submodules
pub mod encrypt;
pub mod decrypt;
pub mod stream;
pub mod aad;

// Re-export key types from submodules
pub use encrypt::*;
pub use decrypt::*; 
pub use stream::*;
pub use aad::*;

/// Initial AES builder
pub struct AesBuilder;

/// AES builder with key
pub struct AesWithKey {
    pub(crate) key_builder: Box<dyn KeyProviderBuilder>,
    pub(crate) chunk_handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
}

/// AES builder with key and data - ready to encrypt
pub struct AesWithKeyAndData {
    pub(in crate::cipher) key_builder: Box<dyn KeyProviderBuilder>,
    pub(in crate::cipher) data: Vec<u8>,
    pub(in crate::cipher) aad: std::collections::HashMap<String, String>,
}

/// AES builder with key and ciphertext - ready to decrypt
pub struct AesWithKeyAndCiphertext {
    pub(in crate::cipher) key_builder: Box<dyn KeyProviderBuilder>,
    pub(in crate::cipher) ciphertext: Vec<u8>,
    pub(in crate::cipher) aad: std::collections::HashMap<String, String>,
}

impl AesBuilder {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self
    }
}

impl KeyBuilder for AesBuilder {
    type Output = AesWithKey;

    fn with_key<K>(self, key_builder: K) -> Self::Output
    where
        K: KeyProviderBuilder + 'static,
    {
        AesWithKey {
            key_builder: Box::new(key_builder),
            chunk_handler: None,
        }
    }
}

impl DataBuilder for AesWithKey {
    type Output = AesWithKeyAndData;

    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        AesWithKeyAndData {
            key_builder: self.key_builder,
            data: data.into(),
            aad: std::collections::HashMap::new(),
        }
    }
}

impl CiphertextBuilder for AesWithKey {
    type Output = AesWithKeyAndCiphertext;

    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        AesWithKeyAndCiphertext {
            key_builder: self.key_builder,
            ciphertext: ciphertext.into(),
            aad: std::collections::HashMap::new(),
        }
    }
}