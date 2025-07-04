//! ChaCha20-Poly1305 encryption builders - core types and entry point
//!
//! Contains the main builder types and entry points for ChaCha20-Poly1305 encryption.

use super::{
    cipher_builder_traits::{
        CiphertextBuilder, DataBuilder, KeyBuilder, KeyProviderBuilder,
    },
};

pub mod encrypt;
pub mod decrypt;
pub mod stream;

pub use encrypt::*;
pub use decrypt::*;
pub use stream::*;

/// Initial ChaCha builder
pub struct ChaChaBuilder;

/// ChaCha builder with key
pub struct ChaChaWithKey {
    pub(crate) key_builder: Box<dyn KeyProviderBuilder>,
}

/// ChaCha builder with key and data - ready to encrypt
pub struct ChaChaWithKeyAndData {
    pub(in crate::cipher) key_builder: Box<dyn KeyProviderBuilder>,
    pub(in crate::cipher) data: Vec<u8>,
}

/// ChaCha builder with key and ciphertext - ready to decrypt
pub struct ChaChaWithKeyAndCiphertext {
    pub(in crate::cipher) key_builder: Box<dyn KeyProviderBuilder>,
    pub(in crate::cipher) ciphertext: Vec<u8>,
}

impl ChaChaBuilder {
    #[doc(hidden)]
    pub fn new() -> Self {
        Self
    }
}

impl KeyBuilder for ChaChaBuilder {
    type Output = ChaChaWithKey;

    fn with_key<K>(self, key_builder: K) -> Self::Output
    where
        K: KeyProviderBuilder + 'static,
    {
        ChaChaWithKey {
            key_builder: Box::new(key_builder),
        }
    }
}

impl DataBuilder for ChaChaWithKey {
    type Output = ChaChaWithKeyAndData;

    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        ChaChaWithKeyAndData {
            key_builder: self.key_builder,
            data: data.into(),
        }
    }
}

impl CiphertextBuilder for ChaChaWithKey {
    type Output = ChaChaWithKeyAndCiphertext;

    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        ChaChaWithKeyAndCiphertext {
            key_builder: self.key_builder,
            ciphertext: ciphertext.into(),
        }
    }
}