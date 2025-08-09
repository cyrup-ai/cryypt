//! Base cipher builder traits
//!
//! Contains fundamental builder traits for cipher operations.

use super::super::{AsyncDecryptionResult, AsyncEncryptionResult};
// Import KeyProviderBuilder from the key crate where it belongs
pub use cryypt_key::traits::KeyProviderBuilder;

/// Builder that can accept a key
pub trait KeyBuilder {
    /// The output type after adding a key
    type Output;
    /// Add a key to the builder
    fn with_key<K>(self, key_builder: K) -> Self::Output
    where
        K: KeyProviderBuilder + 'static;
}

/// Builder that can accept AAD (Additional Authenticated Data) for AEAD ciphers
/// NOTE: Library trait - intended for external implementations
#[allow(dead_code)]
pub trait AadBuilder {
    /// The resulting type after adding AAD
    type Output;

    /// Add multiple AAD key-value pairs from a map
    fn with_aad(self, aad_map: std::collections::HashMap<String, String>) -> Self::Output;
}

/// Final stage builder that can encrypt
/// NOTE: Library trait - intended for external implementations
#[allow(dead_code)]
pub trait EncryptBuilder {
    /// Perform encryption operation
    fn encrypt(self) -> impl AsyncEncryptionResult;
}

/// Final stage builder that can decrypt
/// NOTE: Library trait - intended for external implementations
#[allow(dead_code)]
pub trait DecryptBuilder {
    /// Perform decryption operation
    fn decrypt(self) -> impl AsyncDecryptionResult;
}
