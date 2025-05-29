//! Builder traits for cipher operations

use super::{AsyncEncryptionResult, AsyncDecryptionResult};

/// Builder that can accept a key
pub trait KeyBuilder {
    type Output;
    fn with_key<K>(self, key_builder: K) -> Self::Output 
    where 
        K: KeyProviderBuilder + 'static;
}

/// Trait for key builders that can provide keys
pub trait KeyProviderBuilder: Send + Sync {
    /// Resolve this builder to get the key material
    fn resolve(&self) -> crate::key::KeyResult;
}

/// Builder that can accept data
pub trait DataBuilder {
    type Output;
    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output;
}

/// Builder that can accept ciphertext
pub trait CiphertextBuilder {
    type Output;
    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output;
}

/// Final stage builder that can encrypt
pub trait EncryptBuilder {
    fn encrypt(self) -> impl AsyncEncryptionResult;
}

/// Final stage builder that can decrypt
pub trait DecryptBuilder {
    fn decrypt(self) -> impl AsyncDecryptionResult;
}