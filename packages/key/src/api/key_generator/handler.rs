//! Handler Pattern and Future Implementation
//!
//! This module provides the result handler pattern and Future trait implementation
//! for async key generation with custom error handling.

use super::core_types::{SecureKeyBuffer, generate_secure_key_id};
use crate::traits::KeyStorage;

/// `KeyGenerator` with all parameters and result handler configured
/// Enables sexy syntax like Ok => result in closures via CRATE PRIVATE macros
#[derive(Debug)]
pub struct KeyGeneratorWithHandler<S: KeyStorage, F, T> {
    pub(crate) size_bits: u32,
    pub(crate) store: S,
    pub(crate) namespace: String,
    pub(crate) version: u32,
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

impl<S: KeyStorage + crate::traits::KeyImport, F, T> KeyGeneratorWithHandler<S, F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
    S: KeyStorage + crate::traits::KeyImport + Send + 'static,
{
    /// Generate key - action takes no arguments, follows README.md pattern
    /// USERS USE SEXY SYNTAX Ok => result IN CLOSURES - internal macros handle transformation
    /// This method follows EXACT pattern from `AesWithKeyAndHandler::encrypt`
    pub async fn generate(self) -> T {
        let size_bits = self.size_bits;
        let _store = self.store;
        let namespace = self.namespace;
        let version = self.version;
        let handler = self.result_handler;

        // Generate cryptographically secure key using the same pattern as AES
        let result = async move {
            // Validate key size is secure
            if !matches!(size_bits, 128 | 192 | 256 | 384 | 512) {
                return Err(crate::error::KeyError::InvalidKeySize {
                    expected: 256, // Standard key size
                    actual: size_bits as usize,
                });
            }

            // Generate secure key buffer
            let size_bytes = (size_bits / 8) as usize;
            let key_buffer = SecureKeyBuffer::new(size_bytes).fill_secure_random();

            let key_bytes = key_buffer.into_key_bytes();

            // Generate secure key ID for future storage operations
            let _key_id = generate_secure_key_id(&namespace, version);

            // Note: Storage is handled separately via the store APIs
            // This method focuses on key generation per README.md pattern
            Ok(key_bytes)
        }
        .await;

        // Apply result handler following AES pattern
        handler(result)
    }
}

// Implement IntoFuture for KeyGeneratorWithHandler to enable .await
impl<S: KeyStorage + crate::traits::KeyImport, F, T> std::future::IntoFuture
    for KeyGeneratorWithHandler<S, F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
    S: KeyStorage + crate::traits::KeyImport + Send + 'static,
{
    type Output = T;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.generate())
    }
}
