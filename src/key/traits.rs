//! Traits for key storage backends

use crate::{KeyId, Result};
use std::future::Future;

/// Async result for key existence check
pub trait AsyncExistsResult: Future<Output = Result<bool>> + Send {}
impl<T> AsyncExistsResult for T where T: Future<Output = Result<bool>> + Send {}

/// Async result for key deletion
pub trait AsyncDeleteResult: Future<Output = Result<()>> + Send {}
impl<T> AsyncDeleteResult for T where T: Future<Output = Result<()>> + Send {}

/// Async result for key retrieval
pub trait AsyncRetrieveResult: Future<Output = Result<Vec<u8>>> + Send {}
impl<T> AsyncRetrieveResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}

/// Async result for key storage
pub trait AsyncStoreResult: Future<Output = Result<()>> + Send {}
impl<T> AsyncStoreResult for T where T: Future<Output = Result<()>> + Send {}

/// Async result for key generation
pub trait AsyncGenerateResult: Future<Output = Result<Vec<u8>>> + Send {}
impl<T> AsyncGenerateResult for T where T: Future<Output = Result<Vec<u8>>> + Send {}

/// Async result for key listing
pub trait AsyncListResult: Future<Output = Result<Vec<String>>> + Send {}
impl<T> AsyncListResult for T where T: Future<Output = Result<Vec<String>>> + Send {}

/// Base trait for all key storage backends
pub trait KeyStorage: Send + Sync {
    /// Check if a key exists
    fn exists(&self, key_id: &dyn KeyId) -> impl AsyncExistsResult;

    /// Delete a key by ID
    fn delete(&self, key_id: &dyn KeyId) -> impl AsyncDeleteResult;
}

/// Trait for key stores that support retrieving key material
pub trait KeyRetrieval: KeyStorage {
    /// Retrieve a key by ID
    fn retrieve(&self, key_id: &dyn KeyId) -> impl AsyncRetrieveResult;
}

/// Trait for key stores that support importing key material
pub trait KeyImport: KeyStorage {
    /// Store a key with the given ID
    fn store(&self, key_id: &dyn KeyId, key_material: &[u8]) -> impl AsyncStoreResult;
}

/// Trait for key stores that support generating keys
pub trait KeyGeneration: KeyStorage {
    /// Generate a new key with the given ID
    fn generate(&self, key_id: &dyn KeyId, key_size_bytes: usize) -> impl AsyncGenerateResult;
}

/// Trait for key stores that support listing keys
pub trait KeyEnumeration: KeyStorage {
    /// List all key IDs matching a namespace pattern
    fn list(&self, namespace_pattern: &str) -> impl AsyncListResult;
}

/// Full-featured key store (convenience trait)
pub trait FullKeyStore:
    KeyStorage + KeyRetrieval + KeyImport + KeyGeneration + KeyEnumeration
{
}

/// Automatically implement FullKeyStore for types that implement all components
impl<T> FullKeyStore for T where
    T: KeyStorage + KeyRetrieval + KeyImport + KeyGeneration + KeyEnumeration
{
}

/// Legacy trait for backwards compatibility - DO NOT USE IN NEW CODE
#[deprecated(note = "Use capability-specific traits instead")]
pub trait KeyStore: KeyStorage {
    fn store(
        &self,
        key_id: &dyn KeyId,
        key_material: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;
    fn retrieve(&self, key_id: &dyn KeyId) -> impl Future<Output = Result<Vec<u8>>> + Send;
    fn delete(&self, key_id: &dyn KeyId) -> impl Future<Output = Result<()>> + Send;
    fn exists(&self, key_id: &dyn KeyId) -> impl Future<Output = Result<bool>> + Send;
    fn list(&self, namespace_pattern: &str) -> impl Future<Output = Result<Vec<String>>> + Send;
}
