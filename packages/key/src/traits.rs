//! Traits for key storage backends

use crate::{
    KeyId, KeyResult,
    store_results::{DeleteResult, ExistsResult, ListResult, RetrieveResult, StoreResult},
};
use std::future::Future;

/// Base trait for all key storage backends
pub trait KeyStorage: Send + Sync {
    /// Check if a key exists
    fn exists(&self, key_id: &dyn KeyId) -> ExistsResult;

    /// Delete a key by ID
    fn delete(&self, key_id: &dyn KeyId) -> DeleteResult;
}

/// Trait for key stores that support retrieving key material
pub trait KeyRetrieval: KeyStorage {
    /// Retrieve a key by ID
    fn retrieve(&self, key_id: &dyn KeyId) -> RetrieveResult;
}

/// Trait for key stores that support importing key material
pub trait KeyImport: KeyStorage {
    /// Store a key with the given ID
    fn store(&self, key_id: &dyn KeyId, key_material: &[u8]) -> StoreResult;
}

/// Trait for key stores that support generating keys
pub trait KeyGeneration: KeyStorage {
    /// Generate a new key with the given ID
    fn generate(&self, key_id: &dyn KeyId, key_size_bytes: usize) -> RetrieveResult;
}

/// Trait for key stores that support listing keys
pub trait KeyEnumeration: KeyStorage {
    /// List all key IDs matching a namespace pattern
    fn list(&self, namespace_pattern: &str) -> ListResult;
}

/// Full-featured key store (convenience trait)
pub trait FullKeyStore:
    KeyStorage + KeyRetrieval + KeyImport + KeyGeneration + KeyEnumeration
{
}

/// Automatically implement `FullKeyStore` for types that implement all components
impl<T> FullKeyStore for T where
    T: KeyStorage + KeyRetrieval + KeyImport + KeyGeneration + KeyEnumeration
{
}

/// Trait for key providers that can resolve to key material
pub trait KeyProviderBuilder: Send + Sync {
    /// Resolve this builder to get the key material
    fn resolve(&self) -> KeyResult;
}

/// Legacy trait for backwards compatibility - DO NOT USE IN NEW CODE
#[deprecated(note = "Use capability-specific traits instead")]
pub trait KeyStore: KeyStorage {
    /// Store key material with the given key ID (DEPRECATED - panics on error)
    fn store(&self, key_id: &dyn KeyId, key_material: &[u8]) -> impl Future<Output = ()> + Send;
    /// Retrieve key material for the given key ID (DEPRECATED - panics on error)
    fn retrieve(&self, key_id: &dyn KeyId) -> impl Future<Output = Vec<u8>> + Send;
    /// Delete the key with the given key ID (DEPRECATED - panics on error)
    fn delete(&self, key_id: &dyn KeyId) -> impl Future<Output = ()> + Send;
    /// Check if a key exists with the given key ID (DEPRECATED - panics on error)
    fn exists(&self, key_id: &dyn KeyId) -> impl Future<Output = bool> + Send;
    /// List all keys matching the given namespace pattern (DEPRECATED - panics on error)
    fn list(&self, namespace_pattern: &str) -> impl Future<Output = Vec<String>> + Send;
}
