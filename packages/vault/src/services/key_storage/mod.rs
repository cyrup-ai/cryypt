//! Key storage abstraction for PQCrypto keys
//!
//! Provides a trait-based abstraction over different key storage backends,
//! allowing keys to be stored in OS keychain, files, environment variables,
//! or cloud secret managers.

use crate::error::{VaultError, VaultResult};

pub mod keychain;
pub mod file;
pub mod factory;

pub use keychain::KeychainStorage;
pub use file::FileStorage;
pub use factory::{KeyStorageSource, KeyStorageBackend, create_key_storage};

/// Abstraction over key storage backends for PQCrypto keys
///
/// This trait allows the vault to work with different key storage mechanisms:
/// - OS Keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
/// - File storage (encrypted key files on disk)
/// - Environment variables (for CI/CD pipelines)
/// - Cloud secret managers (AWS Secrets Manager, HashiCorp Vault, etc.)
pub trait KeyStorage: Send + Sync {
    /// Store a PQCrypto keypair
    ///
    /// # Arguments
    /// * `key_id` - Full key identifier (e.g., "pq_armor:v1:pq_keypair")
    /// * `keypair` - Combined public + private key bytes
    ///
    /// # Key Format
    /// For ML-KEM-768: First 1184 bytes = public key, remaining = private key
    ///
    /// # Errors
    /// Returns error if storage operation fails
    fn store(&self, key_id: &str, keypair: &[u8]) -> impl std::future::Future<Output = VaultResult<()>> + Send;

    /// Retrieve a PQCrypto keypair
    ///
    /// # Arguments
    /// * `key_id` - Full key identifier (e.g., "pq_armor:v1:pq_keypair")
    ///
    /// # Returns
    /// Combined public + private key bytes
    ///
    /// # Errors
    /// Returns ItemNotFound if key doesn't exist
    /// Returns error if retrieval operation fails
    fn retrieve(&self, key_id: &str) -> impl std::future::Future<Output = VaultResult<Vec<u8>>> + Send;

    /// Check if a key exists
    ///
    /// # Arguments
    /// * `key_id` - Full key identifier
    ///
    /// # Returns
    /// true if key exists, false otherwise
    fn exists(&self, key_id: &str) -> impl std::future::Future<Output = bool> + Send {
        async move {
            self.retrieve(key_id).await.is_ok()
        }
    }

    /// Delete a key from storage
    ///
    /// # Arguments
    /// * `key_id` - Full key identifier
    ///
    /// # Errors
    /// Returns error if deletion fails
    fn delete(&self, key_id: &str) -> impl std::future::Future<Output = VaultResult<()>> + Send;
}
