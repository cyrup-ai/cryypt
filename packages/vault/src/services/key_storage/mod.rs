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
    /// * `namespace` - Logical grouping for keys (e.g., "pq_armor")
    /// * `version` - Key version number for rotation support
    /// * `keypair` - Combined public + private key bytes
    ///
    /// # Key Format
    /// For ML-KEM-768: First 1184 bytes = public key, remaining = private key
    ///
    /// # Errors
    /// Returns error if storage operation fails
    async fn store(&self, namespace: &str, version: u32, keypair: &[u8]) -> VaultResult<()>;

    /// Retrieve a PQCrypto keypair
    ///
    /// # Arguments
    /// * `namespace` - Logical grouping for keys
    /// * `version` - Key version number
    ///
    /// # Returns
    /// Combined public + private key bytes
    ///
    /// # Errors
    /// Returns ItemNotFound if key doesn't exist
    /// Returns error if retrieval operation fails
    async fn retrieve(&self, namespace: &str, version: u32) -> VaultResult<Vec<u8>>;

    /// Check if a key exists
    ///
    /// # Arguments
    /// * `namespace` - Logical grouping for keys
    /// * `version` - Key version number
    ///
    /// # Returns
    /// true if key exists, false otherwise
    async fn exists(&self, namespace: &str, version: u32) -> bool {
        self.retrieve(namespace, version).await.is_ok()
    }

    /// Delete a key from storage
    ///
    /// # Arguments
    /// * `namespace` - Logical grouping for keys
    /// * `version` - Key version number
    ///
    /// # Errors
    /// Returns error if deletion fails
    async fn delete(&self, namespace: &str, version: u32) -> VaultResult<()>;

    /// List all versions for a namespace
    ///
    /// # Arguments
    /// * `namespace` - Logical grouping for keys
    ///
    /// # Returns
    /// Vector of version numbers, sorted ascending
    async fn list_versions(&self, namespace: &str) -> VaultResult<Vec<u32>>;
}
