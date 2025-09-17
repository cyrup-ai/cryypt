//! Actual cryptographic key that holds key material

use crate::{KeyResult, traits::KeyProviderBuilder};
use zeroize::Zeroizing;

/// Actual cryptographic key holding key material
///
/// This represents a generated or retrieved cryptographic key that can be used
/// directly for encryption operations as shown in README.md
#[derive(Debug, Clone)]
pub struct ActualKey {
    /// The key material, automatically zeroized on drop
    key_bytes: Zeroizing<Vec<u8>>,
}

impl ActualKey {
    /// Create a new key from bytes
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            key_bytes: Zeroizing::new(bytes),
        }
    }

    /// Get the key bytes (for external use by cryypt consumers)
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    // Note: AES and ChaCha20 convenience methods moved to main cryypt crate
    // to avoid circular dependency between key and cipher crates.
    // The README.md pattern `key.aes().encrypt(data)` will be available
    // through the main cryypt crate which can depend on both key and cipher.
}

/// Simple key provider that provides the key bytes directly
/// This is library code intended for future API expansion
#[derive(Clone)]
#[allow(dead_code)]
pub struct DirectKeyProvider {
    key_bytes: Zeroizing<Vec<u8>>,
}

impl DirectKeyProvider {
    /// Create a new direct key provider
    #[allow(dead_code)]
    pub fn new(key_bytes: Vec<u8>) -> Self {
        Self {
            key_bytes: Zeroizing::new(key_bytes),
        }
    }
}

impl KeyProviderBuilder for DirectKeyProvider {
    fn resolve(&self) -> KeyResult {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let key_bytes = self.key_bytes.clone();

        tokio::spawn(async move {
            let _ = tx.send(Ok(key_bytes.to_vec()));
        });

        KeyResult::new(rx)
    }
}

impl KeyProviderBuilder for ActualKey {
    fn resolve(&self) -> KeyResult {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let key_bytes = self.key_bytes.clone();

        tokio::spawn(async move {
            let _ = tx.send(Ok(key_bytes.to_vec()));
        });

        KeyResult::new(rx)
    }
}

impl Drop for ActualKey {
    fn drop(&mut self) {
        // Zeroizing<Vec<u8>> handles this automatically
    }
}
