//! Actual cryptographic key that holds key material

use zeroize::{Zeroize, Zeroizing};
use crate::{KeyResult, traits::KeyProviderBuilder};

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
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            key_bytes: Zeroizing::new(bytes),
        }
    }

    /// Get the key bytes (for internal use)
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Return AES cipher builder using this key
    /// 
    /// This enables the README.md pattern: `key.aes().encrypt(data)`
    #[cfg(feature = "aes")]
    pub fn aes(&self) -> cryypt_cipher::AesWithKey {
        // Create AES builder pre-configured with this key
        let key_provider = DirectKeyProvider {
            key_bytes: self.key_bytes.clone(),
        };
        cryypt_cipher::Cipher::aes().with_key(key_provider)
    }

    /// Return ChaCha20 cipher builder using this key
    /// 
    /// This enables the README.md pattern: `key.chacha20().encrypt(data)`
    #[cfg(feature = "chacha20")]
    pub fn chacha20(&self) -> cryypt_cipher::ChaChaWithKey {
        // Create ChaCha builder pre-configured with this key
        let key_provider = DirectKeyProvider {
            key_bytes: self.key_bytes.clone(),
        };
        cryypt_cipher::Cipher::chachapoly().with_key(key_provider)
    }
}

/// Simple key provider that provides the key bytes directly
#[derive(Clone)]
struct DirectKeyProvider {
    key_bytes: Zeroizing<Vec<u8>>,
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