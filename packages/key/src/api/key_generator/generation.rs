//! Key Generation Logic
//!
//! This module provides the core key generation implementation with security validation
//! and cryptographically secure random key generation.

use super::builder_types::KeyGeneratorReady;
use super::core_types::{SecureKeyBuffer, generate_secure_key_id};
use super::handler::KeyGeneratorWithHandler;
use crate::traits::KeyStorage;

impl<S: KeyStorage> KeyGeneratorReady<S> {
    /// Get the configured key size in bits
    pub const fn key_size_bits(&self) -> u32 {
        self.size_bits
    }

    /// Get the configured key size in bytes
    pub const fn key_size_bytes(&self) -> usize {
        (self.size_bits / 8) as usize
    }

    /// Validate that the key size is cryptographically secure
    pub const fn is_secure_key_size(&self) -> bool {
        matches!(self.size_bits, 128 | 192 | 256 | 384 | 512)
    }

    /// Generate key with default unwrapping - README.md pattern
    /// Returns unwrapped Vec<u8> with default error handling (empty Vec on error)
    pub fn generate(self) -> Vec<u8> {
        let size_bits = self.size_bits;
        let namespace = self.namespace;
        let version = self.version;

        // Validate key size is secure - return empty Vec on invalid size (default error handling)
        if !matches!(size_bits, 128 | 192 | 256 | 384 | 512) {
            return Vec::new();
        }

        // Generate secure key buffer
        let size_bytes = (size_bits / 8) as usize;
        let key_buffer = SecureKeyBuffer::new(size_bytes).fill_secure_random();

        let key_bytes = key_buffer.into_key_bytes();

        // Generate secure key ID for future storage operations
        let _key_id = generate_secure_key_id(&namespace, version);

        // Note: Storage is handled separately via the store APIs
        // This method focuses on key generation per README.md pattern
        key_bytes
    }

    /// Add `on_result` handler - README.md pattern with sexy syntax support
    /// USERS WRITE: Ok => result, Err(e) => `Vec::new()` - CRATE PRIVATE macros transform it
    /// This method signature follows EXACT pattern from `AesWithKey.on_result`
    pub fn on_result<F, T>(self, handler: F) -> KeyGeneratorWithHandler<S, F, T>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        KeyGeneratorWithHandler {
            size_bits: self.size_bits,
            store: self.store,
            namespace: self.namespace,
            version: self.version,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }
}
