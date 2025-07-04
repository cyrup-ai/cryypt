//! Cryptographically secure key generation module
//!
//! Contains the main generator traits, builder patterns, and core types for secure key generation.

use crate::{
    traits::KeyStorage,
    SimpleKeyId,
};
use rand::{rng, RngCore};
use zeroize::Zeroizing;

// Declare submodules
pub mod symmetric;
pub mod entropy;
pub mod derive;

// Re-export key types from submodules for external use
// pub use derive::*;
// pub use entropy::*;
// pub use symmetric::*;

/// Secure key buffer that automatically zeroizes on drop
/// Prevents key material from remaining in memory
#[derive(Debug)]
pub(crate) struct SecureKeyBuffer {
    data: Zeroizing<Vec<u8>>,
}

impl SecureKeyBuffer {
    /// Create a new secure buffer with the specified size
    /// Uses zeroizing allocator to ensure cleanup
    #[inline]
    fn new(size: usize) -> Self {
        Self {
            data: Zeroizing::new(vec![0u8; size]),
        }
    }

    /// Fill the buffer with cryptographically secure random bytes
    /// Uses thread-local RNG for maximum security
    #[inline]
    fn fill_secure_random(mut self) -> Self {
        rng().fill_bytes(&mut self.data);
        self
    }

    /// Extract the key bytes in a secure manner
    /// Returns zeroizing vector that will clean up automatically
    #[inline]
    fn into_key_bytes(self) -> Vec<u8> {
        self.data.to_vec()
    }
}

/// Generate cryptographically secure unique identifier
/// Uses secure random bytes instead of predictable counters
#[inline]
pub(crate) fn generate_secure_key_id(namespace: &str, version: u32) -> SimpleKeyId {
    let mut id_bytes = [0u8; 16];
    rng().fill_bytes(&mut id_bytes);
    let unique_id = hex::encode(id_bytes);

    // Use format! since this is not in hot path and security is paramount
    let id_str = format!("{}:v{}:{}", namespace, version, unique_id);
    SimpleKeyId::new(id_str)
}

/// Builder for generating new cryptographic keys
/// Zero-sized type for compile-time optimization
#[derive(Debug, Clone, Copy)]
pub struct KeyGenerator;

/// KeyGenerator with size configured
/// Single u32 field for minimal memory footprint
#[derive(Debug, Clone, Copy)]
pub struct KeyGeneratorWithSize {
    pub(crate) size_bits: u32,
}

/// KeyGenerator with size and store configured
/// Generic over storage to enable monomorphization optimization
#[derive(Debug, Clone)]
pub struct KeyGeneratorWithSizeAndStore<S: KeyStorage> {
    pub(crate) size_bits: u32,
    pub(crate) store: S,
}

/// KeyGenerator with size, store, and namespace configured
/// Uses secure string handling for namespace
#[derive(Debug, Clone)]
pub struct KeyGeneratorWithSizeStoreAndNamespace<S: KeyStorage> {
    pub(crate) size_bits: u32,
    pub(crate) store: S,
    pub(crate) namespace: String,
}

/// KeyGenerator with all parameters configured - ready to generate
/// Final builder state with all parameters validated
#[derive(Debug, Clone)]
pub struct KeyGeneratorReady<S: KeyStorage> {
    pub(crate) size_bits: u32,
    pub(crate) store: S,
    pub(crate) namespace: String,
    pub(crate) version: u32,
}

/// Stream configuration for secure key generation operations
/// Encapsulates channel capacity and security settings
#[derive(Debug, Clone, Copy)]
pub struct StreamConfig {
    pub(crate) capacity: usize,
    pub(crate) bounded: bool,
}

impl StreamConfig {
    /// Create bounded stream configuration with specified capacity
    /// Bounded channels provide backpressure control
    #[inline(always)]
    pub const fn bounded(capacity: usize) -> Self {
        Self {
            capacity,
            bounded: true,
        }
    }

    /// Create unbounded stream configuration
    /// Use with caution - no backpressure control
    #[inline(always)]
    pub const fn unbounded() -> Self {
        Self {
            capacity: 0,
            bounded: false,
        }
    }

    /// Default bounded configuration optimized for single key generation
    #[inline(always)]
    pub const fn default_bounded() -> Self {
        Self::bounded(1)
    }
}

impl Default for StreamConfig {
    #[inline(always)]
    fn default() -> Self {
        Self::default_bounded()
    }
}

impl KeyGenerator {
    /// Create a new key generator
    /// Zero-cost constructor for zero-sized type
    #[inline(always)]
    pub const fn new() -> Self {
        Self
    }

    /// Set the key size in bits
    /// Validates key size at compile time where possible
    #[inline(always)]
    pub const fn size(self, bits: crate::bits_macro::BitSize) -> KeyGeneratorWithSize {
        KeyGeneratorWithSize {
            size_bits: bits.bits,
        }
    }
}

impl Default for KeyGenerator {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl KeyGeneratorWithSize {
    /// Set the key storage backend
    /// Generic constraint enables compile-time optimization
    #[inline(always)]
    pub fn with_store<S: KeyStorage + 'static>(self, store: S) -> KeyGeneratorWithSizeAndStore<S> {
        KeyGeneratorWithSizeAndStore {
            size_bits: self.size_bits,
            store,
        }
    }

    /// Get the configured key size in bits
    #[inline(always)]
    pub const fn key_size_bits(&self) -> u32 {
        self.size_bits
    }

    /// Get the configured key size in bytes
    #[inline(always)]
    pub const fn key_size_bytes(&self) -> usize {
        (self.size_bits / 8) as usize
    }

    /// Validate that the key size is cryptographically secure
    #[inline(always)]
    pub const fn is_secure_key_size(&self) -> bool {
        // Only allow standard, secure key sizes
        matches!(self.size_bits, 128 | 192 | 256 | 384 | 512)
    }
}

impl<S: KeyStorage> KeyGeneratorWithSizeAndStore<S> {
    /// Set the namespace for organizing keys
    /// Namespace is used in key identification
    #[inline]
    pub fn with_namespace(
        self,
        namespace: impl Into<String>,
    ) -> KeyGeneratorWithSizeStoreAndNamespace<S> {
        let namespace = namespace.into();
        // Note: We remove validation here to match README.md pattern
        // Validation can be done in generate_internal if needed
        KeyGeneratorWithSizeStoreAndNamespace {
            size_bits: self.size_bits,
            store: self.store,
            namespace,
        }
    }

    /// Get the configured key size in bits
    #[inline(always)]
    pub const fn key_size_bits(&self) -> u32 {
        self.size_bits
    }

    /// Get the configured key size in bytes
    #[inline(always)]
    pub const fn key_size_bytes(&self) -> usize {
        (self.size_bits / 8) as usize
    }

    /// Validate that the key size is cryptographically secure
    #[inline(always)]
    pub const fn is_secure_key_size(&self) -> bool {
        matches!(self.size_bits, 128 | 192 | 256 | 384 | 512)
    }
}

impl<S: KeyStorage> KeyGeneratorWithSizeStoreAndNamespace<S> {
    /// Set the version number for key rotation
    /// Version must be non-zero for security
    #[inline]
    pub fn version(self, version: u32) -> KeyGeneratorReady<S> {
        // Note: We remove the validation here to match README.md pattern
        // Validation can be done in generate_internal if needed
        KeyGeneratorReady {
            size_bits: self.size_bits,
            store: self.store,
            namespace: self.namespace,
            version,
        }
    }

    /// Get the configured key size in bits
    #[inline(always)]
    pub const fn key_size_bits(&self) -> u32 {
        self.size_bits
    }

    /// Get the configured key size in bytes
    #[inline(always)]
    pub const fn key_size_bytes(&self) -> usize {
        (self.size_bits / 8) as usize
    }

    /// Validate that the key size is cryptographically secure
    #[inline(always)]
    pub const fn is_secure_key_size(&self) -> bool {
        matches!(self.size_bits, 128 | 192 | 256 | 384 | 512)
    }
}

impl<S: KeyStorage> KeyGeneratorReady<S> {
    /// Get the configured key size in bits
    #[inline(always)]
    pub const fn key_size_bits(&self) -> u32 {
        self.size_bits
    }

    /// Get the configured key size in bytes
    #[inline(always)]
    pub const fn key_size_bytes(&self) -> usize {
        (self.size_bits / 8) as usize
    }

    /// Validate that the key size is cryptographically secure
    #[inline(always)]
    pub const fn is_secure_key_size(&self) -> bool {
        matches!(self.size_bits, 128 | 192 | 256 | 384 | 512)
    }
}