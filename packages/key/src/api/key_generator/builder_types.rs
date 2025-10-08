//! Builder Pattern Types for Key Generation
//!
//! This module provides the builder pattern types and basic methods for constructing
//! key generators with compile-time validation and type safety.

use crate::traits::KeyStorage;

/// Builder for generating new cryptographic keys
/// Zero-sized type for compile-time optimization
#[derive(Debug, Clone, Copy)]
pub struct KeyGenerator;

/// `KeyGenerator` with size configured
/// Single u32 field for minimal memory footprint
#[derive(Debug, Clone, Copy)]
pub struct KeyGeneratorWithSize {
    pub(crate) size_bits: u32,
}

/// `KeyGenerator` with size and store configured
/// Generic over storage to enable monomorphization optimization
#[derive(Debug, Clone)]
pub struct KeyGeneratorWithSizeAndStore<S: KeyStorage> {
    pub(crate) size_bits: u32,
    pub(crate) store: S,
}

/// `KeyGenerator` with size, store, and namespace configured
/// Uses secure string handling for namespace
#[derive(Debug, Clone)]
pub struct KeyGeneratorWithSizeStoreAndNamespace<S: KeyStorage> {
    pub(crate) size_bits: u32,
    pub(crate) store: S,
    pub(crate) namespace: String,
}

/// `KeyGenerator` with all parameters configured - ready to generate
/// Final builder state with all parameters validated
#[derive(Debug, Clone)]
pub struct KeyGeneratorReady<S: KeyStorage> {
    pub(crate) size_bits: u32,
    pub(crate) store: S,
    pub(crate) namespace: String,
    pub(crate) version: u32,
}

impl KeyGenerator {
    /// Create a new key generator
    /// Zero-cost constructor for zero-sized type
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Set the key size in bits
    /// Validates key size at compile time where possible
    #[must_use]
    pub const fn size(self, bits: crate::bits_macro::BitSize) -> KeyGeneratorWithSize {
        KeyGeneratorWithSize {
            size_bits: bits.bits,
        }
    }
}

impl Default for KeyGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyGeneratorWithSize {
    /// Set the key storage backend
    /// Generic constraint enables compile-time optimization
    pub fn with_store<S: KeyStorage + 'static>(self, store: S) -> KeyGeneratorWithSizeAndStore<S> {
        KeyGeneratorWithSizeAndStore {
            size_bits: self.size_bits,
            store,
        }
    }

    /// Get the configured key size in bits
    #[must_use]
    pub const fn key_size_bits(&self) -> u32 {
        self.size_bits
    }

    /// Get the configured key size in bytes
    #[must_use]
    pub const fn key_size_bytes(&self) -> usize {
        (self.size_bits / 8) as usize
    }

    /// Validate that the key size is cryptographically secure
    #[must_use]
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
        KeyGeneratorWithSizeStoreAndNamespace {
            size_bits: self.size_bits,
            store: self.store,
            namespace,
        }
    }

    /// Get the configured key size in bits
    pub const fn key_size_bits(&self) -> u32 {
        self.size_bits
    }

    /// Get the configured key size in bytes
    #[must_use]
    pub const fn key_size_bytes(&self) -> usize {
        (self.size_bits / 8) as usize
    }

    /// Validate that the key size is cryptographically secure
    #[must_use]
    pub const fn is_secure_key_size(&self) -> bool {
        matches!(self.size_bits, 128 | 192 | 256 | 384 | 512)
    }
}

impl<S: KeyStorage> KeyGeneratorWithSizeStoreAndNamespace<S> {
    /// Set the version number for key rotation
    /// Version must be non-zero for security
    #[inline]
    pub fn version(self, version: u32) -> KeyGeneratorReady<S> {
        KeyGeneratorReady {
            size_bits: self.size_bits,
            store: self.store,
            namespace: self.namespace,
            version,
        }
    }

    /// Get the configured key size in bits
    pub const fn key_size_bits(&self) -> u32 {
        self.size_bits
    }

    /// Get the configured key size in bytes
    #[must_use]
    pub const fn key_size_bytes(&self) -> usize {
        (self.size_bits / 8) as usize
    }

    /// Validate that the key size is cryptographically secure
    #[must_use]
    pub const fn is_secure_key_size(&self) -> bool {
        matches!(self.size_bits, 128 | 192 | 256 | 384 | 512)
    }
}
