//! Key Derivation Function Configuration
//!
//! This module provides KDF algorithm types and configuration presets
//! for secure key derivation operations.

/// Key derivation function types
/// Standard KDF algorithms for key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KdfAlgorithm {
    /// PBKDF2 with SHA-256
    Pbkdf2Sha256,
    /// PBKDF2 with SHA-512
    Pbkdf2Sha512,
    /// Argon2id (recommended for new applications)
    #[default]
    Argon2id,
    /// HKDF with SHA-256
    HkdfSha256,
    /// HKDF with SHA-512
    HkdfSha512,
}

/// Key derivation configuration
/// Parameters for controlling KDF operations
#[derive(Debug, Clone)]
pub struct KdfConfig {
    /// Algorithm to use for key derivation
    pub algorithm: KdfAlgorithm,
    /// Number of iterations (for PBKDF2) or time cost (for Argon2)
    pub iterations: u32,
    /// Memory cost in KB (for Argon2)
    pub memory_cost: u32,
    /// Parallelism factor (for Argon2)
    pub parallelism: u32,
    /// Salt size in bytes
    pub salt_size: usize,
    /// Output key size in bytes
    pub output_size: usize,
}

impl KdfConfig {
    /// Create high-security KDF configuration
    /// Suitable for password-based key derivation
    #[must_use]
    pub fn high_security() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            iterations: 100_000,
            memory_cost: 65536, // 64 MB
            parallelism: 4,
            salt_size: 32,
            output_size: 32,
        }
    }

    /// Create standard KDF configuration
    /// Balanced security and performance
    #[must_use]
    pub fn standard() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            iterations: 50_000,
            memory_cost: 32768, // 32 MB
            parallelism: 2,
            salt_size: 16,
            output_size: 32,
        }
    }

    /// Create fast KDF configuration
    /// Optimized for performance
    #[must_use]
    pub fn fast() -> Self {
        Self {
            algorithm: KdfAlgorithm::HkdfSha256,
            iterations: 1,
            memory_cost: 0,
            parallelism: 1,
            salt_size: 16,
            output_size: 32,
        }
    }
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self::standard()
    }
}
