//! Core Key Derivation Implementation
//!
//! This module provides the main `KeyDerivation` struct with secure key derivation
//! operations and automatic cleanup of sensitive data.

use super::config::{KdfAlgorithm, KdfConfig};
use crate::KeyError;
use argon2::Argon2;
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512};
use std::num::NonZeroU32;
use zeroize::{Zeroize, Zeroizing};

/// Key derivation context for secure key derivation operations
/// Handles salt generation and key derivation with automatic cleanup
pub struct KeyDerivation {
    config: KdfConfig,
    salt: Option<Zeroizing<Vec<u8>>>,
}

impl KeyDerivation {
    /// Create a new key derivation context
    #[must_use]
    pub fn new(config: KdfConfig) -> Self {
        Self { config, salt: None }
    }

    /// Create with default configuration
    #[must_use]
    pub fn new_default() -> Self {
        Self::new(KdfConfig::default())
    }

    /// Set a custom salt for key derivation
    /// Salt will be zeroized automatically
    #[must_use]
    pub fn with_salt(mut self, salt: Vec<u8>) -> Self {
        self.salt = Some(Zeroizing::new(salt));
        self
    }

    /// Generate a random salt
    /// Uses cryptographically secure random bytes
    #[must_use]
    pub fn with_random_salt(mut self) -> Self {
        use super::super::entropy::generate_secure_bytes;
        let salt = generate_secure_bytes(self.config.salt_size);
        self.salt = Some(Zeroizing::new(salt));
        self
    }
    /// Derive a key from input material
    /// Returns derived key bytes with automatic cleanup
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No salt was provided for key derivation
    /// - KDF parameters are invalid (e.g., zero iterations for PBKDF2)
    /// - The underlying cryptographic operation fails
    pub fn derive_key(&self, input: &[u8]) -> Result<Vec<u8>, KeyError> {
        let salt = self
            .salt
            .as_ref()
            .ok_or_else(|| KeyError::invalid_key("Salt not provided for key derivation"))?;

        match self.config.algorithm {
            KdfAlgorithm::Pbkdf2Sha256 => self.derive_pbkdf2_sha256(input, salt),
            KdfAlgorithm::Pbkdf2Sha512 => self.derive_pbkdf2_sha512(input, salt),
            KdfAlgorithm::Argon2id => self.derive_argon2id(input, salt),
            KdfAlgorithm::HkdfSha256 => self.derive_hkdf_sha256(input, salt),
            KdfAlgorithm::HkdfSha512 => self.derive_hkdf_sha512(input, salt),
        }
    }

    /// Derive key using PBKDF2 with SHA-256
    fn derive_pbkdf2_sha256(&self, input: &[u8], salt: &[u8]) -> Result<Vec<u8>, KeyError> {
        let iterations = NonZeroU32::new(self.config.iterations)
            .ok_or_else(|| KeyError::invalid_key("PBKDF2 iterations must be non-zero"))?;

        let mut output = vec![0u8; self.config.output_size];
        pbkdf2_hmac::<Sha256>(input, salt, iterations.get(), &mut output);

        Ok(output)
    }

    /// Derive key using PBKDF2 with SHA-512
    fn derive_pbkdf2_sha512(&self, input: &[u8], salt: &[u8]) -> Result<Vec<u8>, KeyError> {
        let iterations = NonZeroU32::new(self.config.iterations)
            .ok_or_else(|| KeyError::invalid_key("PBKDF2 iterations must be non-zero"))?;

        let mut output = vec![0u8; self.config.output_size];
        pbkdf2_hmac::<Sha512>(input, salt, iterations.get(), &mut output);

        Ok(output)
    }

    /// Derive key using Argon2id
    fn derive_argon2id(&self, input: &[u8], salt: &[u8]) -> Result<Vec<u8>, KeyError> {
        use argon2::{Algorithm, Params, Version};

        let params = Params::new(
            self.config.memory_cost,
            self.config.iterations,
            self.config.parallelism,
            Some(self.config.output_size),
        )
        .map_err(|e| KeyError::internal(format!("Invalid Argon2 parameters: {e}")))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; self.config.output_size];
        argon2
            .hash_password_into(input, salt, &mut output)
            .map_err(|e| KeyError::internal(format!("Argon2 key derivation failed: {e}")))?;

        Ok(output)
    }

    /// Derive key using HKDF with SHA-256
    fn derive_hkdf_sha256(&self, input: &[u8], salt: &[u8]) -> Result<Vec<u8>, KeyError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), input);
        let mut output = vec![0u8; self.config.output_size];

        hk.expand(&[], &mut output)
            .map_err(|e| KeyError::internal(format!("HKDF-SHA256 expansion failed: {e}")))?;

        Ok(output)
    }

    /// Derive key using HKDF with SHA-512
    fn derive_hkdf_sha512(&self, input: &[u8], salt: &[u8]) -> Result<Vec<u8>, KeyError> {
        let hk = Hkdf::<Sha512>::new(Some(salt), input);
        let mut output = vec![0u8; self.config.output_size];

        hk.expand(&[], &mut output)
            .map_err(|e| KeyError::internal(format!("HKDF-SHA512 expansion failed: {e}")))?;

        Ok(output)
    }

    /// Get the current salt (if set)
    #[must_use]
    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_ref().map(|s| s.as_slice())
    }

    /// Get the KDF configuration
    #[must_use]
    pub fn config(&self) -> &KdfConfig {
        &self.config
    }
}

impl Default for KeyDerivation {
    fn default() -> Self {
        Self::new(KdfConfig::default())
    }
}

impl Drop for KeyDerivation {
    fn drop(&mut self) {
        // Explicit cleanup of sensitive data
        if let Some(ref mut salt) = self.salt {
            salt.zeroize();
        }
    }
}
