//! Core Key Derivation Implementation
//!
//! This module provides the main KeyDerivation struct with secure key derivation
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
    pub fn new(config: KdfConfig) -> Self {
        Self { config, salt: None }
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(KdfConfig::default())
    }

    /// Set a custom salt for key derivation
    /// Salt will be zeroized automatically
    pub fn with_salt(mut self, salt: Vec<u8>) -> Self {
        self.salt = Some(Zeroizing::new(salt));
        self
    }

    /// Generate a random salt
    /// Uses cryptographically secure random bytes
    pub fn with_random_salt(mut self) -> Self {
        use super::super::entropy::generate_secure_bytes;
        let salt = generate_secure_bytes(self.config.salt_size);
        self.salt = Some(Zeroizing::new(salt));
        self
    }
    /// Derive a key from input material
    /// Returns derived key bytes with automatic cleanup
    pub async fn derive_key(&self, input: &[u8]) -> Result<Vec<u8>, KeyError> {
        let salt = self
            .salt
            .as_ref()
            .ok_or_else(|| KeyError::invalid_key("Salt not provided for key derivation"))?;

        match self.config.algorithm {
            KdfAlgorithm::Pbkdf2Sha256 => self.derive_pbkdf2_sha256(input, salt).await,
            KdfAlgorithm::Pbkdf2Sha512 => self.derive_pbkdf2_sha512(input, salt).await,
            KdfAlgorithm::Argon2id => self.derive_argon2id(input, salt).await,
            KdfAlgorithm::HkdfSha256 => self.derive_hkdf_sha256(input, salt).await,
            KdfAlgorithm::HkdfSha512 => self.derive_hkdf_sha512(input, salt).await,
        }
    }

    /// Derive key using PBKDF2 with SHA-256
    async fn derive_pbkdf2_sha256(&self, input: &[u8], salt: &[u8]) -> Result<Vec<u8>, KeyError> {
        let iterations = NonZeroU32::new(self.config.iterations)
            .ok_or_else(|| KeyError::invalid_key("PBKDF2 iterations must be non-zero"))?;

        let mut output = vec![0u8; self.config.output_size];
        pbkdf2_hmac::<Sha256>(input, salt, iterations.get(), &mut output);

        Ok(output)
    }

    /// Derive key using PBKDF2 with SHA-512
    async fn derive_pbkdf2_sha512(&self, input: &[u8], salt: &[u8]) -> Result<Vec<u8>, KeyError> {
        let iterations = NonZeroU32::new(self.config.iterations)
            .ok_or_else(|| KeyError::invalid_key("PBKDF2 iterations must be non-zero"))?;

        let mut output = vec![0u8; self.config.output_size];
        pbkdf2_hmac::<Sha512>(input, salt, iterations.get(), &mut output);

        Ok(output)
    }

    /// Derive key using Argon2id
    async fn derive_argon2id(&self, input: &[u8], salt: &[u8]) -> Result<Vec<u8>, KeyError> {
        use argon2::{Algorithm, Params, Version};

        let params = Params::new(
            self.config.memory_cost,
            self.config.iterations,
            self.config.parallelism,
            Some(self.config.output_size),
        )
        .map_err(|e| KeyError::internal(format!("Invalid Argon2 parameters: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = vec![0u8; self.config.output_size];
        argon2
            .hash_password_into(input, salt, &mut output)
            .map_err(|e| KeyError::internal(format!("Argon2 key derivation failed: {}", e)))?;

        Ok(output)
    }

    /// Derive key using HKDF with SHA-256
    async fn derive_hkdf_sha256(&self, input: &[u8], salt: &[u8]) -> Result<Vec<u8>, KeyError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), input);
        let mut output = vec![0u8; self.config.output_size];

        hk.expand(&[], &mut output)
            .map_err(|e| KeyError::internal(format!("HKDF-SHA256 expansion failed: {}", e)))?;

        Ok(output)
    }

    /// Derive key using HKDF with SHA-512
    async fn derive_hkdf_sha512(&self, input: &[u8], salt: &[u8]) -> Result<Vec<u8>, KeyError> {
        let hk = Hkdf::<Sha512>::new(Some(salt), input);
        let mut output = vec![0u8; self.config.output_size];

        hk.expand(&[], &mut output)
            .map_err(|e| KeyError::internal(format!("HKDF-SHA512 expansion failed: {}", e)))?;

        Ok(output)
    }

    /// Get the current salt (if set)
    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_ref().map(|s| s.as_slice())
    }

    /// Get the KDF configuration
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
