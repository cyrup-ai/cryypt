//! Specialized Key Derivation Tools
//!
//! This module provides specialized key derivation implementations optimized
//! for specific use cases like password stretching and zero-allocation hot paths.

use super::config::{KdfAlgorithm, KdfConfig};
use super::core::KeyDerivation;
use crate::KeyError;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512};
use std::num::NonZeroU32;
use zeroize::{Zeroize, Zeroizing};

/// High-performance key stretching for password-based keys
/// Uses optimized parameters for different security levels
pub struct KeyStretcher {
    algorithm: KdfAlgorithm,
}

impl KeyStretcher {
    /// Create new key stretcher with specified algorithm
    #[must_use]
    pub fn new(algorithm: KdfAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Create key stretcher optimized for interactive use
    #[must_use]
    pub fn interactive() -> Self {
        Self::new(KdfAlgorithm::Argon2id)
    }

    /// Create key stretcher optimized for server use
    #[must_use]
    pub fn server() -> Self {
        Self::new(KdfAlgorithm::Argon2id)
    }
    /// Stretch password to cryptographic key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The selected algorithm is not supported for password stretching
    /// - The underlying key derivation operation fails
    /// - Invalid parameters are provided to the KDF
    pub fn stretch_password(
        &self,
        password: &[u8],
        salt: &[u8],
        output_length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let config = match self.algorithm {
            KdfAlgorithm::Argon2id => KdfConfig {
                algorithm: KdfAlgorithm::Argon2id,
                iterations: 3,
                memory_cost: 65536, // 64 MB
                parallelism: 4,
                salt_size: salt.len(),
                output_size: output_length,
            },
            KdfAlgorithm::Pbkdf2Sha256 => KdfConfig {
                algorithm: KdfAlgorithm::Pbkdf2Sha256,
                iterations: 600_000, // OWASP recommendation 2023
                memory_cost: 0,
                parallelism: 1,
                salt_size: salt.len(),
                output_size: output_length,
            },
            KdfAlgorithm::Pbkdf2Sha512 => KdfConfig {
                algorithm: KdfAlgorithm::Pbkdf2Sha512,
                iterations: 210_000, // OWASP recommendation 2023
                memory_cost: 0,
                parallelism: 1,
                salt_size: salt.len(),
                output_size: output_length,
            },
            _ => {
                return Err(KeyError::invalid_key(
                    "Unsupported algorithm for password stretching",
                ));
            }
        };

        let kdf = KeyDerivation::new(config).with_salt(salt.to_vec());
        let key = kdf.derive_key(password)?;
        Ok(Zeroizing::new(key))
    }
}

/// Zero-allocation key derivation for hot paths
/// Pre-allocates buffers and reuses them for multiple derivations
pub struct FastKeyDerivation {
    algorithm: KdfAlgorithm,
    buffer: Vec<u8>,
    salt_buffer: Vec<u8>,
}

impl FastKeyDerivation {
    /// Create new fast key derivation context
    #[must_use]
    pub fn new(algorithm: KdfAlgorithm, max_output_size: usize, max_salt_size: usize) -> Self {
        Self {
            algorithm,
            buffer: vec![0u8; max_output_size],
            salt_buffer: vec![0u8; max_salt_size],
        }
    }
    /// Derive key with pre-allocated buffers (zero allocation)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Output size exceeds the pre-allocated buffer capacity
    /// - Salt size exceeds the pre-allocated salt buffer capacity
    /// - PBKDF2 iterations parameter is zero
    /// - The underlying cryptographic operation fails (HKDF expansion, Argon2 hashing)
    pub fn derive_fast(
        &mut self,
        input: &[u8],
        salt: &[u8],
        output_size: usize,
        iterations: u32,
    ) -> Result<&[u8], KeyError> {
        if output_size > self.buffer.len() {
            return Err(KeyError::invalid_key("Output size exceeds buffer capacity"));
        }
        if salt.len() > self.salt_buffer.len() {
            return Err(KeyError::invalid_key("Salt size exceeds buffer capacity"));
        }

        // Copy salt to internal buffer
        self.salt_buffer[..salt.len()].copy_from_slice(salt);
        let salt_slice = &self.salt_buffer[..salt.len()];

        match self.algorithm {
            KdfAlgorithm::Pbkdf2Sha256 => {
                let iterations = NonZeroU32::new(iterations)
                    .ok_or_else(|| KeyError::invalid_key("PBKDF2 iterations must be non-zero"))?;

                pbkdf2_hmac::<Sha256>(
                    input,
                    salt_slice,
                    iterations.get(),
                    &mut self.buffer[..output_size],
                );
                Ok(&self.buffer[..output_size])
            }
            KdfAlgorithm::Pbkdf2Sha512 => {
                let iterations = NonZeroU32::new(iterations)
                    .ok_or_else(|| KeyError::invalid_key("PBKDF2 iterations must be non-zero"))?;

                pbkdf2_hmac::<Sha512>(
                    input,
                    salt_slice,
                    iterations.get(),
                    &mut self.buffer[..output_size],
                );
                Ok(&self.buffer[..output_size])
            }
            KdfAlgorithm::HkdfSha256 => {
                let hk = Hkdf::<Sha256>::new(Some(salt_slice), input);
                hk.expand(&[], &mut self.buffer[..output_size])
                    .map_err(|e| {
                        KeyError::internal(format!("HKDF-SHA256 expansion failed: {e}"))
                    })?;
                Ok(&self.buffer[..output_size])
            }
            KdfAlgorithm::HkdfSha512 => {
                let hk = Hkdf::<Sha512>::new(Some(salt_slice), input);
                hk.expand(&[], &mut self.buffer[..output_size])
                    .map_err(|e| {
                        KeyError::internal(format!("HKDF-SHA512 expansion failed: {e}"))
                    })?;
                Ok(&self.buffer[..output_size])
            }
            KdfAlgorithm::Argon2id => {
                let params = Params::new(
                    32768, // 32 MB for fast derivation
                    iterations,
                    2, // 2 threads for fast derivation
                    Some(output_size),
                )
                .map_err(|e| KeyError::internal(format!("Invalid Argon2 parameters: {e}")))?;

                let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

                argon2
                    .hash_password_into(input, salt_slice, &mut self.buffer[..output_size])
                    .map_err(|e| {
                        KeyError::internal(format!("Argon2 key derivation failed: {e}"))
                    })?;

                Ok(&self.buffer[..output_size])
            }
        }
    }
}

impl Drop for FastKeyDerivation {
    fn drop(&mut self) {
        // Zeroize sensitive buffers
        self.buffer.zeroize();
        self.salt_buffer.zeroize();
    }
}
