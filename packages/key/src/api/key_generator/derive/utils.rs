//! Key Derivation Utility Functions
//!
//! This module provides utility functions for key derivation operations
//! including constant-time comparison and automatic parameter selection.

use super::config::{KdfAlgorithm, KdfConfig};
use super::core::KeyDerivation;
use crate::KeyError;
use zeroize::Zeroizing;

/// Constant-time key comparison for derived keys
/// Prevents timing attacks when comparing derived keys
#[must_use]
#[inline]
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Secure key derivation with automatic parameter selection
/// Chooses optimal parameters based on available system resources
///
/// # Errors
///
/// Returns an error if:
/// - The key derivation operation fails with the selected algorithm
/// - Invalid parameters are provided for the chosen KDF
/// - System resources are insufficient for the operation
pub async fn derive_key_auto(
    input: &[u8],
    salt: &[u8],
    output_size: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    // Auto-select algorithm based on system capabilities
    let algorithm = if cfg!(target_arch = "x86_64") || cfg!(target_arch = "aarch64") {
        KdfAlgorithm::Argon2id // Use Argon2id on modern architectures
    } else {
        KdfAlgorithm::Pbkdf2Sha256 // Fallback to PBKDF2 on other architectures
    };

    let config = match algorithm {
        KdfAlgorithm::Argon2id => KdfConfig {
            algorithm,
            iterations: 3,
            memory_cost: 65536, // 64 MB
            parallelism: u32::try_from(num_cpus::get().min(8)).unwrap_or(8),
            salt_size: salt.len(),
            output_size,
        },
        KdfAlgorithm::Pbkdf2Sha256 | KdfAlgorithm::Pbkdf2Sha512 => KdfConfig {
            algorithm,
            iterations: 600_000,
            memory_cost: 0,
            parallelism: 1,
            salt_size: salt.len(),
            output_size,
        },
        KdfAlgorithm::HkdfSha256 | KdfAlgorithm::HkdfSha512 => KdfConfig {
            algorithm,
            iterations: 1,  // HKDF doesn't use iterations
            memory_cost: 0, // HKDF doesn't use memory cost
            parallelism: 1, // HKDF doesn't use parallelism
            salt_size: salt.len(),
            output_size,
        },
    };

    let kdf = KeyDerivation::new(config).with_salt(salt.to_vec());
    let key = kdf.derive_key(input)?;
    Ok(Zeroizing::new(key))
}
