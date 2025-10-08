//! Master key provider implementations
//!
//! Contains the `MasterKeyProvider` trait and all provider types for different key sources.

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use hex;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Trait for types that can provide a master key
pub trait MasterKeyProvider: Send + Sync {
    /// Resolve to the actual master key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key derivation fails
    /// - Invalid key material is provided
    /// - Cryptographic operations fail
    fn resolve(&self) -> crate::Result<[u8; 32]>;
}

/// Master key derived from a user passphrase
pub struct PassphraseMasterKey {
    pub(crate) passphrase: Zeroizing<String>,
}

impl MasterKeyProvider for PassphraseMasterKey {
    fn resolve(&self) -> crate::Result<[u8; 32]> {
        // Use Argon2 for secure key derivation from passphrase
        let argon2 = Argon2::default();

        // Generate deterministic salt from passphrase hash for security
        // This ensures same passphrase = same key, but different passphrases = different salts
        let mut hasher = Sha256::new();
        hasher.update("passphrasesaltv1:".as_bytes()); // Version prefix for future compatibility (no underscores)
        hasher.update(self.passphrase.as_bytes());
        let salt_bytes = hasher.finalize();

        // Use first 22 bytes for salt (Argon2 requirement) - encode as base64 without padding
        let salt_b64 = STANDARD_NO_PAD.encode(&salt_bytes[..22]);
        let salt = SaltString::from_b64(&salt_b64)
            .map_err(|e| crate::KeyError::InvalidKey(format!("Invalid salt: {e}")))?;

        let password_hash = argon2
            .hash_password(self.passphrase.as_bytes(), &salt)
            .map_err(|e| crate::KeyError::InvalidKey(format!("Password hashing failed: {e}")))?;

        let hash_output = password_hash
            .hash
            .ok_or_else(|| crate::KeyError::InvalidKey("No hash generated".into()))?;
        let hash_bytes = hash_output.as_bytes();

        if hash_bytes.len() < 32 {
            return Err(crate::KeyError::InvalidKey("Hash too short".into()));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);
        Ok(key)
    }
}

/// Master key using raw key material directly
pub struct RawMasterKey {
    pub(crate) key: [u8; 32],
}

impl MasterKeyProvider for RawMasterKey {
    fn resolve(&self) -> crate::Result<[u8; 32]> {
        Ok(self.key)
    }
}

/// Master key loaded from environment variables
pub struct EnvMasterKey {
    pub(crate) var_name: String,
}

impl MasterKeyProvider for EnvMasterKey {
    fn resolve(&self) -> crate::Result<[u8; 32]> {
        let value = std::env::var(&self.var_name)
            .map_err(|_| crate::KeyError::InvalidKey("Master key env var not found".into()))?;

        // Try to decode from hex first
        if let Ok(decoded) = hex::decode(&value)
            && decoded.len() == 32
        {
            let mut key = [0u8; 32];
            key.copy_from_slice(&decoded);
            return Ok(key);
        }

        // Try to decode from base64
        if let Ok(decoded) = STANDARD.decode(&value)
            && decoded.len() == 32
        {
            let mut key = [0u8; 32];
            key.copy_from_slice(&decoded);
            return Ok(key);
        }

        // If neither hex nor base64 worked, derive from the string using Argon2
        let argon2 = Argon2::default();

        // Generate deterministic salt from environment variable content hash for security
        // This ensures same env var = same key, but different env vars = different salts
        let mut hasher = Sha256::new();
        hasher.update("envvarsaltv1:".as_bytes()); // Version prefix for future compatibility (no underscores)
        hasher.update(value.as_bytes());
        let salt_bytes = hasher.finalize();

        // Use first 22 bytes for salt (Argon2 requirement) - encode as base64 without padding
        let salt_b64 = STANDARD_NO_PAD.encode(&salt_bytes[..22]);
        let salt = SaltString::from_b64(&salt_b64)
            .map_err(|e| crate::KeyError::InvalidKey(format!("Invalid salt: {e}")))?;

        let password_hash = argon2
            .hash_password(value.as_bytes(), &salt)
            .map_err(|e| crate::KeyError::InvalidKey(format!("Password hashing failed: {e}")))?;

        let hash_output = password_hash
            .hash
            .ok_or_else(|| crate::KeyError::InvalidKey("No hash generated".into()))?;
        let hash_bytes = hash_output.as_bytes();

        if hash_bytes.len() < 32 {
            return Err(crate::KeyError::InvalidKey("Hash too short".into()));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);
        Ok(key)
    }
}
