//! Master key provider implementations
//!
//! Contains the MasterKeyProvider trait and all provider types for different key sources.

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD, Engine};
use hex;
use zeroize::Zeroizing;

/// Trait for types that can provide a master key
pub trait MasterKeyProvider: Send + Sync {
    /// Resolve to the actual master key
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

        // Use a fixed salt for deterministic key derivation
        // In production, you might want configurable salts
        let salt = SaltString::from_b64("YourFixedSaltHere1234567890")
            .map_err(|e| crate::KeyError::InvalidKey(format!("Invalid salt: {}", e)))?;

        let password_hash = argon2
            .hash_password(self.passphrase.as_bytes(), &salt)
            .map_err(|e| crate::KeyError::InvalidKey(format!("Password hashing failed: {}", e)))?;

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
        if let Ok(decoded) = hex::decode(&value) {
            if decoded.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded);
                return Ok(key);
            }
        }

        // Try to decode from base64
        if let Ok(decoded) = STANDARD.decode(&value) {
            if decoded.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded);
                return Ok(key);
            }
        }

        // If neither hex nor base64 worked, derive from the string using Argon2
        let argon2 = Argon2::default();
        let salt = SaltString::from_b64("EnvVarSaltHere1234567890123")
            .map_err(|e| crate::KeyError::InvalidKey(format!("Invalid salt: {}", e)))?;

        let password_hash = argon2
            .hash_password(value.as_bytes(), &salt)
            .map_err(|e| crate::KeyError::InvalidKey(format!("Password hashing failed: {}", e)))?;

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