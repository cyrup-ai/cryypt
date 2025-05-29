//! Master key builder

/// Builder for master key
pub struct MasterKeyBuilder;

impl MasterKeyBuilder {
    /// Derive from passphrase
    pub fn from_passphrase(passphrase: &str) -> PassphraseMasterKey {
        PassphraseMasterKey {
            passphrase: passphrase.to_string(),
        }
    }
    
    /// From raw bytes
    pub fn from_bytes(key: [u8; 32]) -> RawMasterKey {
        RawMasterKey { key }
    }
    
    /// From environment variable
    pub fn from_env(var_name: &str) -> EnvMasterKey {
        EnvMasterKey {
            var_name: var_name.to_string(),
        }
    }
}

/// Trait for types that can provide a master key
pub trait MasterKeyProvider: Send + Sync {
    /// Resolve to the actual master key
    fn resolve(&self) -> [u8; 32];
}

pub struct PassphraseMasterKey {
    passphrase: String,
}

impl MasterKeyProvider for PassphraseMasterKey {
    fn resolve(&self) -> [u8; 32] {
        // Derive key from passphrase using Argon2 or similar
        // For now, just hash it
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.passphrase.hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&hash.to_le_bytes());
        key[8..16].copy_from_slice(&hash.to_be_bytes());
        key[16..24].copy_from_slice(&hash.to_le_bytes());
        key[24..32].copy_from_slice(&hash.to_be_bytes());
        key
    }
}

pub struct RawMasterKey {
    key: [u8; 32],
}

impl MasterKeyProvider for RawMasterKey {
    fn resolve(&self) -> [u8; 32] {
        self.key
    }
}

pub struct EnvMasterKey {
    var_name: String,
}

impl MasterKeyProvider for EnvMasterKey {
    fn resolve(&self) -> [u8; 32] {
        // Read from env var and decode
        let value = std::env::var(&self.var_name)
            .expect("Master key env var not found");
        
        // Decode from hex or base64
        // For now, just hash it
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&hash.to_le_bytes());
        key[8..16].copy_from_slice(&hash.to_be_bytes());
        key[16..24].copy_from_slice(&hash.to_le_bytes());
        key[24..32].copy_from_slice(&hash.to_be_bytes());
        key
    }
}