use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::config::VaultConfig;
use crate::core::VaultValue;
use crate::error::VaultResult;
use cryypt_cipher::CipherAlgorithm;

#[derive(Clone)]
pub struct LocalVaultProvider {
    pub(crate) config: VaultConfig,
    pub(crate) data: Arc<Mutex<HashMap<String, VaultValue>>>,
    pub(crate) key: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
    pub(crate) cipher_algorithm: CipherAlgorithm,
}

impl LocalVaultProvider {
    pub fn new(config: VaultConfig) -> VaultResult<Self> {
        // Use Cascade algorithm for highest security (defense-in-depth)
        let cipher_algorithm = CipherAlgorithm::Cascade;

        super::storage::ensure_salt_file(&config)?;

        Ok(Self {
            config,
            data: Arc::new(Mutex::new(HashMap::new())),
            key: Arc::new(Mutex::new(None)),
            cipher_algorithm,
        })
    }

    /// Create a provider with ChaCha20Poly1305 for faster but still secure encryption
    pub fn new_with_chacha(config: VaultConfig) -> VaultResult<Self> {
        // Use ChaCha20Poly1305 for faster encryption
        let cipher_algorithm = CipherAlgorithm::ChaCha20Poly1305;

        super::storage::ensure_salt_file(&config)?;

        Ok(Self {
            config,
            data: Arc::new(Mutex::new(HashMap::new())),
            key: Arc::new(Mutex::new(None)),
            cipher_algorithm,
        })
    }

    pub fn with_algorithm(config: VaultConfig, algorithm: CipherAlgorithm) -> Self {
        Self {
            config,
            data: Arc::new(Mutex::new(HashMap::new())),
            key: Arc::new(Mutex::new(None)),
            cipher_algorithm: algorithm,
        }
    }

    pub fn is_locked(&self) -> bool {
        // Still synchronous as it checks internal state quickly
        self.key
            .try_lock()
            .map(|guard| guard.is_none())
            .unwrap_or(true)
    }

    pub fn supports_encryption(&self) -> bool {
        true
    }

    pub fn encryption_type(&self) -> &str {
        match self.cipher_algorithm {
            CipherAlgorithm::Aes256Gcm => "AES-256-GCM",
            CipherAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            CipherAlgorithm::Cascade => "Cascade (AES + ChaCha)",
            CipherAlgorithm::Custom(ref name) => name,
        }
    }

    pub fn supports_defense_in_depth(&self) -> bool {
        // Only true if using Cascade algorithm
        matches!(self.cipher_algorithm, CipherAlgorithm::Cascade)
    }

    pub fn name(&self) -> &str {
        // Identify the provider by name
        "LocalVaultProvider"
    }
}