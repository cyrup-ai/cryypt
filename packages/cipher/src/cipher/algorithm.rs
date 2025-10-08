//! Cipher algorithm definitions and metadata

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Supported cipher algorithms
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CipherAlgorithm {
    /// AES-256-GCM (Advanced Encryption Standard with Galois/Counter Mode)
    ///
    /// - 256-bit key size
    /// - 96-bit nonce
    /// - 128-bit authentication tag
    /// - Hardware acceleration on modern CPUs
    #[serde(rename = "aes256gcm")]
    Aes256Gcm,

    /// ChaCha20-Poly1305 (`ChaCha20` stream cipher with Poly1305 MAC)
    ///
    /// - 256-bit key size
    /// - 96-bit nonce
    /// - 128-bit authentication tag
    /// - Constant-time implementation
    #[serde(rename = "chacha20poly1305")]
    ChaCha20Poly1305,

    /// Cascade cipher construction
    ///
    /// Applies multiple ciphers in sequence for defense-in-depth:
    /// 1. First layer: AES-256-GCM encryption
    /// 2. Second layer: ChaCha20-Poly1305 encryption
    /// 3. HMAC-SHA3-512 for additional integrity verification
    #[serde(rename = "cascade")]
    Cascade,

    /// Custom cipher chain
    ///
    /// Used when ciphers are chained with the builder API
    #[serde(rename = "custom")]
    Custom(String),
}

impl CipherAlgorithm {
    /// Get the human-readable name of the algorithm
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Aes256Gcm => "AES-256-GCM".to_string(),
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305".to_string(),
            Self::Cascade => "Cascade (AES + ChaCha)".to_string(),
            Self::Custom(chain) => chain.clone(),
        }
    }

    /// Get the key size in bytes required for this algorithm
    #[must_use]
    pub fn key_size(&self) -> usize {
        match self {
            Self::Cascade => 64,                                              // 2x 256 bits
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::Custom(_) => 32, // 256 bits / varies, default to 32
        }
    }

    /// Get the nonce size in bytes required for this algorithm
    #[must_use]
    pub fn nonce_size(&self) -> usize {
        match self {
            Self::Cascade => 24,                                              // 2x 96 bits
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::Custom(_) => 12, // 96 bits / varies, default to 12
        }
    }

    /// Get the authentication tag size in bytes
    #[must_use]
    pub fn tag_size(&self) -> usize {
        match self {
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::Cascade | Self::Custom(_) => 16, // 128 bits for all
        }
    }

    /// Check if this algorithm is available
    #[must_use]
    pub fn is_available(&self) -> bool {
        // All algorithms are available now that features are removed
        true
    }

    /// Get all available algorithms
    #[must_use]
    pub fn available_algorithms() -> Vec<Self> {
        vec![Self::Aes256Gcm, Self::ChaCha20Poly1305, Self::Cascade]
    }

    /// Get the recommended algorithm
    #[must_use]
    pub fn recommended() -> Option<Self> {
        // Prefer cascade for defense in depth
        Some(Self::Cascade)
    }

    /// Get all standard algorithm variants (excludes Custom)
    #[must_use]
    pub fn all_standard() -> &'static [Self] {
        &[Self::Aes256Gcm, Self::ChaCha20Poly1305, Self::Cascade]
    }
}

impl fmt::Display for CipherAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for CipherAlgorithm {
    type Err = crate::CryptError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aes" | "aes256" | "aes256gcm" | "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha" | "chacha20" | "chacha20poly1305" | "chacha20-poly1305" => {
                Ok(Self::ChaCha20Poly1305)
            }
            "cascade" | "dual" | "dual-layer" => Ok(Self::Cascade),
            _ => Err(crate::CryptError::UnsupportedAlgorithm(s.to_string())),
        }
    }
}

impl Default for CipherAlgorithm {
    fn default() -> Self {
        Self::recommended().unwrap_or(Self::Aes256Gcm)
    }
}
