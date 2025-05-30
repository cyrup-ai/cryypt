//! Algorithm enums for post-quantum cryptography

use serde::{Deserialize, Serialize};
use std::fmt;

/// Key Encapsulation Mechanism (KEM) algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KemAlgorithm {
    /// ML-KEM-512 (NIST security level 1, ~128-bit security)
    /// Formerly known as Kyber512
    #[serde(rename = "ml-kem-512")]
    MlKem512,
    
    /// ML-KEM-768 (NIST security level 3, ~192-bit security)
    /// Formerly known as Kyber768
    #[serde(rename = "ml-kem-768")]
    MlKem768,
    
    /// ML-KEM-1024 (NIST security level 5, ~256-bit security)
    /// Formerly known as Kyber1024
    #[serde(rename = "ml-kem-1024")]
    MlKem1024,
}

impl KemAlgorithm {
    /// Get the security level of the algorithm
    pub fn security_level(&self) -> u8 {
        match self {
            Self::MlKem512 => 1,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 5,
        }
    }
    
    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }
    
    /// Get the secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }
    
    /// Get the ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }
    
    /// Get the shared secret size in bytes (always 32 for ML-KEM)
    pub fn shared_secret_size(&self) -> usize {
        32
    }
}

impl fmt::Display for KemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MlKem512 => write!(f, "ML-KEM-512"),
            Self::MlKem768 => write!(f, "ML-KEM-768"),
            Self::MlKem1024 => write!(f, "ML-KEM-1024"),
        }
    }
}

impl Default for KemAlgorithm {
    fn default() -> Self {
        // Default to ML-KEM-768 for balanced security/performance
        Self::MlKem768
    }
}

/// Digital signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// ML-DSA-44 (NIST security level 2)
    /// Formerly known as Dilithium2
    #[serde(rename = "ml-dsa-44")]
    MlDsa44,
    
    /// ML-DSA-65 (NIST security level 3)
    /// Formerly known as Dilithium3
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
    
    /// ML-DSA-87 (NIST security level 5)
    /// Formerly known as Dilithium5
    #[serde(rename = "ml-dsa-87")]
    MlDsa87,
    
    /// FALCON-512 (NIST security level 1)
    #[serde(rename = "falcon-512")]
    Falcon512,
    
    /// FALCON-1024 (NIST security level 5)
    #[serde(rename = "falcon-1024")]
    Falcon1024,
    
    /// SPHINCS+-SHA256-128f-simple (NIST security level 1, fast)
    #[serde(rename = "sphincs-sha256-128f-simple")]
    SphincsShaSha256_128fSimple,
    
    /// SPHINCS+-SHA256-128s-simple (NIST security level 1, small)
    #[serde(rename = "sphincs-sha256-128s-simple")]
    SphincsShaSha256_128sSimple,
    
    /// SPHINCS+-SHA256-192f-simple (NIST security level 3, fast)
    #[serde(rename = "sphincs-sha256-192f-simple")]
    SphincsShaSha256_192fSimple,
    
    /// SPHINCS+-SHA256-192s-simple (NIST security level 3, small)
    #[serde(rename = "sphincs-sha256-192s-simple")]
    SphincsShaSha256_192sSimple,
    
    /// SPHINCS+-SHA256-256f-simple (NIST security level 5, fast)
    #[serde(rename = "sphincs-sha256-256f-simple")]
    SphincsShaSha256_256fSimple,
    
    /// SPHINCS+-SHA256-256s-simple (NIST security level 5, small)
    #[serde(rename = "sphincs-sha256-256s-simple")]
    SphincsShaSha256_256sSimple,
}

impl SignatureAlgorithm {
    /// Get the security level of the algorithm
    pub fn security_level(&self) -> u8 {
        match self {
            Self::MlDsa44 => 2,
            Self::MlDsa65 => 3,
            Self::MlDsa87 => 5,
            Self::Falcon512 => 1,
            Self::Falcon1024 => 5,
            Self::SphincsShaSha256_128fSimple | Self::SphincsShaSha256_128sSimple => 1,
            Self::SphincsShaSha256_192fSimple | Self::SphincsShaSha256_192sSimple => 3,
            Self::SphincsShaSha256_256fSimple | Self::SphincsShaSha256_256sSimple => 5,
        }
    }
    
    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
            Self::Falcon512 => 897,
            Self::Falcon1024 => 1793,
            Self::SphincsShaSha256_128fSimple => 32,
            Self::SphincsShaSha256_128sSimple => 32,
            Self::SphincsShaSha256_192fSimple => 48,
            Self::SphincsShaSha256_192sSimple => 48,
            Self::SphincsShaSha256_256fSimple => 64,
            Self::SphincsShaSha256_256sSimple => 64,
        }
    }
    
    /// Get the secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2528,
            Self::MlDsa65 => 4000,
            Self::MlDsa87 => 4864,
            Self::Falcon512 => 1281,
            Self::Falcon1024 => 2305,
            Self::SphincsShaSha256_128fSimple => 64,
            Self::SphincsShaSha256_128sSimple => 64,
            Self::SphincsShaSha256_192fSimple => 96,
            Self::SphincsShaSha256_192sSimple => 96,
            Self::SphincsShaSha256_256fSimple => 128,
            Self::SphincsShaSha256_256sSimple => 128,
        }
    }
    
    /// Get the maximum signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3293,
            Self::MlDsa87 => 4595,
            Self::Falcon512 => 666,
            Self::Falcon1024 => 1280,
            Self::SphincsShaSha256_128fSimple => 17088,
            Self::SphincsShaSha256_128sSimple => 7856,
            Self::SphincsShaSha256_192fSimple => 35664,
            Self::SphincsShaSha256_192sSimple => 16224,
            Self::SphincsShaSha256_256fSimple => 49856,
            Self::SphincsShaSha256_256sSimple => 29792,
        }
    }
    
    /// Check if this is a "fast" variant (for SPHINCS+)
    pub fn is_fast_variant(&self) -> bool {
        matches!(
            self,
            Self::SphincsShaSha256_128fSimple
                | Self::SphincsShaSha256_192fSimple
                | Self::SphincsShaSha256_256fSimple
        )
    }
    
    /// Check if this is a "small" variant (for SPHINCS+)
    pub fn is_small_variant(&self) -> bool {
        matches!(
            self,
            Self::SphincsShaSha256_128sSimple
                | Self::SphincsShaSha256_192sSimple
                | Self::SphincsShaSha256_256sSimple
        )
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MlDsa44 => write!(f, "ML-DSA-44"),
            Self::MlDsa65 => write!(f, "ML-DSA-65"),
            Self::MlDsa87 => write!(f, "ML-DSA-87"),
            Self::Falcon512 => write!(f, "FALCON-512"),
            Self::Falcon1024 => write!(f, "FALCON-1024"),
            Self::SphincsShaSha256_128fSimple => write!(f, "SPHINCS+-SHA256-128f-simple"),
            Self::SphincsShaSha256_128sSimple => write!(f, "SPHINCS+-SHA256-128s-simple"),
            Self::SphincsShaSha256_192fSimple => write!(f, "SPHINCS+-SHA256-192f-simple"),
            Self::SphincsShaSha256_192sSimple => write!(f, "SPHINCS+-SHA256-192s-simple"),
            Self::SphincsShaSha256_256fSimple => write!(f, "SPHINCS+-SHA256-256f-simple"),
            Self::SphincsShaSha256_256sSimple => write!(f, "SPHINCS+-SHA256-256s-simple"),
        }
    }
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        // Default to ML-DSA-65 for balanced security/performance
        Self::MlDsa65
    }
}