//! JWT error types following README.md patterns

use std::fmt;

/// JWT operation result type
pub type JwtResult<T> = Result<T, JwtError>;

/// JWT error types
#[derive(Debug, Clone)]
pub enum JwtError {
    /// Invalid JWT format
    InvalidFormat,
    /// Invalid signature
    InvalidSignature,
    /// Token has expired
    Expired,
    /// Token not yet valid
    NotYetValid,
    /// Missing required claim
    MissingClaim(String),
    /// Invalid issuer
    InvalidIssuer,
    /// Invalid audience
    InvalidAudience,
    /// Key generation failed
    KeyGeneration,
    /// Serialization failed
    Serialization,
    /// Cryptographic operation failed
    Crypto,
    /// Task execution failed
    TaskFailed,
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtError::InvalidFormat => write!(f, "Invalid JWT format"),
            JwtError::InvalidSignature => write!(f, "Invalid JWT signature"),
            JwtError::Expired => write!(f, "JWT token has expired"),
            JwtError::NotYetValid => write!(f, "JWT token not yet valid"),
            JwtError::MissingClaim(claim) => write!(f, "Missing required claim: {}", claim),
            JwtError::InvalidIssuer => write!(f, "Invalid JWT issuer"),
            JwtError::InvalidAudience => write!(f, "Invalid JWT audience"),
            JwtError::KeyGeneration => write!(f, "Failed to generate keys"),
            JwtError::Serialization => write!(f, "Failed to serialize/deserialize"),
            JwtError::Crypto => write!(f, "Cryptographic operation failed"),
            JwtError::TaskFailed => write!(f, "Task execution failed"),
        }
    }
}

impl std::error::Error for JwtError {}