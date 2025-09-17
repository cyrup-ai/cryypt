//! JWT error types following README.md patterns

use std::fmt;

/// JWT operation result type
pub type JwtResult<T> = Result<T, JwtError>;

/// JWT error types
#[derive(Debug, Clone)]
pub enum JwtError {
    /// Invalid JWT format
    InvalidToken(String),
    /// Invalid signature
    InvalidSignature,
    /// Token has expired
    TokenExpired,
    /// Token not yet valid
    TokenNotYetValid,
    /// Missing required claim
    MissingClaim(String),
    /// Invalid issuer
    InvalidIssuer,
    /// Invalid audience
    InvalidAudience,
    /// Key error
    InvalidKey(String),
    /// Missing key
    MissingKey(String),
    /// Unsupported algorithm
    UnsupportedAlgorithm(String),
    /// Serialization failed
    Serialization(String),
    /// Cryptographic operation failed
    SigningError(String),
    /// Internal error
    Internal(String),
    /// Invalid claims configuration
    InvalidClaims(String),
    /// Cryptographic operation failed (alias for `SigningError`)
    Crypto,
    /// Background task failed
    TaskFailed,
    /// Invalid format (alias for `InvalidToken`)
    InvalidFormat,
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtError::InvalidToken(msg) => write!(f, "Invalid JWT token: {msg}"),
            JwtError::InvalidSignature => write!(f, "Invalid JWT signature"),
            JwtError::TokenExpired => write!(f, "JWT token has expired"),
            JwtError::TokenNotYetValid => write!(f, "JWT token not yet valid"),
            JwtError::MissingClaim(claim) => write!(f, "Missing required claim: {claim}"),
            JwtError::InvalidIssuer => write!(f, "Invalid JWT issuer"),
            JwtError::InvalidAudience => write!(f, "Invalid JWT audience"),
            JwtError::InvalidKey(msg) => write!(f, "Invalid key: {msg}"),
            JwtError::MissingKey(msg) => write!(f, "Missing key: {msg}"),
            JwtError::UnsupportedAlgorithm(alg) => write!(f, "Unsupported algorithm: {alg}"),
            JwtError::Serialization(msg) => write!(f, "Serialization error: {msg}"),
            JwtError::SigningError(msg) => write!(f, "Signing error: {msg}"),
            JwtError::Internal(msg) => write!(f, "Internal error: {msg}"),
            JwtError::InvalidClaims(msg) => write!(f, "Invalid claims: {msg}"),
            JwtError::Crypto => write!(f, "Cryptographic operation failed"),
            JwtError::TaskFailed => write!(f, "Background task failed"),
            JwtError::InvalidFormat => write!(f, "Invalid format"),
        }
    }
}

impl std::error::Error for JwtError {}

impl JwtError {
    /// Create an invalid token error
    #[inline]
    #[must_use]
    pub fn invalid_token(msg: &str) -> Self {
        JwtError::InvalidToken(msg.to_string())
    }

    /// Create an invalid signature error
    #[inline]
    #[must_use]
    pub fn invalid_signature() -> Self {
        JwtError::InvalidSignature
    }

    /// Create a token expired error
    #[inline]
    #[must_use]
    pub fn token_expired() -> Self {
        JwtError::TokenExpired
    }

    /// Create a token not yet valid error
    #[inline]
    #[must_use]
    pub fn token_not_yet_valid() -> Self {
        JwtError::TokenNotYetValid
    }

    /// Create a missing claim error
    #[inline]
    #[must_use]
    pub fn missing_claim(claim: &str) -> Self {
        JwtError::MissingClaim(claim.to_string())
    }

    /// Create an invalid key error
    #[inline]
    #[must_use]
    pub fn invalid_key(msg: &str) -> Self {
        JwtError::InvalidKey(msg.to_string())
    }

    /// Create a missing key error
    #[inline]
    #[must_use]
    pub fn missing_key(msg: &str) -> Self {
        JwtError::MissingKey(msg.to_string())
    }

    /// Create an unsupported algorithm error
    #[inline]
    #[must_use]
    pub fn unsupported_algorithm(alg: &str) -> Self {
        JwtError::UnsupportedAlgorithm(alg.to_string())
    }

    /// Create a serialization error
    #[inline]
    #[must_use]
    pub fn serialization(msg: &str) -> Self {
        JwtError::Serialization(msg.to_string())
    }

    /// Create a signing error
    #[inline]
    #[must_use]
    pub fn signing_error(msg: &str) -> Self {
        JwtError::SigningError(msg.to_string())
    }

    /// Create an internal error
    #[inline]
    #[must_use]
    pub fn internal(msg: &str) -> Self {
        JwtError::Internal(msg.to_string())
    }

    /// Create an invalid claims error
    #[inline]
    #[must_use]
    pub fn invalid_claims(msg: &str) -> Self {
        JwtError::InvalidClaims(msg.to_string())
    }
}
