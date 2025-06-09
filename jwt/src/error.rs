//! JWT error types and results.

use thiserror::Error;

/// JWT error types.
#[derive(Debug, Error)]
pub enum JwtError {
    /// Signing / verification failure.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Invalid token format.
    #[error("invalid token")]
    Malformed,
    /// Token expired.
    #[error("token expired")]
    Expired,
    /// Token not yet valid.
    #[error("token not yet valid")]
    NotYetValid,
    /// Invalid signature.
    #[error("invalid signature")]
    InvalidSignature,
    /// Revoked token.
    #[error("revoked token")]
    Revoked,
    /// Algorithm mismatch.
    #[error("algorithm mismatch: expected {expected}, got {got}")]
    AlgorithmMismatch {
        /// Expected algorithm
        expected: String,
        /// Actual algorithm in token
        got: String,
    },
    /// Missing required claim.
    #[error("missing required claim: {0}")]
    MissingClaim(String),
    /// Invalid audience.
    #[error("invalid audience")]
    InvalidAudience,
    /// Invalid issuer.
    #[error("invalid issuer")]
    InvalidIssuer,
    /// Task join error.
    #[error("task join error")]
    TaskJoinError,
}

/// Result alias for JWT operations.
pub type JwtResult<T> = Result<T, JwtError>;
