//! Core JWT traits and types.

use crate::error::JwtResult;
use serde::{Deserialize, Serialize};

/// JWT header structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    /// Algorithm used for signing.
    pub alg: String,
    /// Token type (always "JWT").
    pub typ: &'static str,
    /// Key ID hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl Header {
    /// Create a new header with the given algorithm and optional key ID.
    pub fn new(alg: &'static str, kid: Option<String>) -> Self {
        Self {
            alg: alg.to_string(),
            typ: "JWT",
            kid,
        }
    }
}

/// Signing algorithm interface.
///
/// This trait defines the contract for JWT signing algorithms.
/// Implementations must be thread-safe (Send + Sync).
pub trait Signer: Send + Sync + 'static {
    /// Sign opaque payload → token (base64url header.payload.signature).
    fn sign(&self, header: &Header, payload: &str) -> JwtResult<String>;

    /// Verify token & return payload.
    fn verify(&self, token: &str) -> JwtResult<String>;

    /// Header `alg` value.
    fn alg(&self) -> &'static str;

    /// Key ID.
    fn kid(&self) -> Option<String>;
}

/// Implementation of Signer for Arc<T> to allow shared ownership.
impl<T: Signer> Signer for std::sync::Arc<T> {
    fn sign(&self, header: &Header, payload: &str) -> JwtResult<String> {
        (**self).sign(header, payload)
    }

    fn verify(&self, token: &str) -> JwtResult<String> {
        (**self).verify(token)
    }

    fn alg(&self) -> &'static str {
        (**self).alg()
    }

    fn kid(&self) -> Option<String> {
        (**self).kid()
    }
}
