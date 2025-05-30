//! JWT signing algorithm implementations.
//!
//! This module provides implementations of various JWT signing algorithms:
//! - HS256 (HMAC-SHA256) - Symmetric key algorithm
//! - ES256 (ECDSA with P-256) - Asymmetric key algorithm

mod es256;
mod hs256;

pub use es256::Es256Key;
pub use hs256::Hs256Key;
