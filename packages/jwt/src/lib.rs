//! JSON Web Token (JWT) implementation following README.md patterns
//!
//! This module provides JWT functionality with:
//! - HS256 and ES256 algorithms  
//! - Key rotation support
//! - Standard claims handling
//! - True async with channels using fast crypto operations
//! - README.md compliant API patterns

// Internal modules - following README.md patterns
pub(crate) mod algorithms;
pub mod api;
pub(crate) mod crypto;
mod error;
mod rotation;
mod types;

// Public re-exports following README.md patterns
pub use api::{
    AsyncJwtResult, AsyncJwtResultWithError, JwtBuilder, JwtMasterBuilder, get_recommended_key_size,
};
pub use api::{builder, builders, claims, keys, operations, rotator_builder, validation};
pub use error::*;
pub use types::*;

// Re-export common macros and handlers from cryypt_common
pub use cryypt_common::on_result;

/// Main entry point - README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Master builder for JWT operations - README.md pattern
    #[must_use]
    pub fn jwt() -> crate::api::JwtMasterBuilder {
        crate::api::JwtMasterBuilder
    }
}

// Direct builder entry point - equivalent to Cryypt::jwt()
pub use api::Jwt;
