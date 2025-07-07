//! JSON Web Token (JWT) implementation following README.md patterns
//!
//! This module provides JWT functionality with:
//! - HS256 and ES256 algorithms  
//! - Key rotation support
//! - Standard claims handling
//! - True async with channels (no spawn_blocking)
//! - README.md compliant API patterns

// Internal modules - following README.md patterns  
pub mod api;
mod algorithms;
mod error;
mod types;
pub(crate) mod crypto;
mod rotation;

// Public re-exports following README.md patterns
pub use api::*;
pub use error::*;
pub use types::*;

/// Main entry point - README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Master builder for JWT operations - README.md pattern
    pub fn jwt() -> crate::api::JwtMasterBuilder {
        crate::api::JwtMasterBuilder
    }
}

// Direct builder entry point - equivalent to Cryypt::jwt()
pub use api::Jwt;