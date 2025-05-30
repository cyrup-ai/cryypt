//! JSON Web Token (JWT) implementation with strong typing and security features.
//!
//! This module provides a comprehensive JWT implementation with:
//! - Multiple signing algorithms (HS256, ES256)
//! - Compile-time validated claims builder
//! - Token revocation with automatic cleanup
//! - Key rotation support
//! - Comprehensive validation options
//! - Concrete Future types (no async traits)
//!
//! # Example
//!
//! ```no_run
//! use cryypt::jwt::{ClaimsBuilder, Generator, Hs256Key};
//! use chrono::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a signing key
//! let key = Hs256Key::random();
//! let generator = Generator::new(key);
//!
//! // Build claims with compile-time validation
//! let claims = ClaimsBuilder::new()
//!     .subject("user@example.com")
//!     .expires_in(Duration::hours(24))
//!     .issued_now()
//!     .issuer("my-app")
//!     .build();
//!
//! // Generate token
//! let token = generator.token(&claims).await?;
//!
//! // Verify token
//! let verified = generator.verify(&token).await?;
//! assert_eq!(verified.sub, "user@example.com");
//! # Ok(())
//! # }
//! ```

// Internal modules
mod algorithms;
mod claims;
mod error;
mod futures;
mod generator;
mod revocation;
mod rotator;
mod traits;
mod validation;

// Keep the old jwt.rs for now during transition
mod jwt;

// Public re-exports
pub use algorithms::{Es256Key, Hs256Key};
pub use claims::{Claims, ClaimsBuilder};
pub use error::{JwtError, JwtResult};
pub use futures::{CleanupStartFuture, TokenGenerationFuture, TokenVerificationFuture};
pub use generator::Generator;
pub use revocation::{Revocation, RevokedToken};
pub use rotator::Rotator;
pub use traits::{Header, Signer};
pub use validation::ValidationOptions;

// Re-export typestate markers for advanced usage
pub use claims::ts;
