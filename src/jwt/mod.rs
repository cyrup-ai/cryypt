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
mod error;
mod claims;
mod validation;
mod traits;
mod algorithms;
mod futures;
mod generator;
mod rotator;
mod revocation;

// Keep the old jwt.rs for now during transition
mod jwt;

// Public re-exports
pub use error::{JwtError, JwtResult};
pub use claims::{Claims, ClaimsBuilder};
pub use validation::ValidationOptions;
pub use traits::{Header, Signer};
pub use algorithms::{Hs256Key, Es256Key};
pub use futures::{TokenGenerationFuture, TokenVerificationFuture, CleanupStartFuture};
pub use generator::Generator;
pub use rotator::Rotator;
pub use revocation::{Revocation, RevokedToken};

// Re-export typestate markers for advanced usage
pub use claims::ts;