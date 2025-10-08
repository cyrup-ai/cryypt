//! Authentication module for vault operations
//!
//! This module provides JWT-based authentication for secure vault access.
//! All vault operations require valid JWT tokens for authentication.

pub mod jwt_handler;

pub use jwt_handler::{JwtHandler, VaultJwtClaims, extract_jwt_from_env};
