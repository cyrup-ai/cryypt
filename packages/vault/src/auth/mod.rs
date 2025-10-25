//! Authentication module for vault operations
//!
//! This module provides JWT-based authentication for secure vault access.
//! All vault operations require valid JWT tokens for authentication.

pub mod jwt_handler;
pub mod key_converter;
pub mod rsa_key_manager;

pub use jwt_handler::{JwtHandler, VaultJwtClaims, extract_jwt_from_env};
pub use key_converter::{pkcs1_to_pkcs8, pkcs1_public_to_spki, private_pkcs1_to_public_spki};
pub use rsa_key_manager::RsaKeyManager;
