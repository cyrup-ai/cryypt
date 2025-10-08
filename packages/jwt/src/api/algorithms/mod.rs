//! JWT Algorithms Module
//!
//! This module provides the main algorithms for JWT signing and verification.
//! It has been decomposed from a single large file into multiple focused modules.

mod core;
mod ecdsa;
mod hmac;
pub mod rsa;
mod utils;

// Re-export the main API functions
pub(crate) use core::{sign_jwt, verify_jwt};
