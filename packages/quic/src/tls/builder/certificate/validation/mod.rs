//! Certificate validation module
//!
//! This module provides certificate validation operations decomposed into:
//! - basic: Basic validation and input handling
//! - security: Security validation (OCSP, CRL, chain)
//! - domain: Domain validation operations

pub mod basic;
pub mod domain;
pub mod security;

// Re-export main validation types
pub use basic::{CertificateValidator, CertificateValidatorWithInput};
