//! Certificate validation module
//!
//! This module provides certificate validation operations decomposed into:
//! - basic: Basic validation and input handling
//! - security: Security validation (OCSP, CRL, chain)
//! - domain: Domain validation operations

pub mod basic;
pub mod security;
pub mod domain;

// Re-export main validation types
pub use basic::{CertificateValidator, CertificateValidatorWithInput};