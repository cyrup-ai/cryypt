//! Certificate validation and generation module
//!
//! This module provides a clean interface for certificate operations:
//! - Certificate validation with security checks
//! - Certificate generation with CA and wildcard support
//! - Common types for certificate operations

// Public modules
pub mod generation;
pub mod types;
pub mod validation;

// Re-export main types for public API compatibility
pub use generation::{CertificateGenerator, CertificateGeneratorWithDomain};
pub use types::InputSource;
pub use validation::{CertificateValidator, CertificateValidatorWithInput};

/// Main certificate builder entry point
#[derive(Debug, Clone)]
pub struct CertificateBuilder;

impl CertificateBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Create a certificate validator
    pub fn validator(self) -> CertificateValidator {
        CertificateValidator::new()
    }

    /// Create a certificate generator
    pub fn generator(self) -> CertificateGenerator {
        CertificateGenerator::new()
    }
}
