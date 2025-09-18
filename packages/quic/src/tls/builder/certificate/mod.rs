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
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Create a certificate validator
    #[must_use]
    pub fn validator(self) -> CertificateValidator {
        CertificateValidator::new()
    }

    /// Create a certificate generator
    #[must_use]
    pub fn generator(self) -> CertificateGenerator {
        CertificateGenerator::new()
    }
}
