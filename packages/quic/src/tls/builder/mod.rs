//! TLS Builder Module
//!
//! Provides fluent, immutable builders for TLS certificate operations including:
//! - Certificate Authority creation and loading
//! - Certificate validation and generation
//! - Structured response objects

pub mod authority;
pub mod certificate;
pub mod responses;

// Re-export main types for easy access
pub use authority::{
    AuthorityBuilder, AuthorityFilesystemBuilder, AuthorityKeychainBuilder, AuthorityRemoteBuilder,
    CertificateAuthority,
};
pub use certificate::{
    CertificateBuilder, CertificateGenerator, CertificateGeneratorWithDomain, CertificateValidator,
    CertificateValidatorWithInput,
};
pub use responses::{
    CertificateAuthorityResponse, CertificateGenerationResponse, CertificateInfo,
    CertificateValidationResponse, ValidationSummary,
};

/// Main entry point for TLS operations
pub struct Tls;

impl Tls {
    /// Create or load a certificate authority
    #[must_use]
    pub fn authority(name: &str) -> AuthorityBuilder {
        AuthorityBuilder::new(name)
    }

    /// Work with certificates (validate or generate)
    #[must_use]
    pub fn certificate() -> CertificateBuilder {
        CertificateBuilder::new()
    }
}
