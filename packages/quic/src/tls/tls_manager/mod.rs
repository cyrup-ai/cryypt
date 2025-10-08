//! TLS Manager module
//!
//! This module provides comprehensive TLS connection management with OCSP validation,
//! CRL checking, certificate validation, and enterprise security features.
//!
//! The module is decomposed into focused, single-responsibility components:
//! - `config`: TLS configuration structures and presets
//! - `manager`: Core TLS connection manager implementation
//! - `cache`: Pre-validation cache for async certificate validation
//! - `verifier`: Enterprise certificate verifier with OCSP/CRL support

pub mod cache;
pub mod config;
pub mod manager;
pub mod verifier;

// Re-export main types for backward compatibility
pub use config::TlsConfig;
pub use manager::TlsManager;
