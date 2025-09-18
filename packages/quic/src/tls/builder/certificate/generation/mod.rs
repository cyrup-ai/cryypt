//! Certificate generation module  
//!
//! This module provides certificate generation operations decomposed into:
//! - core: Core generation setup and domain configuration
//! - signing: Certificate signing operations (self-signed and CA-signed)
//! - `file_ops`: File operations for saving certificates

pub mod core;
pub mod file_ops;
pub mod signing;

// Re-export main generation types
pub use core::{CertificateGenerator, CertificateGeneratorWithDomain};
