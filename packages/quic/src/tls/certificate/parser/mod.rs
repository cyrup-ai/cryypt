//! Certificate parsing implementation module
//!
//! This module provides comprehensive X.509 certificate parsing capabilities
//! decomposed into focused, single-responsibility modules:
//!
//! - `core`: Main parsing functions coordinating all operations
//! - `name_extraction`: Distinguished name attribute extraction
//! - `details_extraction`: Certificate details including SAN, constraints, and key usage
//! - `key_extraction`: Key algorithm and size information extraction

pub mod core;
pub mod details_extraction;
pub mod key_extraction;
pub mod name_extraction;

// Re-export main parsing functions for backward compatibility
pub use core::{parse_certificate_from_pem_internal, parse_x509_certificate_from_der_internal};
