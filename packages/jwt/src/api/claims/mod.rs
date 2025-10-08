//! JWT Claims Validation and Processing - Re-exports from decomposed modules
//!
//! This module provides blazing-fast, zero-allocation JWT claims validation
//! with comprehensive support for standard and custom claims.

pub mod builder;
pub mod extractor;
pub mod standard_claims;
pub mod validation;
pub mod validator;

// Re-export main types for backward compatibility
pub use builder::ClaimsBuilder;
pub use extractor::ClaimsExtractor;
pub use standard_claims::Claims;
pub use validator::ClaimsValidator;

// Re-export internal validation function for crate use
// use crate::api::algorithms::validation::validate_standard_claims;
