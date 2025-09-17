//! Certificate management module
//!
//! This module provides comprehensive certificate lifecycle management including:
//! - Certificate generation and loading
//! - Certificate parsing and validation
//! - Certificate chain verification
//! - Wildcard certificate support

pub mod generation;
pub mod parser;
pub mod parsing;
pub mod validation;
pub mod wildcard;

// Re-export main certificate functions
pub use generation::new;
// Re-export internal parsing function for use within certificate module

pub use parsing::{
    parse_certificate_from_pem, validate_basic_constraints, validate_certificate_time,
    validate_key_usage, verify_peer_certificate,
};
pub use validation::validate_certificate_chain;
