//! Modular JWT API implementation
//!
//! This module provides a decomposed, production-ready JWT implementation
//! following single responsibility principles with focused submodules.

// Import all implementation modules
pub mod algorithm_builders;
pub mod algorithms;
pub mod builder;
pub mod builders;
pub mod claims;
pub mod keys;
pub mod operations;
pub mod rotator_builder;
pub mod validation;

// Re-export main builder types - use builder.rs for ChunkHandler implementation
pub use algorithm_builders::{HsJwtBuilder, RsJwtBuilder};
pub use builder::{JwtBuilder, JwtMasterBuilder};
pub use builders::Jwt;
pub use validation::{AsyncJwtResult, AsyncJwtResultWithError};

// Re-export key utilities for public API
pub use keys::get_recommended_key_size;
