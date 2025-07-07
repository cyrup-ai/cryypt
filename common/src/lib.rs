//! Common infrastructure and utilities for the cryypt project
//!
//! This crate provides shared functionality used across all cryypt crates including:
//! - Error handling with context propagation
//! - Metrics and telemetry
//! - Resource pooling
//! - Security audit logging
//! - Memory safety utilities

#![feature(negative_impls)]
#![feature(marker_trait_attr)]

pub mod error;
pub mod handlers;
pub mod traits;
pub mod builder_traits;
#[doc(hidden)]
pub mod macros;

pub use error::*;
// Handler functions are placeholders - actual implementation is via internal macros
pub use handlers::{on_chunk, on_error, on_result};
pub use traits::{
    NotResult,
    AsyncExistsResult, AsyncDeleteResult, AsyncRetrieveResult,
    AsyncStoreResult, AsyncGenerateResult, AsyncListResult
};
pub use builder_traits::{
    OnResultBuilder, OnChunkBuilder, OnErrorBuilder,
    AsyncResultWithHandler, ResultHandler, ChunkHandler, ErrorHandler
};