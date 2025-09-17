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

use cyrup_sugars::prelude::*;

pub mod builder_traits;
pub mod chunk_types;
pub mod error;
pub mod handlers;
#[doc(hidden)]
pub mod macros;
// Keep DSL internal only (no public exposure)
mod dsl;
pub mod traits;

pub use error::*;
// Handler functions provide async result processing - implementation via internal macros
pub use builder_traits::{
    AsyncResultWithHandler, ErrorHandler, OnChunkBuilder, OnErrorBuilder, OnResultBuilder,
    ResultHandler,
};
// Do NOT re-export external sugars/macros publicly
pub use handlers::{on_error, on_result};
pub use traits::{
    AsyncDeleteResult, AsyncExistsResult, AsyncGenerateResult, AsyncListResult,
    AsyncRetrieveResult, AsyncStoreResult, NotResult,
};

/// `BadChunk` type for streaming error handling - used in `on_chunk` handlers
pub struct BadChunk(Vec<u8>);

impl BadChunk {
    /// Create a `BadChunk` from an error
    pub fn from_error(e: impl std::error::Error) -> Self {
        let error_msg = format!("ERROR: {e}");
        Self(error_msg.into_bytes())
    }
}

impl From<BadChunk> for Vec<u8> {
    fn from(val: BadChunk) -> Self {
        val.0
    }
}

/// Data chunk wrapper that implements `MessageChunk` for `cyrup_sugars` compatibility
#[derive(Debug, Clone)]
pub struct DataChunk {
    pub data: Vec<u8>,
    error: Option<String>,
}

impl DataChunk {
    /// Create a new data chunk
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, error: None }
    }

    /// Get the data as Vec<u8>
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

impl MessageChunk for DataChunk {
    fn bad_chunk(error: String) -> Self {
        Self {
            data: format!("[ERROR] {error}").into_bytes(),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

impl From<Vec<u8>> for DataChunk {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<DataChunk> for Vec<u8> {
    fn from(val: DataChunk) -> Self {
        val.data
    }
}
