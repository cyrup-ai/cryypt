pub mod api;
pub mod async_result;
pub mod bzip2;
mod chunk_macro;
pub mod compression_result;
pub mod error;
pub mod gzip;
mod result_macro;
pub mod zip;
pub mod zstd;
// Re-export error types
pub use error::{CompressionError, Result};

// Re-export compression result types
pub use async_result::{AsyncCompressionResult, AsyncCompressionResultWithHandler};
pub use compression_result::{CompressionAlgorithm, CompressionResult};

// Re-export common macros and handlers from cryypt_common
pub use cryypt_common::{on_error, on_result};

// Macros are defined but unused - they were replaced with direct implementations

pub use api::*;
