pub mod api;
pub mod bzip2;
mod chunk_macro;
pub mod compression_result;
pub mod error;
pub mod gzip;
mod result_macro;
pub mod zip;
pub mod zstd;
mod on_result;

// Re-export error types
pub use error::{CompressionError, Result};

// Re-export compression result type  
pub use compression_result::{CompressionResult, CompressionAlgorithm};

// Export on_result function for main cryypt crate
pub use on_result::on_result;

pub use api::*;