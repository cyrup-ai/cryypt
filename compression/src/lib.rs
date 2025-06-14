pub mod api;
pub mod error;
pub mod bzip2;
pub mod gzip;
pub mod zip;
pub mod zstd;

// Re-export error types
pub use error::{CompressionError, Result};

pub use api::*;
