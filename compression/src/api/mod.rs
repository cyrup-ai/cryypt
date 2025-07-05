//! Fluent compression API transitioning to the new pattern
//!
//! Usage: `let compressed = Compress::zstd().compress(b"...").await` (NEW)
//! Old:   `let compressed = Compress::gzip().with_data(b"...").compress().await` (OLD - will be updated)

mod bzip2_builder;
mod gzip_builder;
mod zip_builder;
mod zstd_builder;
pub use bzip2_builder::{Bzip2Builder, Bzip2Stream};
pub use gzip_builder::{GzipBuilder, GzipStream};
pub use zip_builder::{ZipBuilder, ZipStream};
pub use zstd_builder::{ZstdBuilder, CompressionStream};

/// Entry point for compression operations
pub struct Compress;

impl Compress {
    /// Create a Zstd compressor (best compression ratio, recommended) - NEW PATTERN
    pub fn zstd() -> ZstdBuilder<zstd_builder::NoLevel> {
        ZstdBuilder::new()
    }

    /// Create a Gzip compressor (widely compatible) - NEW PATTERN
    pub fn gzip() -> GzipBuilder<gzip_builder::NoLevel> {
        GzipBuilder::new()
    }

    /// Create a Bzip2 compressor (good compression) - NEW PATTERN
    pub fn bzip2() -> Bzip2Builder<bzip2_builder::NoLevel> {
        Bzip2Builder::new()
    }

    /// Create a Zip compressor (multi-file archives) - NEW PATTERN
    pub fn zip() -> ZipBuilder<zip_builder::NoFiles> {
        ZipBuilder::new()
    }
}
