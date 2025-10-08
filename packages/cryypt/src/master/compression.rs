//! Compression Master Builder
//!
//! Master builder for compression operations (Zstd, Gzip, Bzip2, Zip)

/// Master builder for compression operations
#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
pub struct CompressMasterBuilder;

#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
impl CompressMasterBuilder {
    /// Use Zstandard compression - README.md pattern
    #[cfg(feature = "zstd")]
    #[must_use]
    pub fn zstd(
        self,
    ) -> cryypt_compression::ZstdBuilder<cryypt_compression::api::zstd_builder::NoLevel> {
        cryypt_compression::Compress::zstd()
    }

    /// Use Gzip compression - README.md pattern
    #[cfg(feature = "gzip")]
    #[must_use]
    pub fn gzip(
        self,
    ) -> cryypt_compression::GzipBuilder<cryypt_compression::api::gzip_builder::NoLevel> {
        cryypt_compression::Compress::gzip()
    }

    /// Use Bzip2 compression - README.md pattern
    #[cfg(feature = "bzip2")]
    #[must_use]
    pub fn bzip2(
        self,
    ) -> cryypt_compression::Bzip2Builder<cryypt_compression::api::bzip2_builder::NoLevel> {
        cryypt_compression::Compress::bzip2()
    }

    /// Use ZIP compression for multi-file archives - README.md pattern
    #[cfg(feature = "zip")]
    #[must_use]
    pub fn zip(
        self,
    ) -> cryypt_compression::ZipBuilder<cryypt_compression::api::zip_builder::NoFiles> {
        cryypt_compression::Compress::zip()
    }
}
