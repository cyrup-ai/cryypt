//! Zstd compression configuration
//!
//! Contains methods for configuring compression levels and options.

use super::{HasLevel, ZstdBuilder};

// Additional configuration methods for NoLevel builders
impl ZstdBuilder<super::NoLevel> {
    /// Maximum compression (level 22)
    #[must_use]
    pub fn max_compression(self) -> ZstdBuilder<HasLevel> {
        self.with_level(22)
    }

    /// Fast compression (level 1)
    #[must_use]
    pub fn fast_compression(self) -> ZstdBuilder<HasLevel> {
        self.with_level(1)
    }
}
