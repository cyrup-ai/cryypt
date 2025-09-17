//! Bzip2 compression configuration
//!
//! Contains methods for configuring compression levels and options.

use super::{Bzip2Builder, HasLevel, NoLevel};

// Methods for setting compression level
impl Bzip2Builder<NoLevel> {
    /// Set the compression level (1-9, where 1 is fastest and 9 is maximum compression)
    #[must_use]
    pub fn with_level(self, level: u32) -> Bzip2Builder<HasLevel> {
        Bzip2Builder {
            level: HasLevel(level.clamp(1, 9)),
            error_handler: self.error_handler,
        }
    }

    /// Maximum compression (level 9)
    #[must_use]
    pub fn max_compression(self) -> Bzip2Builder<HasLevel> {
        self.with_level(9)
    }

    /// Balanced compression (level 6)
    #[must_use]
    pub fn balanced_compression(self) -> Bzip2Builder<HasLevel> {
        self.with_level(6)
    }

    /// Fast compression (level 1)
    #[must_use]
    pub fn fast_compression(self) -> Bzip2Builder<HasLevel> {
        self.with_level(1)
    }
}
