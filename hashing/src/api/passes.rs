//! Hash iteration passes configuration with production-safe defaults

/// Number of hash iterations to perform
///
/// Default values are tuned for PRODUCTION security.
/// These follow OWASP recommendations for password hashing.
///
/// # Security Considerations
///
/// - For password hashing: Use at least `Default` (10,000 iterations)
/// - For key derivation: Use `Strong` or higher
/// - For general hashing: `Fast` may be acceptable
/// - Never use less than `Fast` (100 iterations) in production
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashPasses {
    /// Fast hashing - 100 iterations
    ///
    /// ⚠️ WARNING: Only use for non-sensitive data or development
    /// Not suitable for password hashing
    Fast = 100,

    /// Moderate security - 1,000 iterations
    ///
    /// Minimum acceptable for low-value passwords
    /// Consider using Default or higher for production
    Moderate = 1_000,

    /// Default production security - 10,000 iterations
    ///
    /// OWASP minimum recommendation for password hashing
    /// Suitable for most production use cases
    Default = 10_000,

    /// Strong security - 100,000 iterations
    ///
    /// Recommended for high-value passwords
    /// Good balance of security and performance
    Strong = 100_000,

    /// Maximum security - 1,000,000 iterations
    ///
    /// For extremely sensitive data
    /// May cause noticeable delays
    Maximum = 1_000_000,
}

impl Default for HashPasses {
    fn default() -> Self {
        // Production-safe default
        Self::Default
    }
}

impl HashPasses {
    /// Get the number of iterations as u32
    pub fn iterations(&self) -> u32 {
        match self {
            Self::Fast => 100,
            Self::Moderate => 1_000,
            Self::Default => 10_000,
            Self::Strong => 100_000,
            Self::Maximum => 1_000_000,
        }
    }

    /// Check if this is suitable for password hashing
    pub fn is_password_safe(&self) -> bool {
        self.iterations() >= 10_000
    }

    /// Get a description of the security level
    pub fn security_level(&self) -> &'static str {
        match self {
            Self::Fast => "⚠️  Development only",
            Self::Moderate => "⚠️  Low security",
            Self::Default => "✓ Production ready",
            Self::Strong => "✓ High security",
            Self::Maximum => "✓ Maximum security",
        }
    }
}

impl From<HashPasses> for u32 {
    fn from(passes: HashPasses) -> Self {
        passes.iterations()
    }
}

