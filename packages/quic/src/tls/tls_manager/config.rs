//! TLS configuration module
//!
//! Provides TLS configuration structures and presets for different use cases.

use std::time::Duration;

/// TLS configuration for enterprise features
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Enable OCSP validation
    pub enable_ocsp: bool,
    /// Enable CRL checking
    pub enable_crl: bool,
    /// Use system certificate store
    pub use_system_certs: bool,
    /// Custom root certificates
    pub custom_root_certs: Vec<String>,
    /// TLS 1.3 early data support
    pub enable_early_data: bool,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Certificate validation timeout
    pub validation_timeout: Duration,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enable_ocsp: true,
            enable_crl: true,
            use_system_certs: true,
            custom_root_certs: Vec::new(),
            enable_early_data: false,
            connect_timeout: Duration::from_secs(10),
            validation_timeout: Duration::from_secs(5),
        }
    }
}

impl TlsConfig {
    /// Create production-optimized TLS configuration
    #[must_use]
    pub fn production_optimized() -> Self {
        Self {
            enable_ocsp: true,
            enable_crl: true,
            use_system_certs: true,
            custom_root_certs: Vec::new(),
            enable_early_data: false, // Disable for security
            connect_timeout: Duration::from_secs(10),
            validation_timeout: Duration::from_secs(5),
        }
    }

    /// Create AI-optimized TLS configuration
    #[must_use]
    pub fn ai_optimized() -> Self {
        Self {
            enable_ocsp: true,
            enable_crl: true,
            use_system_certs: true,
            custom_root_certs: Vec::new(),
            enable_early_data: true, // Enable for AI performance
            connect_timeout: Duration::from_secs(5), // Faster for AI workloads
            validation_timeout: Duration::from_secs(3),
        }
    }
}
