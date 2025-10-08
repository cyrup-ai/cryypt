//! TLS Builder Interface
//!
//! This module provides a fluent, secure-by-default certificate management API.
//! All internal complexity is hidden behind the builder interface.

// Internal modules - not exposed publicly
pub(crate) mod certificate;
pub(crate) mod crl_cache;
pub(crate) mod errors;
pub(crate) mod http_client;
pub(crate) mod key_encryption;
pub(crate) mod ocsp;
pub(crate) mod tls_config;
pub(crate) mod tls_manager;
pub(crate) mod types;

// Public builder interface - the only public API
pub mod builder;
pub use builder::{CertificateAuthority, Tls};

// Public QUIC integration utilities
pub mod quiche_integration;
pub use quiche_integration::{QuicheCertificateProvider, configure_quiche_with_tls};

// Public TLS manager for enterprise connections
pub use tls_manager::{TlsConfig, TlsManager};

// Export HTTP client for internal TLS operations
pub use http_client::TlsHttpClient;
