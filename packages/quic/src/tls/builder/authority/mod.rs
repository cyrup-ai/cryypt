//! Certificate Authority builder operations module
//!
//! This module provides a complete certificate authority management system
//! decomposed into focused, single-responsibility modules:
//!
//! - `core`: Core domain types and business logic
//! - `filesystem`: File system based CA operations  
//! - `keychain`: System keystore integration
//! - `remote`: Network-based CA fetching

pub mod core;
pub mod filesystem;
pub mod keychain;
pub mod remote;

// Re-export all public types for backward compatibility
pub use core::{AuthorityBuilder, CaMetadata, CaSource, CertificateAuthority};
pub use filesystem::AuthorityFilesystemBuilder;
pub use keychain::AuthorityKeychainBuilder;
pub use remote::AuthorityRemoteBuilder;
