//! Keychain certificate authority operations module
//!
//! This module provides platform-specific keychain/system certificate store access:
//! - macOS: security-framework integration
//! - Linux/Windows: System certificate store locations

#[cfg(not(target_os = "macos"))]
mod cross_platform;
#[cfg(target_os = "macos")]
mod macos;

/// Builder for keychain certificate authority operations
#[derive(Debug, Clone)]
pub struct AuthorityKeychainBuilder {
    name: String,
}

impl AuthorityKeychainBuilder {
    pub(super) fn new(name: String) -> Self {
        Self { name }
    }

    /// Load certificate authority from system keychain
    pub fn load(self) -> super::super::responses::CertificateAuthorityResponse {
        #[cfg(target_os = "macos")]
        {
            macos::load_from_keychain(self.name)
        }

        #[cfg(not(target_os = "macos"))]
        {
            cross_platform::load_from_system_store(self.name)
        }
    }
}
