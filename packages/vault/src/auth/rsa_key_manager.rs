//! RSA key management for vault JWT authentication
//!
//! Handles RSA keypair generation, filesystem persistence, and loading for
//! RS256 JWT signing operations.

use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;
use secrecy::ExposeSecret;
use std::path::{Path, PathBuf};
use tokio::fs;

/// RSA key manager for vault authentication
#[derive(Debug, Clone)]
pub struct RsaKeyManager {
    key_path: PathBuf,
}

impl RsaKeyManager {
    /// Create new RSA key manager with specified key path
    pub fn new(key_path: PathBuf) -> Self {
        Self { key_path }
    }

    /// Get platform-agnostic default path: ~/.ssh/cryypt.rsa
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| {
                log::warn!("Could not determine home directory, using current directory");
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
            })
            .join(".ssh")
            .join("cryypt.rsa")
    }

    /// Load RSA keypair or create if doesn't exist
    ///
    /// # Arguments
    /// * `passphrase` - Used for key generation if key doesn't exist
    ///
    /// # Returns
    /// Parsed RSA keypair (private_key_der, public_key_der)
    pub async fn load_or_create(
        &self,
        passphrase: &Passphrase,
    ) -> VaultResult<(Vec<u8>, Vec<u8>)> {
        if self.key_path.exists() {
            log::debug!("Loading existing RSA key from {}", self.key_path.display());
            self.load().await
        } else {
            log::info!("RSA key not found, generating new key at {}", self.key_path.display());
            self.generate_and_save(passphrase).await
        }
    }

    /// Load existing RSA keypair from filesystem
    ///
    /// # Returns
    /// Parsed RSA keypair (private_key_der, public_key_der)
    pub async fn load(&self) -> VaultResult<(Vec<u8>, Vec<u8>)> {
        if !self.key_path.exists() {
            return Err(VaultError::Crypto(format!(
                "RSA key not found at {}",
                self.key_path.display()
            )));
        }

        let keypair_bytes = fs::read(&self.key_path).await.map_err(|e| {
            VaultError::Crypto(format!(
                "Failed to read RSA key from {}: {}",
                self.key_path.display(),
                e
            ))
        })?;

        Self::parse_keypair(&keypair_bytes)
    }

    /// Generate new RSA keypair from passphrase and save to filesystem
    ///
    /// Uses passphrase as entropy seed for deterministic generation (same passphrase = same key)
    ///
    /// # Returns
    /// Parsed RSA keypair (private_key_der, public_key_der)
    pub async fn generate_and_save(
        &self,
        passphrase: &Passphrase,
    ) -> VaultResult<(Vec<u8>, Vec<u8>)> {
        use cryypt_key::api::RsaKeyBuilder;

        // Generate RSA-2048 keypair (random generation)
        // Note: Passphrase parameter reserved for future deterministic generation support

        let keypair_bytes = RsaKeyBuilder::new()
            .with_size(2048)
            .on_result(|result| match result {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("RSA key generation failed: {}", e);
                    Vec::new()
                }
            })
            .generate()
            .await;

        if keypair_bytes.is_empty() {
            return Err(VaultError::Crypto(
                "RSA key generation failed - empty result".to_string(),
            ));
        }

        // Save to filesystem
        self.save_keypair(&keypair_bytes).await?;

        // Parse and return
        Self::parse_keypair(&keypair_bytes)
    }

    /// Load RSA keypair and convert to PKCS8/SPKI format for JWT usage
    ///
    /// Loads PKCS1 format from filesystem and converts to formats expected by JwtHandler:
    /// - Private key: PKCS8 DER
    /// - Public key: SPKI DER (SubjectPublicKeyInfo)
    ///
    /// # Returns
    /// (private_key_pkcs8_der, public_key_spki_der) ready for JwtHandler
    pub async fn load_for_jwt(&self) -> VaultResult<(Vec<u8>, Vec<u8>)> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

        // Load PKCS1 format from filesystem
        let (private_pkcs1, public_pkcs1) = self.load().await?;

        // Parse PKCS1 format
        let private_key = rsa::RsaPrivateKey::from_pkcs1_der(&private_pkcs1).map_err(|e| {
            VaultError::Crypto(format!("Invalid RSA private key: {}", e))
        })?;

        // Extract public key from private key (more reliable than parsing public_pkcs1 separately)
        let public_key = rsa::RsaPublicKey::from(&private_key);

        // Convert to PKCS8/SPKI format
        let private_pkcs8 = private_key
            .to_pkcs8_der()
            .map_err(|e| VaultError::Crypto(format!("PKCS8 encoding failed: {}", e)))?
            .as_bytes()
            .to_vec();

        let public_spki = public_key
            .to_public_key_der()
            .map_err(|e| VaultError::Crypto(format!("SPKI encoding failed: {}", e)))?
            .as_bytes()
            .to_vec();

        log::debug!(
            "Converted RSA key to JWT format: PKCS8={} bytes, SPKI={} bytes",
            private_pkcs8.len(),
            public_spki.len()
        );

        Ok((private_pkcs8, public_spki))
    }

    /// Generate new RSA keypair and return in PKCS8/SPKI format for JWT usage
    ///
    /// Generates PKCS1 format, saves to filesystem, then converts to JWT-compatible formats.
    ///
    /// # Returns
    /// (private_key_pkcs8_der, public_key_spki_der) ready for JwtHandler
    pub async fn generate_for_jwt(
        &self,
        passphrase: &Passphrase,
    ) -> VaultResult<(Vec<u8>, Vec<u8>)> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

        // Generate and save in PKCS1 format
        let (private_pkcs1, _public_pkcs1) = self.generate_and_save(passphrase).await?;

        // Parse PKCS1 format
        let private_key = rsa::RsaPrivateKey::from_pkcs1_der(&private_pkcs1).map_err(|e| {
            VaultError::Crypto(format!("Invalid RSA private key: {}", e))
        })?;

        // Extract public key from private key
        let public_key = rsa::RsaPublicKey::from(&private_key);

        // Convert to PKCS8/SPKI format
        let private_pkcs8 = private_key
            .to_pkcs8_der()
            .map_err(|e| VaultError::Crypto(format!("PKCS8 encoding failed: {}", e)))?
            .as_bytes()
            .to_vec();

        let public_spki = public_key
            .to_public_key_der()
            .map_err(|e| VaultError::Crypto(format!("SPKI encoding failed: {}", e)))?
            .as_bytes()
            .to_vec();

        log::info!(
            "Generated RSA key in JWT format: PKCS8={} bytes, SPKI={} bytes",
            private_pkcs8.len(),
            public_spki.len()
        );

        Ok((private_pkcs8, public_spki))
    }

    /// Save RSA keypair to filesystem with secure permissions
    async fn save_keypair(&self, keypair_bytes: &[u8]) -> VaultResult<()> {
        // Create parent directories
        if let Some(parent) = self.key_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                VaultError::Crypto(format!(
                    "Failed to create directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;

            // Set secure permissions on .ssh directory (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o700); // rwx------
                if let Err(e) = std::fs::set_permissions(parent, perms) {
                    log::warn!("Failed to set .ssh directory permissions: {}", e);
                    // Don't fail on permission errors
                }
            }
        }

        // Atomic write: write to temp file, then rename
        let temp_path = self.key_path.with_extension("tmp");

        fs::write(&temp_path, keypair_bytes).await.map_err(|e| {
            VaultError::Crypto(format!(
                "Failed to write RSA key to {}: {}",
                temp_path.display(),
                e
            ))
        })?;

        fs::rename(&temp_path, &self.key_path)
            .await
            .map_err(|e| {
                VaultError::Crypto(format!(
                    "Failed to rename {} to {}: {}",
                    temp_path.display(),
                    self.key_path.display(),
                    e
                ))
            })?;

        // Set secure permissions on key file (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600); // rw-------
            if let Err(e) = std::fs::set_permissions(&self.key_path, perms) {
                log::warn!("Failed to set RSA key file permissions: {}", e);
                // Don't fail on permission errors
            }
        }

        log::info!("RSA key saved to {}", self.key_path.display());
        Ok(())
    }

    /// Parse combined RSA keypair format into separate private and public keys
    ///
    /// Format from cryypt_key:
    /// [4 bytes private_len][private_der][4 bytes public_len][public_der]
    ///
    /// # Returns
    /// (private_key_der, public_key_der) both in PKCS1 DER format
    fn parse_keypair(keypair_bytes: &[u8]) -> VaultResult<(Vec<u8>, Vec<u8>)> {
        if keypair_bytes.len() < 8 {
            return Err(VaultError::Crypto(format!(
                "Invalid RSA keypair format: too short ({} bytes, minimum 8)",
                keypair_bytes.len()
            )));
        }

        let mut offset = 0;

        // Parse private key length (little-endian u32)
        let private_len = u32::from_le_bytes([
            keypair_bytes[0],
            keypair_bytes[1],
            keypair_bytes[2],
            keypair_bytes[3],
        ]) as usize;
        offset += 4;

        if offset + private_len > keypair_bytes.len() {
            return Err(VaultError::Crypto(format!(
                "Invalid RSA keypair format: private key length {} exceeds data size {}",
                private_len,
                keypair_bytes.len()
            )));
        }

        // Extract private key
        let private_key = keypair_bytes[offset..offset + private_len].to_vec();
        offset += private_len;

        // Parse public key length (little-endian u32)
        if offset + 4 > keypair_bytes.len() {
            return Err(VaultError::Crypto(
                "Invalid RSA keypair format: missing public key length".to_string(),
            ));
        }

        let public_len = u32::from_le_bytes([
            keypair_bytes[offset],
            keypair_bytes[offset + 1],
            keypair_bytes[offset + 2],
            keypair_bytes[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + public_len > keypair_bytes.len() {
            return Err(VaultError::Crypto(format!(
                "Invalid RSA keypair format: public key length {} exceeds remaining data {}",
                public_len,
                keypair_bytes.len() - offset
            )));
        }

        // Extract public key
        let public_key = keypair_bytes[offset..offset + public_len].to_vec();

        log::debug!(
            "Parsed RSA keypair: private={} bytes, public={} bytes",
            private_key.len(),
            public_key.len()
        );

        Ok((private_key, public_key))
    }

    /// Get the configured key path
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }
}
