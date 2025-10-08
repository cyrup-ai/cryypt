//! QUIC-TLS integration utilities
//!
//! This module provides integration between the enterprise-grade TLS module
//! and quiche's file-based certificate loading requirements.

use std::path::PathBuf;
use tokio::fs;

use super::builder::{CertificateAuthority, Tls};
use super::errors::TlsError;
use super::key_encryption::decrypt_private_key;
use super::types::SecureKeyMaterial;

/// QUIC certificate provider that integrates with enterprise TLS module
#[derive(Debug)]
pub struct QuicheCertificateProvider {
    /// Certificate authority from TLS module
    authority: CertificateAuthority,
    /// Temporary directory for certificate files
    temp_dir: Option<PathBuf>,
}

impl QuicheCertificateProvider {
    /// Create provider from certificate authority
    #[must_use]
    pub fn new(authority: CertificateAuthority) -> Self {
        Self {
            authority,
            temp_dir: None,
        }
    }

    /// Create provider by generating self-signed certificates using TLS builder API
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate authority creation fails
    /// - Directory creation or access fails
    /// - Certificate generation fails
    /// - File writing operations fail
    pub async fn create_self_signed(name: &str, cert_dir: PathBuf) -> Result<Self, TlsError> {
        tracing::info!("Creating self-signed certificates using TLS builder API for QUIC");

        let response = Tls::authority(name).path(&cert_dir).create().await;

        if !response.success {
            return Err(TlsError::Internal(format!(
                "Failed to create certificate authority: {}",
                response.issues.join("; ")
            )));
        }

        let authority = response.authority.ok_or_else(|| {
            TlsError::Internal(
                "Certificate authority creation succeeded but no authority returned".to_string(),
            )
        })?;

        Ok(Self::new(authority))
    }

    /// Create provider by loading existing certificates using TLS builder API
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate files cannot be found or read
    /// - Certificate format is invalid or corrupted
    /// - Directory access fails
    /// - Certificate authority loading fails
    pub async fn load_from_path(name: &str, cert_dir: PathBuf) -> Result<Self, TlsError> {
        tracing::info!("Loading existing certificates using TLS builder API for QUIC");

        let response = Tls::authority(name).path(&cert_dir).load().await;

        if !response.success {
            return Err(TlsError::Internal(format!(
                "Failed to load certificate authority: {}",
                response.issues.join("; ")
            )));
        }

        let authority = response.authority.ok_or_else(|| {
            TlsError::Internal(
                "Certificate authority loading succeeded but no authority returned".to_string(),
            )
        })?;

        Ok(Self::new(authority))
    }

    /// Create provider by loading from keychain using TLS builder API
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Keychain access is denied or unavailable
    /// - Certificate not found in keychain
    /// - Keychain certificate format is invalid
    /// - System keychain operations fail
    #[must_use]
    pub fn load_from_keychain(name: &str) -> Result<Self, TlsError> {
        tracing::info!("Loading certificates from keychain using TLS builder API for QUIC");

        let response = Tls::authority(name).keychain().load();

        if !response.success {
            return Err(TlsError::Internal(format!(
                "Failed to load certificate authority from keychain: {}",
                response.issues.join("; ")
            )));
        }

        let authority = response.authority.ok_or_else(|| {
            TlsError::Internal(
                "Keychain certificate authority loading succeeded but no authority returned"
                    .to_string(),
            )
        })?;

        Ok(Self::new(authority))
    }

    /// Create provider by loading from remote URL using TLS builder API
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Network request to remote URL fails
    /// - Remote certificate format is invalid
    /// - Certificate authority loading fails
    /// - Network timeout or connectivity issues
    pub async fn load_from_remote(name: &str, url: &str) -> Result<Self, TlsError> {
        tracing::info!("Loading certificates from remote URL using TLS builder API for QUIC");

        let response = Tls::authority(name).url(url).load().await;

        if !response.success {
            return Err(TlsError::Internal(format!(
                "Failed to load certificate authority from remote: {}",
                response.issues.join("; ")
            )));
        }

        let authority = response.authority.ok_or_else(|| {
            TlsError::Internal(
                "Remote certificate authority loading succeeded but no authority returned"
                    .to_string(),
            )
        })?;

        Ok(Self::new(authority))
    }

    /// Get certificate PEM data directly (no decryption needed)
    #[must_use]
    pub fn get_certificate_pem(&self) -> &str {
        &self.authority.certificate_pem
    }

    /// Get decrypted private key PEM data for quiche
    ///
    /// Note: This decrypts the encrypted private key using the `CRYYPT_KEY_ENCRYPTION_PASSPHRASE`
    /// environment variable. The result is temporarily stored in memory for quiche loading.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Private key is not available (validation-only CA)
    /// - Key decryption fails or passphrase is incorrect
    /// - Environment variable for passphrase is missing
    /// - Key format is invalid or corrupted
    #[must_use]
    pub fn get_decrypted_private_key_pem(&self) -> Result<SecureKeyMaterial, TlsError> {
        tracing::debug!("Decrypting private key for quiche consumption");

        let private_key_pem = self.authority.private_key_pem.as_ref().ok_or_else(|| {
            TlsError::ValidationOnlyCA(
                "Cannot decrypt private key for validation-only CA - no private key available"
                    .to_string(),
            )
        })?;

        // Check if the key is encrypted or already in plain PEM format
        if private_key_pem.starts_with("-----BEGIN") {
            // Key is already in PEM format (not encrypted)
            tracing::debug!("Private key is already in unencrypted PEM format");
            return Ok(SecureKeyMaterial::new(private_key_pem.as_bytes().to_vec()));
        }

        // Key appears to be encrypted data, attempt decryption
        tracing::debug!("Private key appears to be encrypted, attempting decryption");
        let encrypted_data = private_key_pem.as_bytes();

        match decrypt_private_key(encrypted_data) {
            Ok(decrypted_key) => {
                tracing::debug!("Successfully decrypted private key for quiche");
                Ok(decrypted_key)
            }
            Err(e) => {
                tracing::error!("Failed to decrypt private key: {}", e);
                Err(e)
            }
        }
    }

    /// Create temporary PEM files for quiche loading
    ///
    /// This method creates temporary unencrypted PEM files that quiche can load.
    /// The files are cleaned up when the provider is dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Temporary directory creation fails
    /// - File writing operations fail
    /// - Private key decryption fails
    /// - File system permissions are insufficient
    pub async fn create_temp_pem_files(&mut self) -> Result<(PathBuf, PathBuf), TlsError> {
        tracing::debug!("Creating temporary PEM files for quiche loading");

        // Create temporary directory
        let temp_dir = std::env::temp_dir().join(format!("cryypt-quic-certs-{}", {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            std::time::SystemTime::now().hash(&mut hasher);
            hasher.finish()
        }));
        fs::create_dir_all(&temp_dir).await.map_err(|e| {
            TlsError::Internal(format!("Failed to create temporary directory: {e}"))
        })?;

        self.temp_dir = Some(temp_dir.clone());

        // Write certificate file
        let cert_path = temp_dir.join("server.crt");
        fs::write(&cert_path, self.get_certificate_pem())
            .await
            .map_err(|e| {
                TlsError::Internal(format!("Failed to write temporary certificate file: {e}"))
            })?;

        // Decrypt and write private key file
        let decrypted_key = self.get_decrypted_private_key_pem()?;
        let key_path = temp_dir.join("server.key");
        fs::write(&key_path, decrypted_key.as_bytes())
            .await
            .map_err(|e| {
                TlsError::Internal(format!("Failed to write temporary private key file: {e}"))
            })?;

        // Set restrictive permissions on private key file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&key_path)
                .await
                .map_err(|e| TlsError::Internal(format!("Failed to get key file metadata: {e}")))?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&key_path, perms).await.map_err(|e| {
                TlsError::Internal(format!("Failed to set key file permissions: {e}"))
            })?;
        }

        tracing::debug!(
            "Created temporary PEM files: cert={:?}, key={:?}",
            cert_path,
            key_path
        );
        Ok((cert_path, key_path))
    }

    /// Get certificate authority metadata
    #[must_use]
    pub fn get_authority(&self) -> &CertificateAuthority {
        &self.authority
    }

    /// Check if the certificate authority is valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.authority.is_valid()
    }
}

impl Drop for QuicheCertificateProvider {
    fn drop(&mut self) {
        // Clean up temporary files
        if let Some(temp_dir) = &self.temp_dir
            && temp_dir.exists()
        {
            tracing::debug!(
                "Cleaning up temporary certificate directory: {:?}",
                temp_dir
            );
            if let Err(e) = std::fs::remove_dir_all(temp_dir) {
                tracing::warn!("Failed to clean up temporary certificate directory: {}", e);
            }
        }
    }
}

/// Configure quiche with certificates from TLS module
///
/// This function integrates the enterprise-grade TLS module with quiche's configuration
/// by creating temporary PEM files and loading them into quiche.
///
/// # Errors
///
/// Returns an error if:
/// - Certificate authority is expired or invalid
/// - Temporary PEM file creation fails
/// - Quiche certificate chain loading fails
/// - Quiche private key loading fails
/// - File operations fail
pub async fn configure_quiche_with_tls(
    config: &mut quiche::Config,
    provider: &mut QuicheCertificateProvider,
) -> Result<(), TlsError> {
    tracing::info!("Configuring quiche with enterprise TLS certificates");

    // Validate certificate authority
    if !provider.is_valid() {
        return Err(TlsError::CertificateExpired(
            "Certificate authority is expired or invalid".to_string(),
        ));
    }

    // Create temporary PEM files
    let (cert_path, key_path) = provider.create_temp_pem_files().await?;

    // Load certificate chain into quiche
    config
        .load_cert_chain_from_pem_file(&cert_path.to_string_lossy())
        .map_err(|e| {
            TlsError::Internal(format!("Failed to load certificate chain into quiche: {e}"))
        })?;

    // Load private key into quiche
    config
        .load_priv_key_from_pem_file(&key_path.to_string_lossy())
        .map_err(|e| TlsError::Internal(format!("Failed to load private key into quiche: {e}")))?;

    tracing::info!("Successfully configured quiche with TLS certificates");
    Ok(())
}
