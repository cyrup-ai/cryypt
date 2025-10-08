//! Core TLS connection manager
//!
//! Provides the main `TlsManager` struct with connection creation and certificate
//! authority management functionality.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::config::TlsConfig;
use super::verifier::EnterpriseServerCertVerifier;
use crate::tls::builder::CertificateAuthority;
use crate::tls::crl_cache::CrlCache;
use crate::tls::errors::TlsError;
use crate::tls::ocsp::OcspCache;

/// Enterprise TLS connection manager with comprehensive security validation
#[derive(Clone)]
pub struct TlsManager {
    /// OCSP validation cache for certificate status checking
    ocsp_cache: Arc<OcspCache>,
    /// CRL cache for certificate revocation checking
    crl_cache: Arc<CrlCache>,
    /// Custom certificate authorities for validation
    custom_cas: Arc<RwLock<HashMap<String, CertificateAuthority>>>,
    /// TLS configuration
    config: TlsConfig,
}

impl TlsManager {
    /// Create new TLS manager with default configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - OCSP cache initialization fails
    /// - CRL cache initialization fails
    /// - Default configuration is invalid
    #[must_use]
    pub fn new() -> Result<Self, TlsError> {
        Self::with_config(TlsConfig::default())
    }

    /// Create new TLS manager with certificate directory (async)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate directory creation fails
    /// - Directory permissions are insufficient
    /// - TLS manager initialization fails
    /// - File system operations fail
    pub async fn with_cert_dir(cert_dir: std::path::PathBuf) -> Result<Self, TlsError> {
        // Create certificate directory if it doesn't exist
        if !tokio::fs::try_exists(&cert_dir).await.unwrap_or(false) {
            tokio::fs::create_dir_all(&cert_dir)
                .await
                .map_err(|e| TlsError::Internal(format!("Failed to create cert directory: {e}")))?;
        }

        // Initialize TLS manager with custom config
        let mut config = TlsConfig::default();

        // Add any certificates found in the directory
        if let Ok(mut entries) = tokio::fs::read_dir(&cert_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                    if let Ok(cert_data) = tokio::fs::read_to_string(&path).await {
                        config.custom_root_certs.push(cert_data);
                    }
                }
            }
        }

        Self::with_config(config)
    }

    /// Create TLS manager with specific configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - OCSP cache initialization fails
    /// - CRL cache initialization fails
    /// - Configuration validation fails
    #[must_use]
    pub fn with_config(config: TlsConfig) -> Result<Self, TlsError> {
        Ok(Self {
            ocsp_cache: Arc::new(OcspCache::new()?),
            crl_cache: Arc::new(CrlCache::new()?),
            custom_cas: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }

    /// Create TLS manager with production-optimized configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Production configuration setup fails
    /// - Cache initialization with optimized settings fails
    /// - Required system resources are unavailable
    #[must_use]
    pub fn production_optimized() -> Result<Self, TlsError> {
        Self::with_config(TlsConfig::production_optimized())
    }

    /// Add custom certificate authority
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate authority is invalid or malformed
    /// - Name conflicts with existing CA
    /// - Lock acquisition fails for CA storage
    pub fn add_certificate_authority(
        &self,
        name: String,
        ca: CertificateAuthority,
    ) -> Result<(), TlsError> {
        let mut cas = self
            .custom_cas
            .write()
            .map_err(|_| TlsError::Internal("Failed to acquire CA lock".to_string()))?;

        // Validate CA before adding
        if !ca.is_valid() {
            return Err(TlsError::CertificateExpired(format!(
                "Certificate authority '{name}' is expired"
            )));
        }

        cas.insert(name, ca);
        Ok(())
    }

    /// Pre-validate certificate for upcoming connection (eliminates block_on in rustls callbacks)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Certificate parsing fails
    /// - OCSP validation fails
    /// - CRL validation fails
    /// - Certificate is expired or invalid
    /// - Network validation requests fail
    pub async fn pre_validate_certificate(&self, cert_der: &[u8]) -> Result<(), TlsError> {
        // Create enterprise verifier for pre-validation
        let verifier = EnterpriseServerCertVerifier::new(
            self.ocsp_cache.clone(),
            self.crl_cache.clone(),
            self.config.enable_ocsp,
            self.config.enable_crl,
            self.config.validation_timeout,
        );

        verifier.pre_validate_certificate(cert_der).await
    }

    /// Create enterprise TLS connection with full validation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TCP connection fails
    /// - TLS handshake fails
    /// - Certificate validation fails
    /// - Connection timeout exceeded
    /// - Network errors occur
    pub async fn create_connection(
        &self,
        host: &str,
        port: u16,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TlsError> {
        tracing::debug!("Creating enterprise TLS connection to {}:{}", host, port);

        // Create TCP connection with timeout
        let tcp_stream = tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect((host, port)),
        )
        .await
        .map_err(|_| TlsError::Internal("Connection timeout".to_string()))?
        .map_err(|e| TlsError::Internal(format!("Failed to connect to {host}:{port}: {e}")))?;

        // Create enterprise TLS client configuration
        let client_config = self.create_client_config_sync()?;

        // Create TLS connector
        let connector = TlsConnector::from(Arc::new(client_config));

        // Create server name for TLS
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| TlsError::Internal(format!("Invalid hostname '{host}': {e}")))?;

        // Establish TLS connection
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| TlsError::Internal(format!("TLS handshake failed: {e}")))?;

        tracing::info!("Enterprise TLS connection established to {}:{}", host, port);
        Ok(tls_stream)
    }

    /// Create enterprise client configuration with full certificate validation
    #[must_use]
    fn create_client_config_sync(&self) -> Result<ClientConfig, TlsError> {
        // Create root certificate store
        let mut root_store = RootCertStore::empty();

        // Add system certificates if enabled
        if self.config.use_system_certs {
            let cert_result = rustls_native_certs::load_native_certs();
            for cert in cert_result.certs {
                if let Err(e) = root_store.add(cert) {
                    tracing::warn!("Failed to add system certificate: {}", e);
                }
            }

            if !cert_result.errors.is_empty() {
                for err in &cert_result.errors {
                    tracing::warn!("Certificate load error: {}", err);
                }
                // Fall back to webpki roots if there were significant errors
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }

            tracing::debug!("Loaded {} system certificates", root_store.len());
        } else {
            // Use webpki roots as fallback
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        // Add custom root certificates
        for cert_pem in &self.config.custom_root_certs {
            if let Ok(cert_der) = pem::parse(cert_pem) {
                let cert = rustls::pki_types::CertificateDer::from(cert_der.contents());
                if let Err(e) = root_store.add(cert) {
                    tracing::warn!("Failed to add custom root certificate: {}", e);
                } else {
                    tracing::debug!("Added custom root certificate");
                }
            }
        }

        // Add custom certificate authorities
        let cas = self
            .custom_cas
            .read()
            .map_err(|_| TlsError::Internal("Failed to acquire CA lock".to_string()))?;

        for (name, ca) in cas.iter() {
            if ca.is_valid() {
                // Parse CA certificate and add to root store
                if let Ok(cert_der) = pem::parse(&ca.certificate_pem) {
                    let cert = rustls::pki_types::CertificateDer::from(cert_der.contents());
                    if let Err(e) = root_store.add(cert) {
                        tracing::warn!("Failed to add custom CA '{}': {}", name, e);
                    } else {
                        tracing::debug!("Added custom CA: {}", name);
                    }
                }
            } else {
                tracing::warn!("Skipping expired CA: {}", name);
            }
        }

        // Create verifier that includes OCSP and CRL validation
        let verifier = Arc::new(EnterpriseServerCertVerifier::new(
            self.ocsp_cache.clone(),
            self.crl_cache.clone(),
            self.config.enable_ocsp,
            self.config.enable_crl,
            self.config.validation_timeout,
        ));

        // Build configuration with enterprise verifier
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        // Configure early data if enabled
        if self.config.enable_early_data {
            client_config.enable_early_data = true;
        }

        Ok(client_config)
    }

    /// Perform maintenance operations (cleanup caches, etc.)
    pub fn perform_maintenance(&self) {
        self.ocsp_cache.cleanup_cache();
        self.crl_cache.cleanup_cache();
        tracing::debug!("TLS manager maintenance completed");
    }
}
