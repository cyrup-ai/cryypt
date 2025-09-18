//! Enterprise server certificate verifier with AsyncStream-based pre-validation
//!
//! Provides comprehensive certificate verification including OCSP and CRL checking
//! with pre-validation support to avoid blocking operations during TLS handshakes.

use std::sync::Arc;
use std::time::Duration;

use super::cache::ValidationCache;
use crate::tls::certificate::validation::parse_certificate_from_der;
use crate::tls::crl_cache::CrlCache;
use crate::tls::ocsp::OcspCache;

/// Enterprise server certificate verifier with AsyncStream-based pre-validation
#[derive(Debug)]
pub struct EnterpriseServerCertVerifier {
    ocsp_cache: Arc<OcspCache>,
    crl_cache: Arc<CrlCache>,
    validation_cache: ValidationCache,
    enable_ocsp: bool,
    enable_crl: bool,
    validation_timeout: Duration,
}

impl EnterpriseServerCertVerifier {
    #[must_use]
    pub fn new(
        ocsp_cache: Arc<OcspCache>,
        crl_cache: Arc<CrlCache>,
        enable_ocsp: bool,
        enable_crl: bool,
        validation_timeout: Duration,
    ) -> Self {
        Self {
            ocsp_cache,
            crl_cache,
            validation_cache: ValidationCache::new(),
            enable_ocsp,
            enable_crl,
            validation_timeout,
        }
    }

    /// Pre-validate certificate asynchronously (called before rustls verification)
    pub async fn pre_validate_certificate(
        &self,
        cert_der: &[u8],
    ) -> Result<(), super::super::errors::TlsError> {
        use ring::digest::{Context as DigestContext, SHA256};

        // Create unique key for this certificate
        let mut context = DigestContext::new(&SHA256);
        context.update(cert_der);
        let cert_key = hex::encode(context.finish().as_ref());

        // Parse certificate for validation
        let parsed_cert =
            super::super::certificate::validation::parse_certificate_from_der(cert_der)?;

        // Async OCSP validation
        if self.enable_ocsp && !parsed_cert.ocsp_urls.is_empty() {
            match tokio::time::timeout(
                self.validation_timeout,
                self.ocsp_cache.check_certificate(&parsed_cert, None),
            )
            .await
            {
                Ok(Ok(status)) => {
                    self.validation_cache
                        .set_ocsp_status(cert_key.clone(), status);
                }
                Ok(Err(e)) => {
                    tracing::warn!("OCSP pre-validation failed: {}", e);
                    self.validation_cache
                        .set_ocsp_status(cert_key.clone(), crate::tls::ocsp::OcspStatus::Unknown);
                }
                Err(_) => {
                    tracing::warn!("OCSP pre-validation timed out");
                    self.validation_cache
                        .set_ocsp_status(cert_key.clone(), crate::tls::ocsp::OcspStatus::Unknown);
                }
            }
        }

        // Async CRL validation
        if self.enable_crl && !parsed_cert.crl_urls.is_empty() {
            for crl_url in &parsed_cert.crl_urls {
                match tokio::time::timeout(
                    self.validation_timeout,
                    self.crl_cache
                        .check_certificate_status(&parsed_cert.serial_number, crl_url),
                )
                .await
                {
                    Ok(status) => {
                        self.validation_cache
                            .set_crl_status(format!("{cert_key}-{crl_url}"), status);
                    }
                    Err(_) => {
                        tracing::warn!("CRL pre-validation timed out for {crl_url}");
                        self.validation_cache.set_crl_status(
                            format!("{cert_key}-{crl_url}"),
                            crate::tls::crl_cache::CrlStatus::Unknown,
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

impl rustls::client::danger::ServerCertVerifier for EnterpriseServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // First perform standard certificate validation
        let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        ))
        .build()
        .map_err(|e| rustls::Error::General(format!("Failed to create webpki verifier: {e}")))?;

        // Perform standard validation
        webpki_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Parse end entity certificate for additional validation
        let parsed_cert = parse_certificate_from_der(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("Failed to parse certificate: {e}")))?;

        // Check pre-validated OCSP status (no block_on needed)
        if self.enable_ocsp && !parsed_cert.ocsp_urls.is_empty() {
            use ring::digest::{Context as DigestContext, SHA256};

            // Create certificate key for cache lookup
            let mut context = DigestContext::new(&SHA256);
            context.update(end_entity.as_ref());
            let cert_key = hex::encode(context.finish().as_ref());

            match self.validation_cache.get_ocsp_status(&cert_key) {
                Some(crate::tls::ocsp::OcspStatus::Good) => {
                    tracing::debug!("OCSP validation passed for {:?}", server_name);
                }
                Some(crate::tls::ocsp::OcspStatus::Revoked) => {
                    tracing::error!("Certificate revoked via OCSP for {:?}", server_name);
                    return Err(rustls::Error::General(
                        "Certificate revoked via OCSP".to_string(),
                    ));
                }
                Some(crate::tls::ocsp::OcspStatus::Unknown) => {
                    tracing::warn!("OCSP validation inconclusive for {:?}", server_name);
                    // Allow unknown status but log warning
                }
                None => {
                    tracing::warn!(
                        "OCSP validation not pre-cached for {:?} - allowing with warning",
                        server_name
                    );
                    // Allow when not pre-cached but log warning
                }
            }
        }

        // Check pre-validated CRL status (no block_on needed)
        if self.enable_crl && !parsed_cert.crl_urls.is_empty() {
            use ring::digest::{Context as DigestContext, SHA256};

            // Create certificate key for cache lookup
            let mut context = DigestContext::new(&SHA256);
            context.update(end_entity.as_ref());
            let cert_key = hex::encode(context.finish().as_ref());

            // Check certificate against each CRL URL
            for crl_url in &parsed_cert.crl_urls {
                let crl_cache_key = format!("{cert_key}-{crl_url}");
                match self.validation_cache.get_crl_status(&crl_cache_key) {
                    Some(crate::tls::crl_cache::CrlStatus::Valid) => {
                        tracing::debug!(
                            "CRL validation passed for {:?} against {}",
                            server_name,
                            crl_url
                        );
                    }
                    Some(crate::tls::crl_cache::CrlStatus::Revoked) => {
                        tracing::error!(
                            "Certificate revoked via CRL for {:?} against {}",
                            server_name,
                            crl_url
                        );
                        return Err(rustls::Error::General(format!(
                            "Certificate revoked via CRL: {crl_url}"
                        )));
                    }
                    Some(crate::tls::crl_cache::CrlStatus::Unknown) => {
                        tracing::warn!(
                            "CRL validation inconclusive for {:?} against {}",
                            server_name,
                            crl_url
                        );
                        // Allow unknown status but log warning
                    }
                    None => {
                        tracing::warn!(
                            "CRL validation not pre-cached for {:?} against {} - allowing with warning",
                            server_name,
                            crl_url
                        );
                        // Allow when not pre-cached but log warning
                    }
                }
            }
        }

        tracing::info!(
            "Enterprise certificate validation completed for {:?}",
            server_name
        );
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
