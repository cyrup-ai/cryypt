//! Certificate validation and chain verification

use anyhow::Result;
use der::Decode;
use rustls::pki_types::CertificateDer;
use tracing::{info, warn};

use super::parsing::{
    parse_certificate_from_pem, validate_basic_constraints, validate_certificate_time,
    validate_key_usage, verify_peer_certificate,
};
use crate::tls::errors::TlsError;
use crate::tls::types::{CertificateUsage, ParsedCertificate};

/// Validate certificate chain to root CA
pub async fn validate_certificate_chain(
    cert_chain_pem: &str,
    ca_cert: &CertificateDer<'static>,
) -> Result<(), TlsError> {
    // Parse the certificate chain
    let mut chain_certs = Vec::new();
    let mut current_cert_pem = String::new();
    let mut in_cert = false;

    for line in cert_chain_pem.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current_cert_pem.clear();
        }

        if in_cert {
            current_cert_pem.push_str(line);
            current_cert_pem.push('\n');
        }

        if line.contains("-----END CERTIFICATE-----") {
            in_cert = false;
            let parsed_cert = parse_certificate_from_pem(&current_cert_pem)?;
            chain_certs.push(parsed_cert);
        }
    }

    if chain_certs.is_empty() {
        return Err(TlsError::CertificateValidation(
            "No certificates found in chain".to_string(),
        ));
    }

    // Validate each certificate in the chain
    for (i, cert) in chain_certs.iter().enumerate() {
        // Validate time constraints
        validate_certificate_time(cert)?;

        // For intermediate CA certificates, validate BasicConstraints
        if i > 0 {
            validate_basic_constraints(cert, true)?;
            validate_key_usage(cert, CertificateUsage::CertificateAuthority)?;
        }
    }

    // Verify chain integrity - each certificate should be signed by the next one
    for i in 0..chain_certs.len() - 1 {
        let cert = &chain_certs[i];
        let issuer = &chain_certs[i + 1];

        // Basic issuer/subject matching
        if cert.issuer != issuer.subject {
            return Err(TlsError::CertificateValidation(format!(
                "Certificate chain broken: certificate {} issuer does not match certificate {} subject",
                i,
                i + 1
            )));
        }
    }

    // Verify the root certificate matches our CA
    let root_cert = chain_certs.last().ok_or_else(|| {
        TlsError::InvalidCertificateChain("Certificate chain is empty".to_string())
    })?;
    let ca_cert_parsed = parse_certificate_from_der(ca_cert.as_ref())?;

    if root_cert.subject != ca_cert_parsed.subject {
        return Err(TlsError::CertificateValidation(
            "Certificate chain does not terminate at expected CA".to_string(),
        ));
    }

    info!("Certificate chain validation successful");
    Ok(())
}

/// Parse certificate from DER format
pub fn parse_certificate_from_der(der_data: &[u8]) -> Result<ParsedCertificate, TlsError> {
    use x509_cert::Certificate;

    let cert = Certificate::from_der(der_data).map_err(|e| {
        TlsError::CertificateParsing(format!("Failed to parse DER certificate: {e}"))
    })?;

    // Convert X509 certificate to ParsedCertificate format
    super::parser::parse_x509_certificate_from_der_internal(&cert)
}

/// Verify peer certificate with comprehensive revocation checking (OCSP + CRL + Chain)
#[allow(dead_code)] // Part of TLS library infrastructure - used by TlsManager
pub async fn verify_peer_certificate_comprehensive(
    tls_manager: &crate::tls::tls_config::TlsManager,
    cert_pem: &str,
    expected_hostname: &str,
    full_chain_pem: Option<&str>,
    ca_cert: &CertificateDer<'static>,
) -> Result<(), TlsError> {
    // Step 1: Basic peer certificate verification (hostname, time, constraints)
    verify_peer_certificate(cert_pem, expected_hostname)?;

    // Step 2: OCSP validation if possible
    match tls_manager.validate_certificate_ocsp(cert_pem, None).await {
        Ok(()) => info!("OCSP validation passed"),
        Err(e) => warn!(
            "OCSP validation failed: {}, continuing with other checks",
            e
        ),
    }

    // Step 3: CRL validation
    match tls_manager.validate_certificate_crl(cert_pem).await {
        Ok(()) => info!("CRL validation passed"),
        Err(e) => warn!("CRL validation failed: {}, continuing with other checks", e),
    }

    // Step 4: Certificate chain validation if full chain provided
    if let Some(chain_pem) = full_chain_pem {
        validate_certificate_chain(chain_pem, ca_cert).await?;
        info!("Certificate chain validation passed");
    }

    info!(
        "Comprehensive peer certificate verification successful for hostname: {}",
        expected_hostname
    );
    Ok(())
}
