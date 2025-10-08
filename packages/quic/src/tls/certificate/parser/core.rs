//! Core certificate parsing operations
//!
//! This module provides the main certificate parsing functions that coordinate
//! the various extraction operations and return structured certificate data.

use der::{Decode, Encode};
use std::collections::HashMap;
use x509_cert::Certificate as X509CertCert;

use crate::tls::errors::TlsError;
use crate::tls::types::ParsedCertificate;

use super::details_extraction::extract_certificate_details;
use super::key_extraction::extract_key_info_from_cert;
use super::name_extraction::extract_name_attributes;

/// Parse certificate from `X509Certificate` struct to extract actual certificate information
pub fn parse_x509_certificate_from_der_internal(
    cert: &X509CertCert,
) -> Result<ParsedCertificate, TlsError> {
    // Extract subject DN using x509-cert API
    let mut subject = HashMap::new();
    extract_name_attributes(&cert.tbs_certificate.subject, &mut subject);

    // Extract issuer DN using x509-cert API
    let mut issuer = HashMap::new();
    extract_name_attributes(&cert.tbs_certificate.issuer, &mut issuer);

    // Extract basic certificate info using x509-cert
    let (san_dns_names, san_ip_addresses, is_ca, key_usage, not_before, not_after) =
        extract_certificate_details(cert);

    // Extract OCSP and CRL URLs from certificate extensions
    let mut ocsp_urls = Vec::new();
    let mut crl_urls = Vec::new();

    // Iterate through all extensions to find Authority Information Access and CRL Distribution Points
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions {
            let oid_str = ext.extn_id.to_string();

            // Authority Information Access extension (1.3.6.1.5.5.7.1.1)
            if oid_str == "1.3.6.1.5.5.7.1.1" {
                // Extract OCSP URLs from Authority Information Access
                // This is a simplified extraction - proper ASN.1 parsing would be more robust
                let ext_bytes = ext.extn_value.as_bytes();

                // Look for HTTP URLs in the extension data
                for i in 0..ext_bytes.len().saturating_sub(4) {
                    if &ext_bytes[i..i + 4] == b"http" {
                        // Found potential URL start
                        let mut url_bytes = Vec::new();
                        for &byte in &ext_bytes[i..] {
                            if (0x20..=0x7E).contains(&byte) {
                                // Printable ASCII
                                url_bytes.push(byte);
                            } else {
                                break;
                            }
                        }
                        if let Ok(url) = String::from_utf8(url_bytes)
                            && url.starts_with("http")
                            && !ocsp_urls.contains(&url)
                        {
                            ocsp_urls.push(url);
                        }
                    }
                }
            }

            // CRL Distribution Points extension (2.5.29.31)
            if oid_str == "2.5.29.31" {
                // Extract CRL URLs from CRL Distribution Points
                let ext_bytes = ext.extn_value.as_bytes();

                // Look for HTTP URLs in the extension data
                for i in 0..ext_bytes.len().saturating_sub(4) {
                    if &ext_bytes[i..i + 4] == b"http" {
                        // Found potential URL start
                        let mut url_bytes = Vec::new();
                        for &byte in &ext_bytes[i..] {
                            if (0x20..=0x7E).contains(&byte) {
                                // Printable ASCII
                                url_bytes.push(byte);
                            } else {
                                break;
                            }
                        }
                        if let Ok(url) = String::from_utf8(url_bytes)
                            && url.starts_with("http")
                            && !crl_urls.contains(&url)
                        {
                            crl_urls.push(url);
                        }
                    }
                }
            }
        }
    }

    // Get raw DER bytes for OCSP validation
    let subject_der = cert
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| TlsError::CertificateParsing(format!("Failed to encode subject: {e}")))?;

    let public_key_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| TlsError::CertificateParsing(format!("Failed to encode public key: {e}")))?;

    // Extract serial number
    let serial_number = cert.tbs_certificate.serial_number.as_bytes().to_vec();

    // Extract key algorithm and size information
    let (key_algorithm, key_size) = extract_key_info_from_cert(cert);

    Ok(ParsedCertificate {
        subject,
        issuer,
        san_dns_names,
        san_ip_addresses,
        is_ca,
        key_usage,
        not_before,
        not_after,
        serial_number,
        ocsp_urls,
        crl_urls,
        subject_der,
        public_key_der,
        key_algorithm,
        key_size,
    })
}

/// Parse certificate from PEM data to extract actual certificate information
pub fn parse_certificate_from_pem_internal(pem_data: &str) -> Result<ParsedCertificate, TlsError> {
    // Parse PEM to get DER bytes using rustls-pemfile
    let mut cursor = std::io::Cursor::new(pem_data.as_bytes());
    let cert_der = rustls_pemfile::certs(&mut cursor)
        .next()
        .ok_or_else(|| TlsError::CertificateParsing("No certificate in PEM data".to_string()))?
        .map_err(|e| TlsError::CertificateParsing(format!("Failed to parse PEM: {e}")))?;

    // Parse X.509 certificate using x509-cert
    let cert = X509CertCert::from_der(&cert_der)
        .map_err(|e| TlsError::CertificateParsing(format!("X.509 parsing failed: {e}")))?;

    // Delegate to the DER function to avoid code duplication
    parse_x509_certificate_from_der_internal(&cert)
}
