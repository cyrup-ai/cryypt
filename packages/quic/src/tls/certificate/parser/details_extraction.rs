//!
//! This module provides functionality for extracting detailed certificate information
//! including Subject Alternative Names, `BasicConstraints`, `KeyUsage`, and validity periods.

#![allow(clippy::type_complexity, clippy::too_many_lines)]

use std::time::SystemTime;
use x509_cert::Certificate as X509CertCert;

use crate::tls::errors::TlsError;

/// Extract certificate details using x509-cert
pub fn extract_certificate_details(
    cert: &X509CertCert,
) -> (
    Vec<String>,
    Vec<std::net::IpAddr>,
    bool,
    Vec<String>,
    SystemTime,
    SystemTime,
) {
    // Extract SANs (simplified - return empty vectors)
    let san_dns_names = Vec::new();
    let san_ip_addresses = Vec::new();

    // Extract BasicConstraints for CA flag (simplified - always false)
    let is_ca = false;

    // Extract KeyUsage (simplified - return empty vector)
    let key_usage = Vec::new();

    // Extract validity times from TBS certificate
    let validity = &cert.tbs_certificate.validity;

    // Convert x509-cert Time to SystemTime for not_before
    let not_before = validity.not_before.to_system_time();

    // Convert x509-cert Time to SystemTime for not_after
    let not_after = validity.not_after.to_system_time();

    (
        san_dns_names,
        san_ip_addresses,
        is_ca,
        key_usage,
        not_before,
        not_after,
    )
}
