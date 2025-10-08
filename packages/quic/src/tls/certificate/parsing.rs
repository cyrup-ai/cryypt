//! Certificate parsing and validation functions

use std::time::SystemTime;

use crate::tls::errors::TlsError;
use crate::tls::types::{CertificateUsage, ParsedCertificate};

/// Parse certificate from PEM data to extract actual certificate information
pub fn parse_certificate_from_pem(pem_data: &str) -> Result<ParsedCertificate, TlsError> {
    super::parser::parse_certificate_from_pem_internal(pem_data)
}

/// Validate certificate time constraints
pub fn validate_certificate_time(parsed_cert: &ParsedCertificate) -> Result<(), TlsError> {
    validate_certificate_time_internal(parsed_cert)
}

/// Validate `BasicConstraints` extension
pub fn validate_basic_constraints(
    parsed_cert: &ParsedCertificate,
    expected_ca: bool,
) -> Result<(), TlsError> {
    validate_basic_constraints_internal(parsed_cert, expected_ca)
}

/// Validate `KeyUsage` extension
pub fn validate_key_usage(
    parsed_cert: &ParsedCertificate,
    usage: CertificateUsage,
) -> Result<(), TlsError> {
    validate_key_usage_internal(parsed_cert, usage)
}

/// Verify hostname against certificate Subject Alternative Names (SANs)
pub fn verify_hostname(parsed_cert: &ParsedCertificate, hostname: &str) -> Result<(), TlsError> {
    // First try to parse hostname as IP address
    if let Ok(ip_addr) = hostname.parse::<std::net::IpAddr>() {
        // Check against IP SANs
        if parsed_cert.san_ip_addresses.contains(&ip_addr) {
            return Ok(());
        }
        return Err(TlsError::PeerVerification(format!(
            "IP address {hostname} not found in certificate SANs"
        )));
    }

    // Check against DNS SANs
    for san_dns in &parsed_cert.san_dns_names {
        if match_hostname(hostname, san_dns) {
            return Ok(());
        }
    }

    // Also check against Common Name as fallback (though SANs should be preferred)
    if let Some(cn) = parsed_cert.subject.get("CN")
        && match_hostname(hostname, cn)
    {
        tracing::warn!("Using Common Name for hostname verification - SANs should be preferred");
        return Ok(());
    }

    Err(TlsError::PeerVerification(format!(
        "Hostname {hostname} does not match any certificate SANs or Common Name"
    )))
}

/// Verify peer certificate against expected hostname
#[allow(dead_code)] // Part of TLS library infrastructure - used by validation module
pub fn verify_peer_certificate(cert_pem: &str, expected_hostname: &str) -> Result<(), TlsError> {
    // Parse the certificate
    let parsed_cert = parse_certificate_from_pem(cert_pem)?;

    // Validate certificate time constraints
    validate_certificate_time_internal(&parsed_cert)?;

    // Validate this is an end-entity certificate (not CA)
    validate_basic_constraints_internal(&parsed_cert, false)?;

    // Validate KeyUsage for server authentication
    validate_key_usage_internal(&parsed_cert, CertificateUsage::ServerAuth)?;

    // Verify hostname matches
    verify_hostname(&parsed_cert, expected_hostname)?;

    tracing::info!(
        "Successfully verified peer certificate for hostname: {}",
        expected_hostname
    );
    Ok(())
}

/// Match hostname against a DNS name pattern (supports wildcards)
fn match_hostname(hostname: &str, pattern: &str) -> bool {
    // Convert to lowercase for case-insensitive comparison
    let hostname = hostname.to_lowercase();
    let pattern = pattern.to_lowercase();

    // Exact match
    if hostname == pattern {
        return true;
    }

    // Wildcard matching - only support single level wildcard at the beginning
    if let Some(pattern_suffix) = pattern.strip_prefix("*.") {
        // Remove "*."

        // The hostname must have exactly one more label than the pattern
        if hostname.ends_with(pattern_suffix) {
            let hostname_prefix = &hostname[..hostname.len() - pattern_suffix.len()];

            // Ensure the prefix doesn't contain dots (single level wildcard)
            if !hostname_prefix.is_empty()
                && !hostname_prefix.contains('.')
                && hostname_prefix.ends_with('.')
            {
                return true;
            }
        }
    }

    false
}

/// Validate certificate expiration and time constraints
fn validate_certificate_time_internal(parsed_cert: &ParsedCertificate) -> Result<(), TlsError> {
    let now = SystemTime::now();

    // Check if certificate is not yet valid
    if now < parsed_cert.not_before {
        return Err(TlsError::CertificateExpired(format!(
            "Certificate is not yet valid (not before: {:?}, current time: {:?})",
            parsed_cert.not_before, now
        )));
    }

    // Check if certificate is expired
    if now > parsed_cert.not_after {
        return Err(TlsError::CertificateExpired(format!(
            "Certificate has expired (not after: {:?}, current time: {:?})",
            parsed_cert.not_after, now
        )));
    }

    // Check for expiration warning (within 30 days)
    if let Ok(duration_until_expiry) = parsed_cert.not_after.duration_since(now)
        && duration_until_expiry.as_secs() < 30 * 24 * 3600
    {
        // 30 days
        tracing::warn!(
            "Certificate expires soon: {} days remaining (expires: {:?})",
            duration_until_expiry.as_secs() / (24 * 3600),
            parsed_cert.not_after
        );
    }

    Ok(())
}

/// Validate certificate `BasicConstraints` for CA usage
fn validate_basic_constraints_internal(
    parsed_cert: &ParsedCertificate,
    expected_ca: bool,
) -> Result<(), TlsError> {
    if parsed_cert.is_ca != expected_ca {
        if expected_ca {
            return Err(TlsError::CertificateValidation(
                "Certificate is not a valid CA certificate (BasicConstraints CA=false)".to_string(),
            ));
        }
        return Err(TlsError::CertificateValidation(
            "End-entity certificate incorrectly marked as CA (BasicConstraints CA=true)"
                .to_string(),
        ));
    }

    // For CA certificates, ensure they have the keyCertSign usage
    if expected_ca && !parsed_cert.key_usage.contains(&"keyCertSign".to_string()) {
        return Err(TlsError::CertificateValidation(
            "CA certificate missing required keyCertSign usage".to_string(),
        ));
    }

    Ok(())
}

/// Validate certificate `KeyUsage` extension for intended purpose
fn validate_key_usage_internal(
    parsed_cert: &ParsedCertificate,
    usage: CertificateUsage,
) -> Result<(), TlsError> {
    match usage {
        CertificateUsage::CertificateAuthority => {
            // CA certificates must have keyCertSign and should have cRLSign
            if !parsed_cert.key_usage.contains(&"keyCertSign".to_string()) {
                return Err(TlsError::CertificateValidation(
                    "CA certificate missing required keyCertSign usage".to_string(),
                ));
            }

            // CRL signing is recommended but not strictly required
            if !parsed_cert.key_usage.contains(&"cRLSign".to_string()) {
                tracing::warn!("CA certificate missing recommended cRLSign usage");
            }
        }
        CertificateUsage::ServerAuth => {
            // Server certificates must have digitalSignature for TLS
            if !parsed_cert
                .key_usage
                .contains(&"digitalSignature".to_string())
            {
                return Err(TlsError::CertificateValidation(
                    "Server certificate missing required digitalSignature usage".to_string(),
                ));
            }

            // Key encipherment may be required for RSA key exchange
            if !parsed_cert
                .key_usage
                .contains(&"keyEncipherment".to_string())
            {
                tracing::warn!(
                    "Server certificate missing keyEncipherment usage (may be required for RSA)"
                );
            }
        }
        CertificateUsage::ClientAuth => {
            // Client certificates must have digitalSignature
            if !parsed_cert
                .key_usage
                .contains(&"digitalSignature".to_string())
            {
                return Err(TlsError::CertificateValidation(
                    "Client certificate missing required digitalSignature usage".to_string(),
                ));
            }
        }
    }

    // Ensure certificate is not marked as CA if it's for server/client auth
    match usage {
        CertificateUsage::ServerAuth | CertificateUsage::ClientAuth => {
            if parsed_cert.is_ca {
                return Err(TlsError::CertificateValidation(
                    "End-entity certificate incorrectly marked as CA".to_string(),
                ));
            }
        }
        CertificateUsage::CertificateAuthority => {
            if !parsed_cert.is_ca {
                return Err(TlsError::CertificateValidation(
                    "CA certificate not marked as CA in BasicConstraints".to_string(),
                ));
            }
        }
    }

    Ok(())
}
