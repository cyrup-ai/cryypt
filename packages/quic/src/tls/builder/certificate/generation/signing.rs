//! Certificate signing operations
//!
//! This module handles certificate signing including:
//! - Self-signed certificate creation
//! - CA-signed certificate creation
//! - Parameter setup and key generation

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::time::SystemTime;

use super::super::super::responses::{
    CertificateGenerationResponse, CertificateInfo, GenerationIssue, IssueSeverity,
};
use super::core::CertificateGeneratorWithDomain;

/// Perform complete certificate generation process
pub async fn perform_certificate_generation(
    generator: CertificateGeneratorWithDomain,
) -> CertificateGenerationResponse {
    // Create certificate parameters
    let mut params = match CertificateParams::new(generator.domains.clone()) {
        Ok(p) => p,
        Err(e) => {
            return create_parameter_error(e);
        }
    };

    // Set up distinguished name
    setup_distinguished_name(&mut params, &generator.domains);

    // Set validity period
    setup_validity_period(&mut params, generator.valid_for_days);

    // Add SAN entries with wildcard support
    match setup_san_entries(&mut params, &generator.domains, generator.is_wildcard) {
        Ok(()) => {}
        Err(response) => return response,
    }

    // Generate key pair
    let key_pair = match KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => {
            return create_key_generation_error(e);
        }
    };

    // Create certificate based on signing method
    let cert = match create_signed_certificate(&params, &key_pair, &generator) {
        Ok(cert) => cert,
        Err(response) => return response,
    };

    // Serialize certificate and key
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Handle file operations if save path is specified
    let files_created =
        match super::file_ops::save_certificate_files(&generator.save_path, &cert_pem, &key_pem)
            .await
        {
            Ok(files) => files,
            Err(response) => return response,
        };

    // Create successful response
    CertificateGenerationResponse {
        success: true,
        certificate_info: Some(create_certificate_info(&generator)),
        files_created,
        certificate_pem: Some(cert_pem),
        private_key_pem: Some(key_pem),
        issues: vec![],
    }
}

/// Set up distinguished name for certificate
fn setup_distinguished_name(params: &mut CertificateParams, domains: &[String]) {
    let mut distinguished_name = DistinguishedName::new();
    if let Some(first_domain) = domains.first() {
        distinguished_name.push(DnType::CommonName, first_domain);
    }
    params.distinguished_name = distinguished_name;
}

/// Set up validity period for certificate
fn setup_validity_period(params: &mut CertificateParams, valid_for_days: u32) {
    let now = SystemTime::now();
    params.not_before = now.into();
    params.not_after =
        (now + std::time::Duration::from_secs(valid_for_days as u64 * 24 * 3600)).into();
}

/// Set up SAN entries with wildcard support
fn setup_san_entries(
    params: &mut CertificateParams,
    domains: &[String],
    is_wildcard: bool,
) -> Result<(), CertificateGenerationResponse> {
    let mut san_entries = Vec::new();

    for domain in domains {
        // For wildcard certificates, ensure proper wildcard format
        let domain_to_use = if is_wildcard && !domain.starts_with("*.") {
            format!("*.{}", domain)
        } else {
            domain.clone()
        };

        let ia5_string = match domain_to_use.clone().try_into() {
            Ok(s) => s,
            Err(e) => {
                return Err(create_dns_name_error(&domain_to_use, e));
            }
        };
        san_entries.push(SanType::DnsName(ia5_string));

        // For wildcard certificates, also add the base domain
        if is_wildcard {
            let base_domain = if domain.starts_with("*.") {
                &domain[2..] // Remove "*."
            } else {
                domain
            };

            let base_ia5_string = match base_domain.to_string().try_into() {
                Ok(s) => s,
                Err(e) => {
                    return Err(create_base_dns_name_error(base_domain, e));
                }
            };
            san_entries.push(SanType::DnsName(base_ia5_string));
        }
    }

    params.subject_alt_names = san_entries;
    Ok(())
}

/// Create signed certificate based on configuration
fn create_signed_certificate(
    params: &CertificateParams,
    key_pair: &KeyPair,
    generator: &CertificateGeneratorWithDomain,
) -> Result<rcgen::Certificate, CertificateGenerationResponse> {
    if generator.self_signed {
        // Self-signed certificate
        params
            .self_signed(key_pair)
            .map_err(create_self_signed_error)
    } else if let Some(ca) = &generator.authority {
        // CA-signed certificate
        create_ca_signed_certificate(params, key_pair, ca)
    } else {
        Err(create_no_signing_method_error())
    }
}

/// Create CA-signed certificate
fn create_ca_signed_certificate(
    params: &CertificateParams,
    key_pair: &KeyPair,
    ca: &super::super::super::authority::CertificateAuthority,
) -> Result<rcgen::Certificate, CertificateGenerationResponse> {
    let ca_private_key_pem = match ca.private_key_pem.as_ref() {
        Some(key) => key,
        None => {
            return Err(create_no_ca_key_error());
        }
    };

    let ca_key_pair = match rcgen::KeyPair::from_pem(ca_private_key_pem) {
        Ok(kp) => kp,
        Err(e) => {
            return Err(create_ca_key_parse_error(e));
        }
    };

    let ca_issuer = match rcgen::Issuer::from_ca_cert_pem(&ca.certificate_pem, ca_key_pair) {
        Ok(issuer) => issuer,
        Err(e) => {
            return Err(create_ca_issuer_error(e));
        }
    };

    params
        .signed_by(key_pair, &ca_issuer)
        .map_err(create_ca_signing_error)
}

/// Create certificate info for successful response
fn create_certificate_info(generator: &CertificateGeneratorWithDomain) -> CertificateInfo {
    let now = SystemTime::now();
    CertificateInfo {
        subject: generator
            .domains
            .first()
            .unwrap_or(&"Unknown".to_string())
            .clone(),
        issuer: if generator.self_signed {
            generator
                .domains
                .first()
                .unwrap_or(&"Unknown".to_string())
                .clone()
        } else {
            "CA".to_string()
        },
        serial_number: "1".to_string(),
        valid_from: now,
        valid_until: now
            + std::time::Duration::from_secs(generator.valid_for_days as u64 * 24 * 3600),
        domains: generator.domains.clone(),
        is_ca: false,
        key_algorithm: "RSA".to_string(),
        key_size: Some(2048),
    }
}

// Error creation functions
fn create_parameter_error(e: rcgen::Error) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: None,
        private_key_pem: None,
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Failed to create certificate parameters: {e}"),
            suggestion: Some("Check certificate parameters and domain names".to_string()),
        }],
    }
}

fn create_key_generation_error(e: rcgen::Error) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: None,
        private_key_pem: None,
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Failed to generate key pair: {e}"),
            suggestion: Some("Check system entropy and crypto libraries".to_string()),
        }],
    }
}

fn create_dns_name_error(domain: &str, e: rcgen::Error) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: None,
        private_key_pem: None,
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Invalid DNS name '{}': {}", domain, e),
            suggestion: Some("Use valid DNS name format".to_string()),
        }],
    }
}

fn create_base_dns_name_error(base_domain: &str, e: rcgen::Error) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: None,
        private_key_pem: None,
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Invalid base DNS name '{}': {}", base_domain, e),
            suggestion: Some("Use valid DNS name format for base domain".to_string()),
        }],
    }
}

fn create_self_signed_error(e: rcgen::Error) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: None,
        private_key_pem: None,
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Failed to generate self-signed certificate: {e}"),
            suggestion: Some("Check certificate parameters".to_string()),
        }],
    }
}

fn create_no_ca_key_error() -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        certificate_pem: None,
        private_key_pem: None,
        files_created: vec![],
        issues: vec![GenerationIssue {
            message: "Cannot sign certificates with validation-only CA - no private key available"
                .to_string(),
            severity: IssueSeverity::Error,
            suggestion: Some(
                "Use a CA with a private key or load a different certificate authority".to_string(),
            ),
        }],
    }
}

fn create_ca_key_parse_error(e: rcgen::Error) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: None,
        private_key_pem: None,
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Failed to parse CA private key: {e}"),
            suggestion: Some("Check CA private key format".to_string()),
        }],
    }
}

fn create_ca_issuer_error(e: rcgen::Error) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: None,
        private_key_pem: None,
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Failed to create CA certificate: {e}"),
            suggestion: Some("Check CA certificate parameters".to_string()),
        }],
    }
}

fn create_ca_signing_error(e: rcgen::Error) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: None,
        private_key_pem: None,
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Failed to create certificate signed by CA: {e}"),
            suggestion: Some("Check CA certificate and certificate parameters".to_string()),
        }],
    }
}

fn create_no_signing_method_error() -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: None,
        private_key_pem: None,
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: "No signing method specified".to_string(),
            suggestion: Some("Use .self_signed() or .authority(ca)".to_string()),
        }],
    }
}
