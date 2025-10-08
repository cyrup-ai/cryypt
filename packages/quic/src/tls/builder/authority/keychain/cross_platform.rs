//! Cross-platform (Linux/Windows) certificate authority operations
//!
//! This module handles CA loading from system certificate stores on non-macOS platforms.

use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::tls::builder::authority::core::{
    CaMetadata, CaSource, CertificateAuthority, dn_hashmap_to_string, serial_to_string,
};

pub(super) fn load_from_system_store(
    name: String,
) -> super::super::super::responses::CertificateAuthorityResponse {
    // Common certificate store locations
    let cert_paths = vec![
        format!("/etc/ssl/certs/{}.crt", name),
        format!("/usr/local/share/ca-certificates/{}.crt", name),
        format!("/etc/pki/ca-trust/source/anchors/{}.crt", name),
        format!("/etc/ca-certificates/trust-source/anchors/{}.crt", name),
    ];

    let key_paths = vec![
        format!("/etc/ssl/private/{}.key", name),
        format!("/usr/local/share/ca-certificates/{}.key", name),
        format!("/etc/pki/ca-trust/source/anchors/{}.key", name),
        format!("/etc/ca-certificates/trust-source/anchors/{}.key", name),
    ];

    let mut found_cert_path = None;
    let mut found_key_path = None;

    // Find certificate file
    for cert_path in cert_paths {
        if PathBuf::from(&cert_path).exists() {
            found_cert_path = Some(cert_path);
            break;
        }
    }

    // Find key file
    for key_path in key_paths {
        if PathBuf::from(&key_path).exists() {
            found_key_path = Some(key_path);
            break;
        }
    }

    let cert_path = match found_cert_path {
        Some(path) => path,
        None => {
            return super::super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::super::responses::CaOperation::LoadFailed,
                issues: vec![format!(
                    "Certificate '{}' not found in system certificate stores",
                    name
                )],
                files_created: vec![],
            };
        }
    };

    let key_path = match found_key_path {
        Some(path) => path,
        None => {
            return super::super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::super::responses::CaOperation::LoadFailed,
                issues: vec![format!(
                    "Private key '{}' not found in system certificate stores",
                    name
                )],
                files_created: vec![],
            };
        }
    };

    let cert_pem = match fs::read_to_string(&cert_path) {
        Ok(content) => content,
        Err(e) => {
            return super::super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::super::responses::CaOperation::LoadFailed,
                issues: vec![format!(
                    "Failed to read certificate file {}: {}",
                    cert_path, e
                )],
                files_created: vec![],
            };
        }
    };

    let key_pem = match fs::read_to_string(&key_path) {
        Ok(content) => content,
        Err(e) => {
            return super::super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::super::responses::CaOperation::LoadFailed,
                issues: vec![format!(
                    "Failed to read private key file {}: {}",
                    key_path, e
                )],
                files_created: vec![],
            };
        }
    };

    // Validate the loaded certificate
    match crate::tls::certificate::parsing::parse_certificate_from_pem(&cert_pem) {
        Ok(parsed_cert) => {
            // Validate CA constraints
            if let Err(e) =
                crate::tls::certificate::parsing::validate_basic_constraints(&parsed_cert, true)
            {
                return super::super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Invalid CA certificate in system store: {e}")],
                    files_created: vec![],
                };
            }

            // Validate time constraints
            if let Err(e) =
                crate::tls::certificate::parsing::validate_certificate_time(&parsed_cert)
            {
                return super::super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Expired CA certificate in system store: {e}")],
                    files_created: vec![],
                };
            }

            // Create KeyPair from loaded key
            match rcgen::KeyPair::from_pem(&key_pem) {
                Ok(key_pair) => {
                    // Create Certificate from parameters
                    let _issuer = match rcgen::Issuer::from_ca_cert_pem(&cert_pem, key_pair) {
                        Ok(issuer) => issuer,
                        Err(e) => {
                            return super::super::super::responses::CertificateAuthorityResponse {
                                success: false,
                                authority: None,
                                operation: super::super::super::responses::CaOperation::LoadFailed,
                                issues: vec![format!(
                                    "Failed to create issuer from CA cert: {}",
                                    e
                                )],
                                files_created: vec![],
                            };
                        }
                    };

                    let authority = CertificateAuthority {
                        name: name.clone(),
                        certificate_pem: cert_pem.clone(),
                        private_key_pem: Some(key_pem),
                        metadata: CaMetadata {
                            subject: dn_hashmap_to_string(&parsed_cert.subject),
                            issuer: dn_hashmap_to_string(&parsed_cert.issuer),
                            serial_number: serial_to_string(&parsed_cert.serial_number),
                            valid_from: parsed_cert.not_before,
                            valid_until: parsed_cert.not_after,
                            key_algorithm: parsed_cert.key_algorithm.clone(),
                            key_size: parsed_cert.key_size,
                            created_at: SystemTime::now(),
                            source: CaSource::Keychain,
                        },
                    };

                    super::super::super::responses::CertificateAuthorityResponse {
                        success: true,
                        authority: Some(authority),
                        operation: super::super::super::responses::CaOperation::Loaded,
                        issues: vec![],
                        files_created: vec![],
                    }
                }
                Err(e) => super::super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Invalid private key in system store: {e}")],
                    files_created: vec![],
                },
            }
        }
        Err(e) => super::super::super::responses::CertificateAuthorityResponse {
            success: false,
            authority: None,
            operation: super::super::super::responses::CaOperation::LoadFailed,
            issues: vec![format!("Failed to parse system certificate: {e}")],
            files_created: vec![],
        },
    }
}
