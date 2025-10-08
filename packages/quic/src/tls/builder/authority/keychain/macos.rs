//! macOS keychain certificate authority operations
//!
//! This module handles CA loading from macOS Keychain using the security-framework.

use base64::{Engine as _, engine::general_purpose};
use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};
use security_framework::os::macos::item::ItemSearchOptionsExt;
use security_framework::os::macos::keychain::SecKeychain;
use std::time::SystemTime;

use crate::tls::builder::authority::core::{
    CaMetadata, CaSource, CertificateAuthority, dn_hashmap_to_string, serial_to_string,
};

pub(super) fn load_from_keychain(
    name: String,
) -> super::super::super::responses::CertificateAuthorityResponse {
    let keychain = match get_system_keychain() {
        Ok(k) => k,
        Err(e) => return create_keychain_error_response(&e),
    };

    // Clone keychain for reuse in private key search
    let keychain_for_key_search = keychain.clone();

    let cert_item = match find_certificate_in_keychain(&keychain, &name) {
        Ok(cert) => cert,
        Err(response) => return response,
    };

    // Export certificate to DER format then convert to PEM
    let cert_data = cert_item.to_der();

    let cert_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        general_purpose::STANDARD
            .encode(&cert_data)
            .chars()
            .collect::<Vec<char>>()
            .chunks(64)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n")
    );

    // Search for associated private key using cloned keychain
    let private_keys = match ItemSearchOptions::new()
        .keychains(&[keychain_for_key_search])
        .class(ItemClass::key())
        .label(&name)
        .load_refs(true)
        .search()
    {
        Ok(keys) => keys,
        Err(e) => {
            return super::super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::super::responses::CaOperation::LoadFailed,
                issues: vec![format!(
                    "Private key '{}' not found in keychain: {}",
                    name, e
                )],
                files_created: vec![],
            };
        }
    };

    if private_keys.is_empty() {
        return super::super::super::responses::CertificateAuthorityResponse {
            success: false,
            authority: None,
            operation: super::super::super::responses::CaOperation::LoadFailed,
            issues: vec![format!("No private key found for certificate: {name}")],
            files_created: vec![],
        };
    }

    let private_key = match &private_keys[0] {
        SearchResult::Ref(Reference::Key(key)) => key,
        _ => {
            return super::super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::super::responses::CaOperation::LoadFailed,
                issues: vec![format!(
                    "Expected private key, found different type for: {}",
                    name
                )],
                files_created: vec![],
            };
        }
    };

    let key_data = match private_key.external_representation() {
        Some(data) => data,
        None => {
            return super::super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::super::responses::CaOperation::LoadFailed,
                issues: vec![format!("Failed to extract private key: key not available")],
                files_created: vec![],
            };
        }
    };

    let key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        general_purpose::STANDARD
            .encode(&*key_data)
            .chars()
            .collect::<Vec<char>>()
            .chunks(64)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n")
    );

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
                    issues: vec![format!("Invalid CA certificate in keychain: {e}")],
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
                    issues: vec![format!("Expired CA certificate in keychain: {e}")],
                    files_created: vec![],
                };
            }

            // Create KeyPair from loaded key
            match rcgen::KeyPair::from_pem(&key_pem) {
                Ok(key_pair) => {
                    // Create Issuer for signing
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
                    issues: vec![format!("Invalid private key in keychain: {e}")],
                    files_created: vec![],
                },
            }
        }
        Err(e) => super::super::super::responses::CertificateAuthorityResponse {
            success: false,
            authority: None,
            operation: super::super::super::responses::CaOperation::LoadFailed,
            issues: vec![format!("Failed to parse keychain certificate: {e}")],
            files_created: vec![],
        },
    }
}

/// Get the system keychain
fn get_system_keychain() -> Result<SecKeychain, security_framework::base::Error> {
    SecKeychain::default()
}

/// Create an error response for keychain access failures
fn create_keychain_error_response(
    error: &security_framework::base::Error,
) -> super::super::super::responses::CertificateAuthorityResponse {
    super::super::super::responses::CertificateAuthorityResponse {
        success: false,
        authority: None,
        operation: super::super::super::responses::CaOperation::LoadFailed,
        issues: vec![format!("Failed to access system keychain: {error}")],
        files_created: vec![],
    }
}

/// Find a certificate in the keychain by name
fn find_certificate_in_keychain(
    keychain: &SecKeychain,
    name: &str,
) -> Result<
    security_framework::certificate::SecCertificate,
    super::super::super::responses::CertificateAuthorityResponse,
> {
    let cert_items = match ItemSearchOptions::new()
        .keychains(&[keychain.clone()])
        .class(ItemClass::certificate())
        .label(name)
        .load_refs(true)
        .search()
    {
        Ok(items) => items,
        Err(e) => {
            return Err(
                super::super::super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::super::super::responses::CaOperation::LoadFailed,
                    issues: vec![format!(
                        "Certificate '{}' not found in keychain: {}",
                        name, e
                    )],
                    files_created: vec![],
                },
            );
        }
    };

    if cert_items.is_empty() {
        return Err(
            super::super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::super::responses::CaOperation::LoadFailed,
                issues: vec![format!("No certificate found with name: {name}")],
                files_created: vec![],
            },
        );
    }

    match &cert_items[0] {
        SearchResult::Ref(Reference::Certificate(cert)) => Ok(cert.clone()),
        _ => Err(
            super::super::super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::super::super::responses::CaOperation::LoadFailed,
                issues: vec![format!("Invalid certificate reference for: {name}")],
                files_created: vec![],
            },
        ),
    }
}
