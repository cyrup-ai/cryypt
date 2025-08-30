//! Certificate Authority domain object and builders


use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

use crate::tls::errors::TlsError;

/// Convert a HashMap of distinguished name components to a string representation
fn dn_hashmap_to_string(dn_map: &std::collections::HashMap<String, String>) -> String {
    if dn_map.is_empty() {
        return "Unknown".to_string();
    }
    
    dn_map.iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Convert Vec<u8> serial number to hex string representation
fn serial_to_string(serial: &[u8]) -> String {
    serial.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Certificate Authority domain object with serialization support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    pub name: String,
    pub certificate_pem: String,
    /// Private key PEM. None for validation-only CAs (e.g., remote CAs)
    pub private_key_pem: Option<String>,
    pub metadata: CaMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaMetadata {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub valid_from: SystemTime,
    pub valid_until: SystemTime,
    pub key_algorithm: String,
    pub key_size: Option<u32>,
    pub created_at: SystemTime,
    pub source: CaSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaSource {
    Filesystem { path: PathBuf },
    Keychain,
    Remote { url: String },
    Generated,
}

impl CertificateAuthority {
    /// Check if the certificate authority is currently valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now();
        now >= self.metadata.valid_from && now <= self.metadata.valid_until
    }

    /// Get duration until expiry
    pub fn expires_in(&self) -> Result<Duration, TlsError> {
        let now = SystemTime::now();
        self.metadata.valid_until.duration_since(now).map_err(|_| {
            TlsError::CertificateExpired("Certificate authority has expired".to_string())
        })
    }

    /// Check if this CA can sign certificates for the given domain
    pub fn can_sign_for_domain(&self, domain: &str) -> bool {
        use crate::tls::certificate::parsing::{parse_certificate_from_pem, verify_hostname};
        
        if !self.is_valid() {
            return false;
        }
        
        // Parse CA certificate to check constraints
        let ca_cert = match parse_certificate_from_pem(&self.certificate_pem) {
            Ok(cert) => cert,
            Err(e) => {
                tracing::error!("Failed to parse CA certificate for domain validation: {}", e);
                return false;
            }
        };
        
        // Check if this is a proper CA
        if !ca_cert.is_ca {
            tracing::warn!("Certificate is not marked as CA, cannot sign for domain: {}", domain);
            return false;
        }
        
        // Delegate to existing hostname verification logic
        // If the CA certificate itself can validate this domain, then it can sign for it
        match verify_hostname(&ca_cert, domain) {
            Ok(()) => {
                tracing::debug!("CA can sign for domain '{}' - matches CA constraints", domain);
                true
            }
            Err(_) => {
                tracing::warn!("CA certificate cannot sign for domain '{}' - no matching constraints", domain);
                false
            }
        }
    }
}

/// Builder for certificate authority operations
#[derive(Debug, Clone)]
pub struct AuthorityBuilder {
    name: String,
}

impl AuthorityBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    /// Work with filesystem-based certificate authority
    pub fn path<P: AsRef<Path>>(self, path: P) -> AuthorityFilesystemBuilder {
        AuthorityFilesystemBuilder {
            name: self.name,
            path: path.as_ref().to_path_buf(),
            common_name: None,
            valid_for_years: 10,
            key_size: 2048,
        }
    }

    /// Work with keychain-based certificate authority (macOS/Windows)
    pub fn keychain(self) -> AuthorityKeychainBuilder {
        AuthorityKeychainBuilder { name: self.name }
    }

    /// Work with remote certificate authority
    pub fn url(self, url: &str) -> AuthorityRemoteBuilder {
        AuthorityRemoteBuilder {
            name: self.name,
            url: url.to_string(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// Builder for filesystem certificate authority operations
#[derive(Debug, Clone)]
pub struct AuthorityFilesystemBuilder {
    name: String,
    path: PathBuf,
    common_name: Option<String>,
    valid_for_years: u32,
    key_size: u32,
}

impl AuthorityFilesystemBuilder {
    /// Set common name for certificate authority creation
    pub fn common_name(self, cn: &str) -> Self {
        Self {
            common_name: Some(cn.to_string()),
            ..self
        }
    }

    /// Set validity period in years for certificate authority creation
    pub fn valid_for_years(self, years: u32) -> Self {
        Self {
            valid_for_years: years,
            ..self
        }
    }

    /// Set key size for certificate authority creation
    pub fn key_size(self, bits: u32) -> Self {
        Self {
            key_size: bits,
            ..self
        }
    }

    /// Create a new certificate authority
    pub async fn create(self) -> super::responses::CertificateAuthorityResponse {
        use std::time::SystemTime;

        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

        // Create directory if it doesn't exist
        if let Err(e) = std::fs::create_dir_all(&self.path) {
            return super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::responses::CaOperation::CreateFailed,
                issues: vec![format!("Failed to create directory: {}", e)],
                files_created: vec![],
            };
        }

        // Generate CA certificate
        let mut params = match CertificateParams::new(vec![]) {
            Ok(params) => params,
            Err(e) => {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::CreateFailed,
                    issues: vec![format!("Failed to create certificate parameters: {}", e)],
                    files_created: vec![],
                };
            }
        };
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let mut distinguished_name = DistinguishedName::new();
        let common_name = self.common_name.unwrap_or_else(|| self.name.clone());
        distinguished_name.push(DnType::CommonName, &common_name);
        params.distinguished_name = distinguished_name;

        // Set validity period
        let now = SystemTime::now();
        params.not_before = now.into();
        params.not_after = (now
            + std::time::Duration::from_secs(365 * 24 * 3600 * self.valid_for_years as u64))
        .into();

        // Generate key pair
        let key_pair = KeyPair::generate()
            .map_err(|e| format!("Failed to generate key pair: {}", e));

        let key_pair = match key_pair {
            Ok(kp) => kp,
            Err(e) => {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::CreateFailed,
                    issues: vec![e],
                    files_created: vec![],
                };
            }
        };

        let cert = match params.self_signed(&key_pair) {
            Ok(c) => c,
            Err(e) => {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::CreateFailed,
                    issues: vec![format!("Failed to generate certificate: {}", e)],
                    files_created: vec![],
                };
            }
        };

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Both cert_pem and key_pem are now direct String results
        let (cert_pem, key_pem) = (cert_pem, key_pem);

        // Save files
        let cert_path = self.path.join("ca.crt");
        let key_path = self.path.join("ca.key");
        let mut files_created = vec![];

        if let Err(e) = std::fs::write(&cert_path, &cert_pem) {
            return super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::responses::CaOperation::CreateFailed,
                issues: vec![format!("Failed to write certificate: {}", e)],
                files_created,
            };
        }
        files_created.push(cert_path);

        if let Err(e) = std::fs::write(&key_path, &key_pem) {
            return super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::responses::CaOperation::CreateFailed,
                issues: vec![format!("Failed to write private key: {}", e)],
                files_created,
            };
        }
        files_created.push(key_path);

        // Create authority object
        let authority = CertificateAuthority {
            name: self.name.clone(),
            certificate_pem: cert_pem,
            private_key_pem: Some(key_pem),
            metadata: CaMetadata {
                subject: common_name.clone(),
                issuer: common_name,
                serial_number: "1".to_string(), // CA serial number
                valid_from: now,
                valid_until: now
                    + std::time::Duration::from_secs(365 * 24 * 3600 * self.valid_for_years as u64),
                key_algorithm: "RSA".to_string(),
                key_size: Some(self.key_size),
                created_at: now,
                source: CaSource::Generated,
            },
        };

        super::responses::CertificateAuthorityResponse {
            success: true,
            authority: Some(authority),
            operation: super::responses::CaOperation::Created,
            issues: vec![],
            files_created,
        }
    }

    /// Load existing certificate authority from filesystem
    pub async fn load(self) -> super::responses::CertificateAuthorityResponse {
        use std::time::SystemTime;

        use crate::tls::certificate::parse_certificate_from_pem;

        let cert_path = self.path.join("ca.crt");
        let key_path = self.path.join("ca.key");

        // Check if both files exist
        if !cert_path.exists() || !key_path.exists() {
            return super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::responses::CaOperation::LoadFailed,
                issues: vec![format!("CA files not found at {:?}", self.path)],
                files_created: vec![],
            };
        }

        // Read certificate and key files
        let cert_pem = match std::fs::read_to_string(&cert_path) {
            Ok(content) => content,
            Err(e) => {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to read certificate: {}", e)],
                    files_created: vec![],
                };
            }
        };

        let key_pem = match std::fs::read_to_string(&key_path) {
            Ok(content) => content,
            Err(e) => {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to read private key: {}", e)],
                    files_created: vec![],
                };
            }
        };

        // Parse certificate to extract metadata
        let parsed_cert = match parse_certificate_from_pem(&cert_pem) {
            Ok(cert) => cert,
            Err(e) => {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to parse certificate: {}", e)],
                    files_created: vec![],
                };
            }
        };

        let authority = CertificateAuthority {
            name: self.name.clone(),
            certificate_pem: cert_pem,
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
                source: CaSource::Filesystem {
                    path: self.path.clone(),
                },
            },
        };

        super::responses::CertificateAuthorityResponse {
            success: true,
            authority: Some(authority),
            operation: super::responses::CaOperation::Loaded,
            issues: vec![],
            files_created: vec![],
        }
    }
}

/// Builder for keychain certificate authority operations
#[derive(Debug, Clone)]
pub struct AuthorityKeychainBuilder {
    name: String,
}

impl AuthorityKeychainBuilder {
    /// Load certificate authority from system keychain
    pub async fn load(self) -> super::responses::CertificateAuthorityResponse {
        // macOS keychain implementation using security-framework
        #[cfg(target_os = "macos")]
        {
            use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult, Reference};
            use security_framework::os::macos::keychain::SecKeychain;
            use security_framework::os::macos::item::ItemSearchOptionsExt;
            
            // Access system keychain
            let keychain = match SecKeychain::default() {
                Ok(k) => k,
                Err(e) => return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to access system keychain: {}", e)],
                    files_created: vec![],
                }
            };

            // Clone keychain for reuse in private key search
            let keychain_for_key_search = keychain.clone();

            // Search for CA certificate by name using ItemSearchOptions
            let cert_items = match ItemSearchOptions::new()
                .keychains(&[keychain])
                .class(ItemClass::certificate())
                .label(&self.name)
                .load_refs(true)
                .search() {
                Ok(items) => items,
                Err(e) => return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Certificate '{}' not found in keychain: {}", self.name, e)],
                    files_created: vec![],
                }
            };

            if cert_items.is_empty() {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("No certificate found with name: {}", self.name)],
                    files_created: vec![],
                };
            }

            let cert_item = match &cert_items[0] {
                SearchResult::Ref(Reference::Certificate(cert)) => cert,
                _ => return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Expected certificate, found different type for: {}", self.name)],
                    files_created: vec![],
                }
            };
            
            // Export certificate to DER format then convert to PEM  
            let cert_data = cert_item.to_der();

            let cert_pem = format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                general_purpose::STANDARD.encode(&cert_data)
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
                .label(&self.name)
                .load_refs(true)
                .search() {
                Ok(keys) => keys,
                Err(e) => return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Private key '{}' not found in keychain: {}", self.name, e)],
                    files_created: vec![],
                }
            };

            if private_keys.is_empty() {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("No private key found for certificate: {}", self.name)],
                    files_created: vec![],
                };
            }

            let private_key = match &private_keys[0] {
                SearchResult::Ref(Reference::Key(key)) => key,
                _ => return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Expected private key, found different type for: {}", self.name)],
                    files_created: vec![],
                }
            };
            
            let key_data = match private_key.external_representation() {
                Some(data) => data,
                None => return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to extract private key: key not available")],
                    files_created: vec![],
                }
            };

            let key_pem = format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                general_purpose::STANDARD.encode(&*key_data)
                    .chars()
                    .collect::<Vec<char>>()
                    .chunks(64)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect::<Vec<String>>()
                    .join("\n")
            );

            // Validate the loaded certificate
            match super::super::certificate::parsing::parse_certificate_from_pem(&cert_pem) {
                Ok(parsed_cert) => {
                    // Validate CA constraints
                    if let Err(e) = super::super::certificate::parsing::validate_basic_constraints(&parsed_cert, true) {
                        return super::responses::CertificateAuthorityResponse {
                            success: false,
                            authority: None,
                            operation: super::responses::CaOperation::LoadFailed,
                            issues: vec![format!("Invalid CA certificate in keychain: {}", e)],
                            files_created: vec![],
                        };
                    }

                    // Validate time constraints
                    if let Err(e) = super::super::certificate::parsing::validate_certificate_time(&parsed_cert) {
                        return super::responses::CertificateAuthorityResponse {
                            success: false,
                            authority: None,
                            operation: super::responses::CaOperation::LoadFailed,
                            issues: vec![format!("Expired CA certificate in keychain: {}", e)],
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
                                    return super::responses::CertificateAuthorityResponse {
                                        success: false,
                                        authority: None,
                                        operation: super::responses::CaOperation::LoadFailed,
                                        issues: vec![format!("Failed to create issuer from CA cert: {}", e)],
                                        files_created: vec![],
                                    };
                                }
                            };

                                    let authority = super::super::CertificateAuthority {
                                        name: self.name.clone(),
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

                            super::responses::CertificateAuthorityResponse {
                                success: true,
                                authority: Some(authority),
                                operation: super::responses::CaOperation::Loaded,
                                issues: vec![],
                                files_created: vec![],
                            }
                        },
                        Err(e) => super::responses::CertificateAuthorityResponse {
                            success: false,
                            authority: None,
                            operation: super::responses::CaOperation::LoadFailed,
                            issues: vec![format!("Invalid private key in keychain: {}", e)],
                            files_created: vec![],
                        }
                    }
                },
                Err(e) => super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to parse keychain certificate: {}", e)],
                    files_created: vec![],
                }
            }
        }
        
        // Linux/Windows keychain implementation
        #[cfg(not(target_os = "macos"))]
        {
            // For non-macOS systems, attempt to use system certificate stores
            use std::fs;
            use std::path::PathBuf;
            
            // Common certificate store locations
            let cert_paths = vec![
                format!("/etc/ssl/certs/{}.crt", self.name),
                format!("/usr/local/share/ca-certificates/{}.crt", self.name),
                format!("/etc/pki/ca-trust/source/anchors/{}.crt", self.name),
                format!("/etc/ca-certificates/trust-source/anchors/{}.crt", self.name),
            ];
            
            let key_paths = vec![
                format!("/etc/ssl/private/{}.key", self.name),
                format!("/usr/local/share/ca-certificates/{}.key", self.name),
                format!("/etc/pki/ca-trust/source/anchors/{}.key", self.name),
                format!("/etc/ca-certificates/trust-source/anchors/{}.key", self.name),
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
                None => return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Certificate '{}' not found in system certificate stores", self.name)],
                    files_created: vec![],
                }
            };
            
            let key_path = match found_key_path {
                Some(path) => path,
                None => return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Private key '{}' not found in system certificate stores", self.name)],
                    files_created: vec![],
                }
            };

            let cert_pem = match fs::read_to_string(&cert_path) {
                Ok(content) => content,
                Err(e) => return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to read certificate file {}: {}", cert_path, e)],
                    files_created: vec![],
                }
            };

            let key_pem = match fs::read_to_string(&key_path) {
                Ok(content) => content,
                Err(e) => return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to read private key file {}: {}", key_path, e)],
                    files_created: vec![],
                }
            };

            // Validate the loaded certificate
            match super::super::certificate::parsing::parse_certificate_from_pem(&cert_pem) {
                Ok(parsed_cert) => {
                    // Validate CA constraints
                    if let Err(e) = super::super::certificate::parsing::validate_basic_constraints(&parsed_cert, true) {
                        return super::responses::CertificateAuthorityResponse {
                            success: false,
                            authority: None,
                            operation: super::responses::CaOperation::LoadFailed,
                            issues: vec![format!("Invalid CA certificate in system store: {}", e)],
                            files_created: vec![],
                        };
                    }

                    // Validate time constraints  
                    if let Err(e) = super::super::certificate::parsing::validate_certificate_time(&parsed_cert) {
                        return super::responses::CertificateAuthorityResponse {
                            success: false,
                            authority: None,
                            operation: super::responses::CaOperation::LoadFailed,
                            issues: vec![format!("Expired CA certificate in system store: {}", e)],
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
                                    return super::responses::CertificateAuthorityResponse {
                                        success: false,
                                        authority: None,
                                        operation: super::responses::CaOperation::LoadFailed,
                                        issues: vec![format!("Failed to create issuer from CA cert: {}", e)],
                                        files_created: vec![],
                                    };
                                }
                            };

                            let authority = CertificateAuthority {
                                name: self.name.clone(),
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

                            super::responses::CertificateAuthorityResponse {
                                success: true,
                                authority: Some(authority),
                                operation: super::responses::CaOperation::Loaded,
                                issues: vec![],
                                files_created: vec![],
                            }
                        },
                        Err(e) => super::responses::CertificateAuthorityResponse {
                            success: false,
                            authority: None,
                            operation: super::responses::CaOperation::LoadFailed,
                            issues: vec![format!("Invalid private key in system store: {}", e)],
                            files_created: vec![],
                        }
                    }
                },
                Err(e) => super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to parse system certificate: {}", e)],
                    files_created: vec![],
                }
            }
        }
    }
}

/// Builder for remote certificate authority operations
#[derive(Debug, Clone)]
pub struct AuthorityRemoteBuilder {
    name: String,
    url: String,
    timeout: Duration,
}

impl AuthorityRemoteBuilder {
    /// Set timeout for remote operations
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    /// Load certificate authority from remote URL
    pub async fn load(self) -> super::responses::CertificateAuthorityResponse {
        use crate::tls::http_client::TlsHttpClient;
        use crate::tls::certificate::parse_certificate_from_pem;
        
        let http_client = match TlsHttpClient::new() {
            Ok(client) => client,
            Err(e) => {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to create HTTP client: {}", e)],
                    files_created: vec![],
                };
            }
        };
        
        // Download certificate from remote URL with configured timeout
        let cert_pem = match tokio::time::timeout(
            self.timeout,
            http_client.get_ca_certificate(&self.url)
        ).await {
            Ok(Ok(pem)) => pem,
            Ok(Err(e)) => {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to download CA certificate from {}: {}", self.url, e)],
                    files_created: vec![],
                };
            },
            Err(_) => {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Timeout after {:?} downloading CA certificate from {}", self.timeout, self.url)],
                    files_created: vec![],
                };
            }
        };
        
        // Parse the certificate to extract metadata
        let parsed_cert = match parse_certificate_from_pem(&cert_pem) {
            Ok(cert) => cert,
            Err(e) => {
                return super::responses::CertificateAuthorityResponse {
                    success: false,
                    authority: None,
                    operation: super::responses::CaOperation::LoadFailed,
                    issues: vec![format!("Failed to parse downloaded certificate: {}", e)],
                    files_created: vec![],
                };
            }
        };
        
        // Validate that this is actually a CA certificate
        if !parsed_cert.is_ca {
            return super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::responses::CaOperation::LoadFailed,
                issues: vec!["Downloaded certificate is not a Certificate Authority (CA bit not set)".to_string()],
                files_created: vec![],
            };
        }
        
        // Check if certificate is still valid
        let now = SystemTime::now();
        if now < parsed_cert.not_before || now > parsed_cert.not_after {
            return super::responses::CertificateAuthorityResponse {
                success: false,
                authority: None,
                operation: super::responses::CaOperation::LoadFailed,
                issues: vec!["Downloaded CA certificate is expired or not yet valid".to_string()],
                files_created: vec![],
            };
        }
        
        // Note: We cannot load the private key from a remote URL for security reasons
        // This is intentional - remote CA loading only provides the public certificate
        // for validation purposes, not the private key for signing
        let authority = CertificateAuthority {
            name: self.name,
            certificate_pem: cert_pem.to_string(),
            private_key_pem: None, // No private key for validation-only remote CAs
            metadata: CaMetadata {
                subject: dn_hashmap_to_string(&parsed_cert.subject),
                issuer: dn_hashmap_to_string(&parsed_cert.issuer),
                serial_number: serial_to_string(&parsed_cert.serial_number),
                valid_from: parsed_cert.not_before,
                valid_until: parsed_cert.not_after,
                key_algorithm: parsed_cert.key_algorithm,
                key_size: parsed_cert.key_size,
                created_at: SystemTime::now(),
                source: CaSource::Remote { url: self.url },
            },
        };
        
        super::responses::CertificateAuthorityResponse {
            success: true,
            authority: Some(authority),
            operation: super::responses::CaOperation::Loaded,
            issues: vec!["Private key not available for remote CA - can only be used for validation".to_string()],
            files_created: vec![],
        }
    }
}
