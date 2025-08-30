//! Certificate validation and generation builders

use std::path::{Path, PathBuf};

use super::authority::CertificateAuthority;
use super::responses::{CertificateGenerationResponse, CertificateValidationResponse};

/// Main certificate builder entry point
#[derive(Debug, Clone)]
pub struct CertificateBuilder;

impl CertificateBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Create a certificate validator
    pub fn validator(self) -> CertificateValidator {
        CertificateValidator::new()
    }

    /// Create a certificate generator
    pub fn generator(self) -> CertificateGenerator {
        CertificateGenerator::new()
    }
}

/// Certificate validator builder
#[derive(Debug, Clone)]
pub struct CertificateValidator {
    // Internal state for validation configuration
}

impl CertificateValidator {
    pub fn new() -> Self {
        Self {}
    }

    /// Load certificate from file
    pub fn from_file<P: AsRef<Path>>(self, path: P) -> CertificateValidatorWithInput {
        CertificateValidatorWithInput {
            input_source: InputSource::File(path.as_ref().to_path_buf()),
            domain: None,
            domains: None,
            authority: None,
        }
    }

    /// Load certificate from PEM string
    pub fn from_string(self, pem: &str) -> CertificateValidatorWithInput {
        CertificateValidatorWithInput {
            input_source: InputSource::String(pem.to_string()),
            domain: None,
            domains: None,
            authority: None,
        }
    }

    /// Load certificate from bytes
    pub fn from_bytes(self, bytes: &[u8]) -> CertificateValidatorWithInput {
        CertificateValidatorWithInput {
            input_source: InputSource::Bytes(bytes.to_vec()),
            domain: None,
            domains: None,
            authority: None,
        }
    }
}

/// Certificate validator with input source configured
#[derive(Debug, Clone)]
pub struct CertificateValidatorWithInput {
    input_source: InputSource,
    domain: Option<String>,
    domains: Option<Vec<String>>,
    authority: Option<CertificateAuthority>,
}

impl CertificateValidatorWithInput {
    /// Validate certificate for specific domain
    pub fn domain(self, domain: &str) -> Self {
        Self {
            domain: Some(domain.to_string()),
            ..self
        }
    }

    /// Validate certificate for multiple domains
    pub fn domains(self, domains: &[&str]) -> Self {
        Self {
            domains: Some(domains.iter().map(|d| d.to_string()).collect()),
            ..self
        }
    }

    /// Validate certificate against specific authority
    pub fn authority(self, ca: &CertificateAuthority) -> Self {
        Self {
            authority: Some(ca.clone()),
            ..self
        }
    }

    /// Execute validation with all security checks enabled by default
    pub async fn validate(self) -> CertificateValidationResponse {
        use std::collections::HashMap;
        use std::time::{Instant, SystemTime};

        use crate::tls::certificate::{
            parse_certificate_from_pem, validate_basic_constraints, validate_certificate_time,
            validate_key_usage,
        };
        use crate::tls::types::CertificateUsage;

        let start_time = Instant::now();
        let mut validation_breakdown = HashMap::new();
        let mut issues = vec![];

        // Get certificate content based on input source
        let cert_content = match &self.input_source {
            InputSource::File(path) => {
                match tokio::fs::read_to_string(&path).await {
                    Ok(content) => content,
                    Err(e) => {
                        return CertificateValidationResponse {
                            is_valid: false,
                            certificate_info: super::responses::CertificateInfo {
                                subject: "Failed to read".to_string(),
                                issuer: "Failed to read".to_string(),
                                serial_number: "Failed to read".to_string(),
                                valid_from: SystemTime::now(),
                                valid_until: SystemTime::now(),
                                domains: vec![],
                                is_ca: false,
                                key_algorithm: "Unknown".to_string(),
                                key_size: None,
                            },
                            validation_summary: super::responses::ValidationSummary {
                                parsing: super::responses::CheckResult::Failed(format!(
                                    "Failed to read file: {}",
                                    e
                                )),
                                time_validity: super::responses::CheckResult::Skipped,
                                domain_match: None,
                                ca_validation: None,
                                ocsp_status: None,
                                crl_status: None,
                            },
                            issues: vec![super::responses::ValidationIssue {
                                severity: super::responses::IssueSeverity::Error,
                                category: super::responses::IssueCategory::Parsing,
                                message: format!("Failed to read certificate file: {}", e),
                                suggestion: Some("Check file path and permissions".to_string()),
                            }],
                            performance: super::responses::ValidationPerformance {
                                total_duration: start_time.elapsed(),
                                parallel_tasks_executed: 0,
                                cache_hits: 0,
                                cache_misses: 0,
                                network_requests: 0,
                                validation_breakdown,
                            },
                        };
                    }
                }
            },
            InputSource::String(content) => content.clone(),
            InputSource::Bytes(bytes) => match String::from_utf8(bytes.clone()) {
                Ok(content) => content,
                Err(e) => {
                    return CertificateValidationResponse {
                        is_valid: false,
                        certificate_info: super::responses::CertificateInfo {
                            subject: "Invalid UTF-8".to_string(),
                            issuer: "Invalid UTF-8".to_string(),
                            serial_number: "Invalid UTF-8".to_string(),
                            valid_from: SystemTime::now(),
                            valid_until: SystemTime::now(),
                            domains: vec![],
                            is_ca: false,
                            key_algorithm: "Unknown".to_string(),
                            key_size: None,
                        },
                        validation_summary: super::responses::ValidationSummary {
                            parsing: super::responses::CheckResult::Failed(format!(
                                "Invalid UTF-8: {}",
                                e
                            )),
                            time_validity: super::responses::CheckResult::Skipped,
                            domain_match: None,
                            ca_validation: None,
                            ocsp_status: None,
                            crl_status: None,
                        },
                        issues: vec![super::responses::ValidationIssue {
                            severity: super::responses::IssueSeverity::Error,
                            category: super::responses::IssueCategory::Parsing,
                            message: format!("Certificate bytes are not valid UTF-8: {}", e),
                            suggestion: Some("Ensure certificate is in PEM format".to_string()),
                        }],
                        performance: super::responses::ValidationPerformance {
                            total_duration: start_time.elapsed(),
                            parallel_tasks_executed: 0,
                            cache_hits: 0,
                            cache_misses: 0,
                            network_requests: 0,
                            validation_breakdown,
                        },
                    };
                }
            },
        };

        // Parse certificate
        let parse_start = Instant::now();
        let parsed_cert = match parse_certificate_from_pem(&cert_content) {
            Ok(cert) => {
                validation_breakdown.insert("parsing".to_string(), parse_start.elapsed());
                cert
            }
            Err(e) => {
                validation_breakdown.insert("parsing".to_string(), parse_start.elapsed());
                return CertificateValidationResponse {
                    is_valid: false,
                    certificate_info: super::responses::CertificateInfo {
                        subject: "Parse failed".to_string(),
                        issuer: "Parse failed".to_string(),
                        serial_number: "Parse failed".to_string(),
                        valid_from: SystemTime::now(),
                        valid_until: SystemTime::now(),
                        domains: vec![],
                        is_ca: false,
                        key_algorithm: "Unknown".to_string(),
                        key_size: None,
                    },
                    validation_summary: super::responses::ValidationSummary {
                        parsing: super::responses::CheckResult::Failed(format!(
                            "Parse error: {}",
                            e
                        )),
                        time_validity: super::responses::CheckResult::Skipped,
                        domain_match: None,
                        ca_validation: None,
                        ocsp_status: None,
                        crl_status: None,
                    },
                    issues: vec![super::responses::ValidationIssue {
                        severity: super::responses::IssueSeverity::Error,
                        category: super::responses::IssueCategory::Parsing,
                        message: format!("Failed to parse certificate: {}", e),
                        suggestion: Some("Ensure certificate is in valid PEM format".to_string()),
                    }],
                    performance: super::responses::ValidationPerformance {
                        total_duration: start_time.elapsed(),
                        parallel_tasks_executed: 0,
                        cache_hits: 0,
                        cache_misses: 0,
                        network_requests: 0,
                        validation_breakdown,
                    },
                };
            }
        };

        // Time validation
        let time_start = Instant::now();
        let time_result = validate_certificate_time(&parsed_cert);
        validation_breakdown.insert("time_validity".to_string(), time_start.elapsed());

        let time_check = match &time_result {
            Ok(()) => super::responses::CheckResult::Passed,
            Err(e) => {
                issues.push(super::responses::ValidationIssue {
                    severity: super::responses::IssueSeverity::Error,
                    category: super::responses::IssueCategory::Expiry,
                    message: format!("Time validation failed: {}", e),
                    suggestion: Some("Check certificate validity period".to_string()),
                });
                super::responses::CheckResult::Failed(format!("Time validation: {}", e))
            }
        };

        // Basic constraints validation
        let constraints_start = Instant::now();
        let constraints_result = validate_basic_constraints(&parsed_cert, false);
        validation_breakdown.insert("basic_constraints".to_string(), constraints_start.elapsed());

        if let Err(e) = constraints_result {
            issues.push(super::responses::ValidationIssue {
                severity: super::responses::IssueSeverity::Warning,
                category: super::responses::IssueCategory::KeyUsage,
                message: format!("Basic constraints issue: {}", e),
                suggestion: Some("Check certificate basic constraints extension".to_string()),
            });
        }

        // Key usage validation
        let key_usage_start = Instant::now();
        let key_usage_result = validate_key_usage(&parsed_cert, CertificateUsage::ServerAuth);
        validation_breakdown.insert("key_usage".to_string(), key_usage_start.elapsed());

        if let Err(e) = key_usage_result {
            issues.push(super::responses::ValidationIssue {
                severity: super::responses::IssueSeverity::Warning,
                category: super::responses::IssueCategory::KeyUsage,
                message: format!("Key usage issue: {}", e),
                suggestion: Some("Check certificate key usage extension".to_string()),
            });
        }

        // Create TlsManager for OCSP/CRL validation
        let temp_dir = std::env::temp_dir().join("tls_validation");
        let tls_manager = match crate::tls::tls_config::TlsManager::new(temp_dir).await {
            Ok(manager) => manager,
            Err(e) => {
                issues.push(super::responses::ValidationIssue {
                    severity: super::responses::IssueSeverity::Warning,
                    category: super::responses::IssueCategory::Chain,
                    message: format!(
                        "Could not initialize TLS manager for security checks: {}",
                        e
                    ),
                    suggestion: Some("OCSP and CRL validation will be skipped".to_string()),
                });

                // Continue with basic validation only
                let domain_check = if let Some(domain) = &self.domain {
                    if parsed_cert.san_dns_names.contains(domain)
                        || parsed_cert.subject.contains_key("CN") && parsed_cert.subject.get("CN") == Some(domain)
                    {
                        Some(super::responses::CheckResult::Passed)
                    } else {
                        issues.push(super::responses::ValidationIssue {
                            severity: super::responses::IssueSeverity::Error,
                            category: super::responses::IssueCategory::Domain,
                            message: format!("Certificate not valid for domain: {}", domain),
                            suggestion: Some("Check SAN entries and subject CN".to_string()),
                        });
                        Some(super::responses::CheckResult::Failed(
                            "Domain mismatch".to_string(),
                        ))
                    }
                } else {
                    None
                };

                let is_valid = time_result.is_ok()
                    && domain_check
                        .as_ref()
                        .map_or(true, |c| matches!(c, super::responses::CheckResult::Passed));

                return CertificateValidationResponse {
                    is_valid,
                    certificate_info: super::responses::CertificateInfo {
                        subject: format!("{:?}", parsed_cert.subject),
                        issuer: format!("{:?}", parsed_cert.issuer),
                        serial_number: hex::encode(&parsed_cert.serial_number),
                        valid_from: parsed_cert.not_before,
                        valid_until: parsed_cert.not_after,
                        domains: parsed_cert.san_dns_names.clone(),
                        is_ca: parsed_cert.is_ca,
                        key_algorithm: "RSA".to_string(),
                        key_size: None,
                    },
                    validation_summary: super::responses::ValidationSummary {
                        parsing: super::responses::CheckResult::Passed,
                        time_validity: time_check,
                        domain_match: domain_check,
                        ca_validation: None,
                        ocsp_status: Some(super::responses::CheckResult::Skipped),
                        crl_status: Some(super::responses::CheckResult::Skipped),
                    },
                    issues,
                    performance: super::responses::ValidationPerformance {
                        total_duration: start_time.elapsed(),
                        parallel_tasks_executed: 0,
                        cache_hits: 0,
                        cache_misses: 0,
                        network_requests: 0,
                        validation_breakdown,
                    },
                };
            }
        };

        // OCSP validation using existing TlsManager
        let ocsp_start = Instant::now();
        let ocsp_result = tls_manager
            .validate_certificate_ocsp(&cert_content, None)
            .await;
        validation_breakdown.insert("ocsp_validation".to_string(), ocsp_start.elapsed());

        let ocsp_check = match &ocsp_result {
            Ok(()) => super::responses::CheckResult::Passed,
            Err(e) => {
                issues.push(super::responses::ValidationIssue {
                    severity: super::responses::IssueSeverity::Error,
                    category: super::responses::IssueCategory::Revocation,
                    message: format!("OCSP validation failed: {}", e),
                    suggestion: Some(
                        "Certificate may be revoked or OCSP responder unavailable".to_string(),
                    ),
                });
                super::responses::CheckResult::Failed(format!("OCSP: {}", e))
            }
        };

        // CRL validation using existing TlsManager
        let crl_start = Instant::now();
        let crl_result = tls_manager.validate_certificate_crl(&cert_content).await;
        validation_breakdown.insert("crl_validation".to_string(), crl_start.elapsed());

        let crl_check = match &crl_result {
            Ok(()) => super::responses::CheckResult::Passed,
            Err(e) => {
                issues.push(super::responses::ValidationIssue {
                    severity: super::responses::IssueSeverity::Error,
                    category: super::responses::IssueCategory::Revocation,
                    message: format!("CRL validation failed: {}", e),
                    suggestion: Some("Certificate may be revoked or CRL unavailable".to_string()),
                });
                super::responses::CheckResult::Failed(format!("CRL: {}", e))
            }
        };

        // Chain validation if authority provided
        let ca_check = if let Some(authority) = &self.authority {
            let chain_start = Instant::now();
            let chain_result = crate::tls::certificate::validate_certificate_chain(
                &cert_content,
                &rustls::pki_types::CertificateDer::from(
                    authority.certificate_pem.as_bytes().to_vec(),
                ),
            )
            .await;
            validation_breakdown.insert("chain_validation".to_string(), chain_start.elapsed());

            match chain_result {
                Ok(()) => Some(super::responses::CheckResult::Passed),
                Err(e) => {
                    issues.push(super::responses::ValidationIssue {
                        severity: super::responses::IssueSeverity::Error,
                        category: super::responses::IssueCategory::Chain,
                        message: format!("Certificate chain validation failed: {}", e),
                        suggestion: Some(
                            "Certificate may not be signed by the provided CA".to_string(),
                        ),
                    });
                    Some(super::responses::CheckResult::Failed(format!(
                        "Chain: {}",
                        e
                    )))
                }
            }
        } else {
            None
        };

        // Domain validation if specified (single domain or multiple domains)
        let domain_check = if let Some(domain) = &self.domain {
            if parsed_cert.san_dns_names.contains(domain)
                || (parsed_cert.subject.contains_key("CN") && parsed_cert.subject.get("CN") == Some(domain))
            {
                Some(super::responses::CheckResult::Passed)
            } else {
                issues.push(super::responses::ValidationIssue {
                    severity: super::responses::IssueSeverity::Error,
                    category: super::responses::IssueCategory::Domain,
                    message: format!("Certificate not valid for domain: {}", domain),
                    suggestion: Some("Check SAN entries and subject CN".to_string()),
                });
                Some(super::responses::CheckResult::Failed(
                    "Domain mismatch".to_string(),
                ))
            }
        } else if let Some(domains) = &self.domains {
            // Validate multiple domains - all must be present in certificate
            let mut failed_domains = Vec::new();
            
            for domain in domains {
                if !parsed_cert.san_dns_names.contains(domain)
                    && !(parsed_cert.subject.contains_key("CN") && parsed_cert.subject.get("CN") == Some(domain))
                {
                    failed_domains.push(domain.clone());
                }
            }
            
            if failed_domains.is_empty() {
                Some(super::responses::CheckResult::Passed)
            } else {
                issues.push(super::responses::ValidationIssue {
                    severity: super::responses::IssueSeverity::Error,
                    category: super::responses::IssueCategory::Domain,
                    message: format!("Certificate not valid for domains: {}", failed_domains.join(", ")),
                    suggestion: Some("Check SAN entries and subject CN for all required domains".to_string()),
                });
                Some(super::responses::CheckResult::Failed(
                    format!("Domain mismatch for: {}", failed_domains.join(", "))
                ))
            }
        } else {
            None
        };

        // Overall validity check
        let is_valid = time_result.is_ok()
            && ocsp_result.is_ok()
            && crl_result.is_ok()
            && domain_check
                .as_ref()
                .map_or(true, |c| matches!(c, super::responses::CheckResult::Passed))
            && ca_check
                .as_ref()
                .map_or(true, |c| matches!(c, super::responses::CheckResult::Passed));

        // Get real cache statistics from TlsManager
        let (cache_hits, cache_misses) = tls_manager.get_cache_stats();

        CertificateValidationResponse {
            is_valid,
            certificate_info: super::responses::CertificateInfo {
                subject: format!("{:?}", parsed_cert.subject),
                issuer: format!("{:?}", parsed_cert.issuer),
                serial_number: hex::encode(&parsed_cert.serial_number),
                valid_from: parsed_cert.not_before,
                valid_until: parsed_cert.not_after,
                domains: parsed_cert.san_dns_names.clone(),
                is_ca: parsed_cert.is_ca,
                key_algorithm: parsed_cert.key_algorithm.clone(),
                key_size: parsed_cert.key_size,
            },
            validation_summary: super::responses::ValidationSummary {
                parsing: super::responses::CheckResult::Passed,
                time_validity: time_check,
                domain_match: domain_check,
                ca_validation: ca_check,
                ocsp_status: Some(ocsp_check),
                crl_status: Some(crl_check),
            },
            issues,
            performance: super::responses::ValidationPerformance {
                total_duration: start_time.elapsed(),
                parallel_tasks_executed: 3, // OCSP, CRL, chain validation
                cache_hits,
                cache_misses,
                network_requests: 2,        // OCSP + CRL
                validation_breakdown,
            },
        }
    }
}

/// Certificate generator builder
#[derive(Debug, Clone)]
pub struct CertificateGenerator {
    // Internal state for generation configuration
}

impl CertificateGenerator {
    pub fn new() -> Self {
        Self {}
    }

    /// Generate certificate for single domain
    pub fn domain(self, domain: &str) -> CertificateGeneratorWithDomain {
        CertificateGeneratorWithDomain {
            domains: vec![domain.to_string()],
            is_wildcard: false,
            authority: None,
            self_signed: false,
            valid_for_days: 90,
            save_path: None,
        }
    }

    /// Generate certificate for multiple domains
    pub fn domains(self, domains: &[&str]) -> CertificateGeneratorWithDomain {
        CertificateGeneratorWithDomain {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            is_wildcard: false,
            authority: None,
            self_signed: false,
            valid_for_days: 90,
            save_path: None,
        }
    }

    /// Generate wildcard certificate for domain
    pub fn wildcard(self, domain: &str) -> CertificateGeneratorWithDomain {
        CertificateGeneratorWithDomain {
            domains: vec![format!("*.{}", domain)],
            is_wildcard: true,
            authority: None,
            self_signed: false,
            valid_for_days: 90,
            save_path: None,
        }
    }
}

/// Certificate generator with domain configured
#[derive(Debug, Clone)]
pub struct CertificateGeneratorWithDomain {
    domains: Vec<String>,
    is_wildcard: bool,
    authority: Option<CertificateAuthority>,
    self_signed: bool,
    valid_for_days: u32,
    save_path: Option<PathBuf>,
}

impl CertificateGeneratorWithDomain {
    /// Sign certificate with certificate authority
    pub fn authority(self, ca: &CertificateAuthority) -> Self {
        Self {
            authority: Some(ca.clone()),
            self_signed: false,
            ..self
        }
    }

    /// Generate self-signed certificate
    pub fn self_signed(self) -> Self {
        Self {
            self_signed: true,
            authority: None,
            ..self
        }
    }

    /// Set validity period in days
    pub fn valid_for_days(self, days: u32) -> Self {
        Self {
            valid_for_days: days,
            ..self
        }
    }

    /// Save generated certificate to path
    pub fn save_to<P: AsRef<Path>>(self, path: P) -> Self {
        Self {
            save_path: Some(path.as_ref().to_path_buf()),
            ..self
        }
    }

    /// Execute certificate generation
    pub async fn generate(self) -> CertificateGenerationResponse {
        use std::time::SystemTime;

        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

        let mut params = match CertificateParams::new(self.domains.clone()) {
            Ok(p) => p,
            Err(e) => {
                return CertificateGenerationResponse {
                    success: false,
                    certificate_info: None,
                    files_created: vec![],
                    certificate_pem: None,
                    private_key_pem: None,
                    issues: vec![super::responses::GenerationIssue {
                        severity: super::responses::IssueSeverity::Error,
                        message: format!("Failed to create certificate parameters: {}", e),
                        suggestion: Some("Check certificate parameters and domain names".to_string()),
                    }],
                };
            }
        };

        // Set up distinguished name
        let mut distinguished_name = DistinguishedName::new();
        if let Some(first_domain) = self.domains.first() {
            distinguished_name.push(DnType::CommonName, first_domain);
        }
        params.distinguished_name = distinguished_name;

        // Set validity period
        let now = SystemTime::now();
        params.not_before = now.into();
        params.not_after =
            (now + std::time::Duration::from_secs(self.valid_for_days as u64 * 24 * 3600)).into();

        // Add SAN entries (with wildcard support)
        let mut san_entries = Vec::new();
        for domain in &self.domains {
            // For wildcard certificates, ensure proper wildcard format
            let domain_to_use = if self.is_wildcard && !domain.starts_with("*.") {
                format!("*.{}", domain)
            } else {
                domain.clone()
            };
            
            let ia5_string = match domain_to_use.clone().try_into() {
                Ok(s) => s,
                Err(e) => {
                    return CertificateGenerationResponse {
                        success: false,
                        certificate_info: None,
                        files_created: vec![],
                        certificate_pem: None,
                        private_key_pem: None,
                        issues: vec![super::responses::GenerationIssue {
                            severity: super::responses::IssueSeverity::Error,
                            message: format!("Invalid DNS name '{}': {}", domain_to_use, e),
                            suggestion: Some("Use valid DNS name format".to_string()),
                        }],
                    };
                }
            };
            san_entries.push(SanType::DnsName(ia5_string));
            
            // For wildcard certificates, also add the base domain
            if self.is_wildcard {
                let base_domain = if domain.starts_with("*.") {
                    &domain[2..] // Remove "*."
                } else {
                    domain
                };
                
                let base_ia5_string = match base_domain.to_string().try_into() {
                    Ok(s) => s,
                    Err(e) => {
                        return CertificateGenerationResponse {
                            success: false,
                            certificate_info: None,
                            files_created: vec![],
                            certificate_pem: None,
                            private_key_pem: None,
                            issues: vec![super::responses::GenerationIssue {
                                severity: super::responses::IssueSeverity::Error,
                                message: format!("Invalid base DNS name '{}': {}", base_domain, e),
                                suggestion: Some("Use valid DNS name format for base domain".to_string()),
                            }],
                        };
                    }
                };
                san_entries.push(SanType::DnsName(base_ia5_string));
            }
        }
        params.subject_alt_names = san_entries;

        // Generate key pair
        let key_pair = match KeyPair::generate() {
            Ok(kp) => kp,
            Err(e) => {
                return CertificateGenerationResponse {
                    success: false,
                    certificate_info: None,
                    files_created: vec![],
                    certificate_pem: None,
                    private_key_pem: None,
                    issues: vec![super::responses::GenerationIssue {
                        severity: super::responses::IssueSeverity::Error,
                        message: format!("Failed to generate key pair: {}", e),
                        suggestion: Some("Check system entropy and crypto libraries".to_string()),
                    }],
                };
            }
        };

        // Create certificate
        let cert = if self.self_signed {
            // Self-signed certificate
            match params.self_signed(&key_pair) {
                Ok(c) => c,
                Err(e) => {
                    return CertificateGenerationResponse {
                        success: false,
                        certificate_info: None,
                        files_created: vec![],
                        certificate_pem: None,
                        private_key_pem: None,
                        issues: vec![super::responses::GenerationIssue {
                            severity: super::responses::IssueSeverity::Error,
                            message: format!("Failed to generate self-signed certificate: {}", e),
                            suggestion: Some("Check certificate parameters".to_string()),
                        }],
                    };
                }
            }
        } else if let Some(ca) = &self.authority {
            // CA-signed certificate using existing authority
            let ca_private_key_pem = match ca.private_key_pem.as_ref() {
                Some(key) => key,
                None => {
                    return CertificateGenerationResponse {
                        success: false,
                        certificate_info: None,
                        certificate_pem: None,
                        private_key_pem: None,
                        files_created: vec![],
                        issues: vec![super::responses::GenerationIssue {
                            message: "Cannot sign certificates with validation-only CA - no private key available".to_string(),
                            severity: super::responses::IssueSeverity::Error,
                            suggestion: Some("Use a CA with a private key or load a different certificate authority".to_string()),
                        }],
                    };
                }
            };
            let ca_key_pair = match rcgen::KeyPair::from_pem(ca_private_key_pem) {
                Ok(kp) => kp,
                Err(e) => {
                    return CertificateGenerationResponse {
                        success: false,
                        certificate_info: None,
                        files_created: vec![],
                        certificate_pem: None,
                        private_key_pem: None,
                        issues: vec![super::responses::GenerationIssue {
                            severity: super::responses::IssueSeverity::Error,
                            message: format!("Failed to parse CA private key: {}", e),
                            suggestion: Some("Check CA private key format".to_string()),
                        }],
                    };
                }
            };

            let ca_issuer = match rcgen::Issuer::from_ca_cert_pem(&ca.certificate_pem, ca_key_pair) {
                Ok(issuer) => issuer,
                Err(e) => {
                    return CertificateGenerationResponse {
                        success: false,
                        certificate_info: None,
                        files_created: vec![],
                        certificate_pem: None,
                        private_key_pem: None,
                        issues: vec![super::responses::GenerationIssue {
                            severity: super::responses::IssueSeverity::Error,
                            message: format!("Failed to create CA certificate: {}", e),
                            suggestion: Some("Check CA certificate parameters".to_string()),
                        }],
                    };
                }
            };

            // Create the certificate signed by the CA
            match params.signed_by(&key_pair, &ca_issuer) {
                Ok(cert) => cert,
                Err(e) => {
                    return CertificateGenerationResponse {
                        success: false,
                        certificate_info: None,
                        files_created: vec![],
                        certificate_pem: None,
                        private_key_pem: None,
                        issues: vec![super::responses::GenerationIssue {
                            severity: super::responses::IssueSeverity::Error,
                            message: format!("Failed to create certificate signed by CA: {}", e),
                            suggestion: Some("Check CA certificate and certificate parameters".to_string()),
                        }],
                    };
                }
            }
        } else {
            return CertificateGenerationResponse {
                success: false,
                certificate_info: None,
                files_created: vec![],
                certificate_pem: None,
                private_key_pem: None,
                issues: vec![super::responses::GenerationIssue {
                    severity: super::responses::IssueSeverity::Error,
                    message: "No signing method specified".to_string(),
                    suggestion: Some("Use .self_signed() or .authority(ca)".to_string()),
                }],
            };
        };

        // Serialize certificate and key
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let mut files_created = vec![];

        // Save files if path specified
        if let Some(save_path) = &self.save_path {
            // Create directory if it doesn't exist
            if let Err(e) = tokio::fs::create_dir_all(&save_path).await {
                return CertificateGenerationResponse {
                    success: false,
                    certificate_info: None,
                    files_created: vec![],
                    certificate_pem: Some(cert_pem),
                    private_key_pem: Some(key_pem),
                    issues: vec![super::responses::GenerationIssue {
                        severity: super::responses::IssueSeverity::Error,
                        message: format!("Failed to create directory: {}", e),
                        suggestion: Some("Check directory permissions".to_string()),
                    }],
                };
            }

            let cert_file = save_path.join("cert.pem");
            let key_file = save_path.join("key.pem");

            // Write certificate file
            if let Err(e) = tokio::fs::write(&cert_file, &cert_pem).await {
                return CertificateGenerationResponse {
                    success: false,
                    certificate_info: None,
                    files_created: vec![],
                    certificate_pem: Some(cert_pem),
                    private_key_pem: Some(key_pem),
                    issues: vec![super::responses::GenerationIssue {
                        severity: super::responses::IssueSeverity::Error,
                        message: format!("Failed to write certificate file: {}", e),
                        suggestion: Some("Check file permissions".to_string()),
                    }],
                };
            }
            files_created.push(super::responses::GeneratedFile {
                path: cert_file,
                file_type: super::responses::FileType::Certificate,
                size_bytes: cert_pem.len() as u64,
            });

            // Write key file
            if let Err(e) = tokio::fs::write(&key_file, &key_pem).await {
                return CertificateGenerationResponse {
                    success: false,
                    certificate_info: None,
                    files_created: vec![],
                    certificate_pem: Some(cert_pem),
                    private_key_pem: Some(key_pem),
                    issues: vec![super::responses::GenerationIssue {
                        severity: super::responses::IssueSeverity::Error,
                        message: format!("Failed to write private key file: {}", e),
                        suggestion: Some("Check file permissions".to_string()),
                    }],
                };
            }
            files_created.push(super::responses::GeneratedFile {
                path: key_file,
                file_type: super::responses::FileType::PrivateKey,
                size_bytes: key_pem.len() as u64,
            });
        }

        CertificateGenerationResponse {
            success: true,
            certificate_info: Some(super::responses::CertificateInfo {
                subject: self
                    .domains
                    .first()
                    .unwrap_or(&"Unknown".to_string())
                    .clone(),
                issuer: if self.self_signed {
                    self.domains
                        .first()
                        .unwrap_or(&"Unknown".to_string())
                        .clone()
                } else {
                    "CA".to_string()
                },
                serial_number: "1".to_string(),
                valid_from: now,
                valid_until: now
                    + std::time::Duration::from_secs(self.valid_for_days as u64 * 24 * 3600),
                domains: self.domains.clone(),
                is_ca: false,
                key_algorithm: "RSA".to_string(),
                key_size: Some(2048),
            }),
            files_created,
            certificate_pem: Some(cert_pem),
            private_key_pem: Some(key_pem),
            issues: vec![],
        }
    }
}

#[derive(Debug, Clone)]
enum InputSource {
    File(PathBuf),
    String(String),
    Bytes(Vec<u8>),
}
