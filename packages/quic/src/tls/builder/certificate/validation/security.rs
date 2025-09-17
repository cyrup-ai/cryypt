//! Security validation operations
//!
//! This module handles advanced security validation including:
//! - OCSP validation for revocation checking
//! - CRL validation for revocation checking
//! - Certificate chain validation against CA
//! - Security constraints validation

use std::collections::HashMap;
use std::time::{Instant, SystemTime};

use super::super::super::responses::{
    CertificateInfo, CertificateValidationResponse, CheckResult, IssueCategory, IssueSeverity,
    ValidationIssue, ValidationPerformance, ValidationSummary,
};
use super::super::types::InputSource;
use super::basic::CertificateValidatorWithInput;

/// Perform full security validation with all checks
pub async fn perform_full_validation(
    validator: CertificateValidatorWithInput,
) -> CertificateValidationResponse {
    use crate::tls::certificate::{
        parse_certificate_from_pem, validate_basic_constraints, validate_certificate_time,
        validate_key_usage,
    };
    use crate::tls::types::CertificateUsage;

    let start_time = Instant::now();
    let mut validation_breakdown = HashMap::new();
    let mut issues = vec![];

    // Get certificate content based on input source
    let cert_content = match get_certificate_content(&validator.input_source).await {
        Ok(content) => content,
        Err(response) => return response,
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
            return create_parse_error_response(Box::new(e), start_time, validation_breakdown);
        }
    };

    // Time validation
    let time_start = Instant::now();
    let time_result = validate_certificate_time(&parsed_cert);
    validation_breakdown.insert("time_validity".to_string(), time_start.elapsed());

    let time_check = match &time_result {
        Ok(()) => CheckResult::Passed,
        Err(e) => {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Error,
                category: IssueCategory::Expiry,
                message: format!("Time validation failed: {e}"),
                suggestion: Some("Check certificate validity period".to_string()),
            });
            CheckResult::Failed(format!("Time validation: {e}"))
        }
    };

    // Basic constraints validation
    let constraints_start = Instant::now();
    let constraints_result = validate_basic_constraints(&parsed_cert, false);
    validation_breakdown.insert("basic_constraints".to_string(), constraints_start.elapsed());

    if let Err(e) = constraints_result {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            category: IssueCategory::KeyUsage,
            message: format!("Basic constraints issue: {e}"),
            suggestion: Some("Check certificate basic constraints extension".to_string()),
        });
    }

    // Key usage validation
    let key_usage_start = Instant::now();
    let key_usage_result = validate_key_usage(&parsed_cert, CertificateUsage::ServerAuth);
    validation_breakdown.insert("key_usage".to_string(), key_usage_start.elapsed());

    if let Err(e) = key_usage_result {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            category: IssueCategory::KeyUsage,
            message: format!("Key usage issue: {e}"),
            suggestion: Some("Check certificate key usage extension".to_string()),
        });
    }

    // Create TlsManager for OCSP/CRL validation
    let temp_dir = std::env::temp_dir().join("tls_validation");
    let tls_manager = match crate::tls::tls_config::TlsManager::new(temp_dir).await {
        Ok(manager) => manager,
        Err(e) => {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::Chain,
                message: format!(
                    "Could not initialize TLS manager for security checks: {}",
                    e
                ),
                suggestion: Some("OCSP and CRL validation will be skipped".to_string()),
            });

            // Continue with basic validation only
            let domain_check = super::domain::validate_domains(
                &parsed_cert,
                &validator.domain,
                &validator.domains,
                &mut issues,
            );
            let is_valid = time_result.is_ok()
                && domain_check
                    .as_ref()
                    .map_or(true, |c| matches!(c, CheckResult::Passed));

            return CertificateValidationResponse {
                is_valid,
                certificate_info: create_certificate_info(&parsed_cert),
                validation_summary: ValidationSummary {
                    parsing: CheckResult::Passed,
                    time_validity: time_check,
                    domain_match: domain_check,
                    ca_validation: None,
                    ocsp_status: Some(CheckResult::Skipped),
                    crl_status: Some(CheckResult::Skipped),
                },
                issues,
                performance: ValidationPerformance {
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

    // OCSP validation
    let ocsp_start = Instant::now();
    let ocsp_result = tls_manager
        .validate_certificate_ocsp(&cert_content, None)
        .await;
    validation_breakdown.insert("ocsp_validation".to_string(), ocsp_start.elapsed());

    let ocsp_check = match &ocsp_result {
        Ok(()) => CheckResult::Passed,
        Err(e) => {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Error,
                category: IssueCategory::Revocation,
                message: format!("OCSP validation failed: {e}"),
                suggestion: Some(
                    "Certificate may be revoked or OCSP responder unavailable".to_string(),
                ),
            });
            CheckResult::Failed(format!("OCSP: {e}"))
        }
    };

    // CRL validation
    let crl_start = Instant::now();
    let crl_result = tls_manager.validate_certificate_crl(&cert_content).await;
    validation_breakdown.insert("crl_validation".to_string(), crl_start.elapsed());

    let crl_check = match &crl_result {
        Ok(()) => CheckResult::Passed,
        Err(e) => {
            issues.push(ValidationIssue {
                severity: IssueSeverity::Error,
                category: IssueCategory::Revocation,
                message: format!("CRL validation failed: {e}"),
                suggestion: Some("Certificate may be revoked or CRL unavailable".to_string()),
            });
            CheckResult::Failed(format!("CRL: {e}"))
        }
    };

    // Chain validation if authority provided
    let ca_check = if let Some(authority) = &validator.authority {
        let chain_start = Instant::now();
        let chain_result = crate::tls::certificate::validate_certificate_chain(
            &cert_content,
            &rustls::pki_types::CertificateDer::from(authority.certificate_pem.as_bytes().to_vec()),
        )
        .await;
        validation_breakdown.insert("chain_validation".to_string(), chain_start.elapsed());

        match chain_result {
            Ok(()) => Some(CheckResult::Passed),
            Err(e) => {
                issues.push(ValidationIssue {
                    severity: IssueSeverity::Error,
                    category: IssueCategory::Chain,
                    message: format!("Certificate chain validation failed: {e}"),
                    suggestion: Some(
                        "Certificate may not be signed by the provided CA".to_string(),
                    ),
                });
                Some(CheckResult::Failed(format!("Chain: {e}")))
            }
        }
    } else {
        None
    };

    // Domain validation
    let domain_check = super::domain::validate_domains(
        &parsed_cert,
        &validator.domain,
        &validator.domains,
        &mut issues,
    );

    // Overall validity check
    let is_valid = time_result.is_ok()
        && ocsp_result.is_ok()
        && crl_result.is_ok()
        && domain_check
            .as_ref()
            .map_or(true, |c| matches!(c, CheckResult::Passed))
        && ca_check
            .as_ref()
            .map_or(true, |c| matches!(c, CheckResult::Passed));

    // Get cache statistics
    let (cache_hits, cache_misses) = tls_manager.get_cache_stats();

    CertificateValidationResponse {
        is_valid,
        certificate_info: create_certificate_info(&parsed_cert),
        validation_summary: ValidationSummary {
            parsing: CheckResult::Passed,
            time_validity: time_check,
            domain_match: domain_check,
            ca_validation: ca_check,
            ocsp_status: Some(ocsp_check),
            crl_status: Some(crl_check),
        },
        issues,
        performance: ValidationPerformance {
            total_duration: start_time.elapsed(),
            parallel_tasks_executed: 3,
            cache_hits,
            cache_misses,
            network_requests: 2,
            validation_breakdown,
        },
    }
}

/// Get certificate content from input source
async fn get_certificate_content(
    input_source: &InputSource,
) -> Result<String, CertificateValidationResponse> {
    match input_source {
        InputSource::File(path) => match tokio::fs::read_to_string(&path).await {
            Ok(content) => Ok(content),
            Err(e) => Err(create_file_read_error(e)),
        },
        InputSource::String(content) => Ok(content.clone()),
        InputSource::Bytes(bytes) => match String::from_utf8(bytes.clone()) {
            Ok(content) => Ok(content),
            Err(e) => Err(create_utf8_error(e)),
        },
    }
}

/// Create file read error response
fn create_file_read_error(e: std::io::Error) -> CertificateValidationResponse {
    CertificateValidationResponse {
        is_valid: false,
        certificate_info: create_default_cert_info("Failed to read"),
        validation_summary: ValidationSummary {
            parsing: CheckResult::Failed(format!("Failed to read file: {e}")),
            time_validity: CheckResult::Skipped,
            domain_match: None,
            ca_validation: None,
            ocsp_status: None,
            crl_status: None,
        },
        issues: vec![ValidationIssue {
            severity: IssueSeverity::Error,
            category: IssueCategory::Parsing,
            message: format!("Failed to read certificate file: {e}"),
            suggestion: Some("Check file path and permissions".to_string()),
        }],
        performance: ValidationPerformance {
            total_duration: std::time::Duration::from_millis(0),
            parallel_tasks_executed: 0,
            cache_hits: 0,
            cache_misses: 0,
            network_requests: 0,
            validation_breakdown: HashMap::new(),
        },
    }
}

/// Create UTF-8 error response
fn create_utf8_error(e: std::string::FromUtf8Error) -> CertificateValidationResponse {
    CertificateValidationResponse {
        is_valid: false,
        certificate_info: create_default_cert_info("Invalid UTF-8"),
        validation_summary: ValidationSummary {
            parsing: CheckResult::Failed(format!("Invalid UTF-8: {e}")),
            time_validity: CheckResult::Skipped,
            domain_match: None,
            ca_validation: None,
            ocsp_status: None,
            crl_status: None,
        },
        issues: vec![ValidationIssue {
            severity: IssueSeverity::Error,
            category: IssueCategory::Parsing,
            message: format!("Certificate bytes are not valid UTF-8: {e}"),
            suggestion: Some("Ensure certificate is in PEM format".to_string()),
        }],
        performance: ValidationPerformance {
            total_duration: std::time::Duration::from_millis(0),
            parallel_tasks_executed: 0,
            cache_hits: 0,
            cache_misses: 0,
            network_requests: 0,
            validation_breakdown: HashMap::new(),
        },
    }
}

/// Create parse error response
fn create_parse_error_response(
    e: Box<dyn std::error::Error + Send + Sync>,
    start_time: Instant,
    validation_breakdown: HashMap<String, std::time::Duration>,
) -> CertificateValidationResponse {
    CertificateValidationResponse {
        is_valid: false,
        certificate_info: create_default_cert_info("Parse failed"),
        validation_summary: ValidationSummary {
            parsing: CheckResult::Failed(format!("Parse error: {e}")),
            time_validity: CheckResult::Skipped,
            domain_match: None,
            ca_validation: None,
            ocsp_status: None,
            crl_status: None,
        },
        issues: vec![ValidationIssue {
            severity: IssueSeverity::Error,
            category: IssueCategory::Parsing,
            message: format!("Failed to parse certificate: {e}"),
            suggestion: Some("Ensure certificate is in valid PEM format".to_string()),
        }],
        performance: ValidationPerformance {
            total_duration: start_time.elapsed(),
            parallel_tasks_executed: 0,
            cache_hits: 0,
            cache_misses: 0,
            network_requests: 0,
            validation_breakdown,
        },
    }
}

/// Create default certificate info for error cases
fn create_default_cert_info(status: &str) -> CertificateInfo {
    CertificateInfo {
        subject: status.to_string(),
        issuer: status.to_string(),
        serial_number: status.to_string(),
        valid_from: SystemTime::now(),
        valid_until: SystemTime::now(),
        domains: vec![],
        is_ca: false,
        key_algorithm: "Unknown".to_string(),
        key_size: None,
    }
}

/// Create certificate info from parsed certificate
fn create_certificate_info(parsed_cert: &crate::tls::types::ParsedCertificate) -> CertificateInfo {
    CertificateInfo {
        subject: format!("{:?}", parsed_cert.subject),
        issuer: format!("{:?}", parsed_cert.issuer),
        serial_number: hex::encode(&parsed_cert.serial_number),
        valid_from: parsed_cert.not_before,
        valid_until: parsed_cert.not_after,
        domains: parsed_cert.san_dns_names.clone(),
        is_ca: parsed_cert.is_ca,
        key_algorithm: parsed_cert.key_algorithm.clone(),
        key_size: parsed_cert.key_size,
    }
}
