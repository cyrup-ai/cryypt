//! Domain validation operations
//!
//! This module handles domain validation including:
//! - Single domain validation
//! - Multiple domain validation
//! - SAN and CN checking

use super::super::super::responses::{CheckResult, IssueCategory, IssueSeverity, ValidationIssue};

/// Validate domains against certificate
pub fn validate_domains(
    parsed_cert: &crate::tls::types::ParsedCertificate,
    domain: &Option<String>,
    domains: &Option<Vec<String>>,
    issues: &mut Vec<ValidationIssue>,
) -> Option<CheckResult> {
    if let Some(domain) = domain {
        validate_single_domain(parsed_cert, domain, issues)
    } else if let Some(domains) = domains {
        validate_multiple_domains(parsed_cert, domains, issues)
    } else {
        None
    }
}

/// Validate certificate for single domain
fn validate_single_domain(
    parsed_cert: &crate::tls::types::ParsedCertificate,
    domain: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Option<CheckResult> {
    if parsed_cert.san_dns_names.contains(&domain.to_string())
        || (parsed_cert.subject.contains_key("CN")
            && parsed_cert.subject.get("CN") == Some(&domain.to_string()))
    {
        Some(CheckResult::Passed)
    } else {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Error,
            category: IssueCategory::Domain,
            message: format!("Certificate not valid for domain: {domain}"),
            suggestion: Some("Check SAN entries and subject CN".to_string()),
        });
        Some(CheckResult::Failed("Domain mismatch".to_string()))
    }
}

/// Validate certificate for multiple domains
fn validate_multiple_domains(
    parsed_cert: &crate::tls::types::ParsedCertificate,
    domains: &[String],
    issues: &mut Vec<ValidationIssue>,
) -> Option<CheckResult> {
    let mut failed_domains = Vec::new();

    for domain in domains {
        if !parsed_cert.san_dns_names.contains(domain)
            && !(parsed_cert.subject.contains_key("CN")
                && parsed_cert.subject.get("CN") == Some(domain))
        {
            failed_domains.push(domain.clone());
        }
    }

    if failed_domains.is_empty() {
        Some(CheckResult::Passed)
    } else {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Error,
            category: IssueCategory::Domain,
            message: format!(
                "Certificate not valid for domains: {}",
                failed_domains.join(", ")
            ),
            suggestion: Some(
                "Check SAN entries and subject CN for all required domains".to_string(),
            ),
        });
        Some(CheckResult::Failed(format!(
            "Domain mismatch for: {}",
            failed_domains.join(", ")
        )))
    }
}
