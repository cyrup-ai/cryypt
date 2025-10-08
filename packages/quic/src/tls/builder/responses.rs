//! Structured response objects for TLS operations

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use super::authority::CertificateAuthority;

/// Response from certificate authority operations
#[derive(Debug)]
pub struct CertificateAuthorityResponse {
    pub success: bool,
    pub authority: Option<CertificateAuthority>,
    pub operation: CaOperation,
    pub issues: Vec<String>,
    pub files_created: Vec<PathBuf>,
}

impl CertificateAuthorityResponse {
    #[must_use]
    pub fn authority(&self) -> Option<&CertificateAuthority> {
        self.authority.as_ref()
    }

    #[must_use]
    pub fn was_successful(&self) -> bool {
        self.success
    }
}

#[derive(Debug)]
pub enum CaOperation {
    Created,
    Loaded,
    LoadFailed,
    CreateFailed,
}

/// Response from certificate validation operations
#[derive(Debug)]
pub struct CertificateValidationResponse {
    pub is_valid: bool,
    pub certificate_info: CertificateInfo,
    pub validation_summary: ValidationSummary,
    pub issues: Vec<ValidationIssue>,
    pub performance: ValidationPerformance,
}

impl CertificateValidationResponse {
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.issues
            .iter()
            .any(|i| matches!(i.severity, IssueSeverity::Warning))
    }

    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|i| matches!(i.severity, IssueSeverity::Error))
    }

    #[must_use]
    pub fn error_summary(&self) -> String {
        self.issues
            .iter()
            .filter(|i| matches!(i.severity, IssueSeverity::Error))
            .map(|i| i.message.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    }

    #[must_use]
    pub fn detailed_report(&self) -> String {
        format!(
            "Certificate Validation Report\n\
             Valid: {}\n\
             Subject: {}\n\
             Issuer: {}\n\
             Valid From: {:?}\n\
             Valid Until: {:?}\n\
             Issues: {}",
            self.is_valid,
            self.certificate_info.subject,
            self.certificate_info.issuer,
            self.certificate_info.valid_from,
            self.certificate_info.valid_until,
            self.issues.len()
        )
    }
}

/// Response from certificate generation operations
#[derive(Debug)]
pub struct CertificateGenerationResponse {
    pub success: bool,
    pub certificate_info: Option<CertificateInfo>,
    pub files_created: Vec<GeneratedFile>,
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
    pub issues: Vec<GenerationIssue>,
}

#[derive(Debug)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub valid_from: SystemTime,
    pub valid_until: SystemTime,
    pub domains: Vec<String>,
    pub is_ca: bool,
    pub key_algorithm: String,
    pub key_size: Option<u32>,
}

#[derive(Debug)]
pub struct ValidationSummary {
    pub parsing: CheckResult,
    pub time_validity: CheckResult,
    pub domain_match: Option<CheckResult>,
    pub ca_validation: Option<CheckResult>,
    pub ocsp_status: Option<CheckResult>,
    pub crl_status: Option<CheckResult>,
}

#[derive(Debug)]
pub enum CheckResult {
    Passed,
    Failed(String),
    Warning(String),
    Skipped,
}

#[derive(Debug)]
pub struct ValidationIssue {
    pub severity: IssueSeverity,
    pub category: IssueCategory,
    pub message: String,
    pub suggestion: Option<String>,
}

#[derive(Debug)]
pub enum IssueSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Debug)]
pub enum IssueCategory {
    Parsing,
    Expiry,
    Domain,
    Chain,
    Revocation,
    KeyUsage,
}

#[derive(Debug)]
pub struct ValidationPerformance {
    pub total_duration: Duration,
    pub parallel_tasks_executed: usize,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub network_requests: usize,
    pub validation_breakdown: HashMap<String, Duration>,
}

#[derive(Debug)]
pub struct GeneratedFile {
    pub path: PathBuf,
    pub file_type: FileType,
    pub size_bytes: u64,
}

#[derive(Debug)]
pub enum FileType {
    Certificate,
    PrivateKey,
    CertificateRequest,
}

#[derive(Debug)]
pub struct GenerationIssue {
    pub severity: IssueSeverity,
    pub message: String,
    pub suggestion: Option<String>,
}
