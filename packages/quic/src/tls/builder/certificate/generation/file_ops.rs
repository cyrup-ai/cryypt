//! File operations for certificate generation
//!
//! This module handles file operations including:
//! - Certificate file saving
//! - Directory creation
//! - File permissions and error handling

use std::path::PathBuf;

use super::super::super::responses::{
    CertificateGenerationResponse, FileType, GeneratedFile, GenerationIssue, IssueSeverity,
};

/// Save certificate files to specified path
///
/// # Errors
///
/// Returns an error if:
/// - Directory creation fails
/// - File write permissions are insufficient
/// - Certificate or key content is invalid
/// - File system operations fail
/// - Disk space is insufficient
pub async fn save_certificate_files(
    save_path: &Option<PathBuf>,
    cert_pem: &str,
    key_pem: &str,
) -> Result<Vec<GeneratedFile>, CertificateGenerationResponse> {
    let mut files_created = vec![];

    if let Some(save_path) = save_path {
        // Create directory if it doesn't exist
        if let Err(e) = tokio::fs::create_dir_all(&save_path).await {
            return Err(create_directory_error(e, cert_pem, key_pem));
        }

        let cert_file = save_path.join("cert.pem");
        let key_file = save_path.join("key.pem");

        // Write certificate file
        if let Err(e) = tokio::fs::write(&cert_file, &cert_pem).await {
            return Err(create_cert_write_error(e, cert_pem, key_pem));
        }
        files_created.push(GeneratedFile {
            path: cert_file,
            file_type: FileType::Certificate,
            size_bytes: cert_pem.len() as u64,
        });

        // Write key file
        if let Err(e) = tokio::fs::write(&key_file, &key_pem).await {
            return Err(create_key_write_error(e, cert_pem, key_pem));
        }
        files_created.push(GeneratedFile {
            path: key_file,
            file_type: FileType::PrivateKey,
            size_bytes: key_pem.len() as u64,
        });
    }

    Ok(files_created)
}

/// Create directory creation error response
fn create_directory_error(
    e: std::io::Error,
    cert_pem: &str,
    key_pem: &str,
) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: Some(cert_pem.to_string()),
        private_key_pem: Some(key_pem.to_string()),
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Failed to create directory: {e}"),
            suggestion: Some("Check directory permissions".to_string()),
        }],
    }
}

/// Create certificate file write error response
fn create_cert_write_error(
    e: std::io::Error,
    cert_pem: &str,
    key_pem: &str,
) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: Some(cert_pem.to_string()),
        private_key_pem: Some(key_pem.to_string()),
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Failed to write certificate file: {e}"),
            suggestion: Some("Check file permissions".to_string()),
        }],
    }
}

/// Create key file write error response  
fn create_key_write_error(
    e: std::io::Error,
    cert_pem: &str,
    key_pem: &str,
) -> CertificateGenerationResponse {
    CertificateGenerationResponse {
        success: false,
        certificate_info: None,
        files_created: vec![],
        certificate_pem: Some(cert_pem.to_string()),
        private_key_pem: Some(key_pem.to_string()),
        issues: vec![GenerationIssue {
            severity: IssueSeverity::Error,
            message: format!("Failed to write private key file: {e}"),
            suggestion: Some("Check file permissions".to_string()),
        }],
    }
}
