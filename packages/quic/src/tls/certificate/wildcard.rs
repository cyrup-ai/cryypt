//! Wildcard certificate generation with multiple `SAN` entries for `SweetMCP` auto-integration

use std::path::Path;
use std::time::{Duration, SystemTime};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use tokio::fs;
use tracing::info;

use super::parsing::{parse_certificate_from_pem, validate_certificate_time};
use crate::tls::errors::TlsError;

/// Generate wildcard certificate with multiple `SAN` entries for `SweetMCP` auto-integration
/// Creates a non-expiring certificate for *.cyrup.dev with SAN entries for *.cyrup.ai, *.cyrup.cloud, *.cyrup.pro
#[allow(dead_code)] // SweetMCP integration infrastructure - used for automatic certificate generation
pub async fn generate_wildcard_certificate(xdg_config_home: &Path) -> Result<(), TlsError> {
    let cert_dir = xdg_config_home.join("sweetmcp");

    // Create cert directory if it doesn't exist
    fs::create_dir_all(&cert_dir).await.map_err(|e| {
        TlsError::FileOperation(format!("Failed to create certificate directory: {e}"))
    })?;

    let wildcard_cert_path = cert_dir.join("wildcard.cyrup.pem");

    // Check if certificate already exists and is valid
    if wildcard_cert_path.exists() {
        if (validate_existing_wildcard_cert(&wildcard_cert_path).await).is_ok() {
            info!(
                "Valid wildcard certificate already exists at {}",
                wildcard_cert_path.display()
            );
            return Ok(());
        }
        info!("Existing wildcard certificate is invalid, regenerating...");
    }

    info!("Generating new wildcard certificate with multiple SAN entries");

    let mut params = CertificateParams::new(Vec::default()).map_err(|e| {
        TlsError::CertificateParsing(format!("Failed to create certificate params: {e}"))
    })?;

    // Set as non-CA certificate
    params.is_ca = rcgen::IsCa::NoCa;

    // Primary wildcard domain with SweetMCP branding
    params.subject_alt_names = vec![
        SanType::DnsName(
            "sweetmcp.cyrup.dev"
                .try_into()
                .map_err(|e| TlsError::CertificateParsing(format!("Invalid DNS name: {e}")))?,
        ),
        SanType::DnsName(
            "sweetmcp.cyrup.ai"
                .try_into()
                .map_err(|e| TlsError::CertificateParsing(format!("Invalid DNS name: {e}")))?,
        ),
        SanType::DnsName(
            "sweetmcp.cyrup.cloud"
                .try_into()
                .map_err(|e| TlsError::CertificateParsing(format!("Invalid DNS name: {e}")))?,
        ),
        SanType::DnsName(
            "sweetmcp.cyrup.pro"
                .try_into()
                .map_err(|e| TlsError::CertificateParsing(format!("Invalid DNS name: {e}")))?,
        ),
    ];

    // Set distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "SweetMCP");
    dn.push(DnType::CommonName, "sweetmcp.cyrup.dev");
    params.distinguished_name = dn;

    // Set non-expiring validity period (100 years)
    let now = SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + Duration::from_secs(100 * 365 * 24 * 60 * 60)).into();

    // Generate key pair and self-signed certificate
    let key_pair = KeyPair::generate()
        .map_err(|e| TlsError::CertificateParsing(format!("Failed to generate key pair: {e}")))?;

    let cert = params.self_signed(&key_pair).map_err(|e| {
        TlsError::CertificateParsing(format!("Failed to generate certificate: {e}"))
    })?;

    // Create combined PEM file with certificate and private key
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let combined_pem = format!("{cert_pem}\n{key_pem}");

    // Write combined PEM file
    fs::write(&wildcard_cert_path, &combined_pem)
        .await
        .map_err(|e| {
            TlsError::FileOperation(format!("Failed to write wildcard certificate: {e}"))
        })?;

    // Set secure permissions on certificate file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&wildcard_cert_path)
            .await
            .map_err(|e| TlsError::FileOperation(format!("Failed to get file metadata: {e}")))?
            .permissions();
        perms.set_mode(0o600); // Owner read/write only
        fs::set_permissions(&wildcard_cert_path, perms)
            .await
            .map_err(|e| TlsError::FileOperation(format!("Failed to set file permissions: {e}")))?;
    }

    info!(
        "Wildcard certificate generated successfully at {}",
        wildcard_cert_path.display()
    );
    Ok(())
}

/// Validate existing wildcard certificate
#[allow(dead_code)] // SweetMCP integration infrastructure - used by generate_wildcard_certificate
async fn validate_existing_wildcard_cert(cert_path: &Path) -> Result<(), TlsError> {
    let cert_content = fs::read_to_string(cert_path)
        .await
        .map_err(|e| TlsError::FileOperation(format!("Failed to read certificate file: {e}")))?;

    // Parse the certificate from the combined PEM
    let parsed_cert = parse_certificate_from_pem(&cert_content)?;

    // Check if it has the required SAN entries
    let required_sans = [
        "sweetmcp.cyrup.dev",
        "sweetmcp.cyrup.ai",
        "sweetmcp.cyrup.cloud",
        "sweetmcp.cyrup.pro",
    ];

    for required_san in &required_sans {
        if !parsed_cert
            .san_dns_names
            .contains(&(*required_san).to_string())
        {
            return Err(TlsError::CertificateValidation(format!(
                "Missing required SAN entry: {required_san}"
            )));
        }
    }

    // Check if certificate is still valid (should be non-expiring but validate anyway)
    validate_certificate_time(&parsed_cert)?;

    Ok(())
}
