//! Certificate generation and loading functions

use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use tracing::info;

use super::parsing::{
    parse_certificate_from_pem, validate_basic_constraints, validate_certificate_time,
    validate_key_usage,
};
use crate::tls::errors::TlsError;
use crate::tls::key_encryption::{decrypt_private_key, encrypt_private_key};
use crate::tls::types::CertificateUsage;

/// Create a new TLS manager with self-signed certificates
pub async fn new(
    cert_dir: std::path::PathBuf,
) -> Result<(
    CertificateDer<'static>,
    PrivatePkcs8KeyDer<'static>,
    CertificateDer<'static>,
    PrivatePkcs8KeyDer<'static>,
    super::super::ocsp::OcspCache,
    super::super::crl_cache::CrlCache,
)> {
    tokio::fs::create_dir_all(&cert_dir).await?;

    // Generate or load CA
    let (ca_cert, ca_key, ca_issuer) = if cert_dir.join("ca.crt").exists() {
        info!("Loading existing CA certificate");
        load_ca(&cert_dir).await?
    } else {
        info!("Generating new CA certificate");
        generate_ca(&cert_dir).await?
    };

    // Generate server certificate
    info!("Generating server certificate");
    let (server_cert, server_key) = generate_server_cert(&ca_issuer, &cert_dir).await?;

    let ocsp_cache = crate::tls::ocsp::OcspCache::new()?;
    let crl_cache = crate::tls::crl_cache::CrlCache::new()?;

    Ok((
        ca_cert,
        ca_key,
        server_cert,
        server_key,
        ocsp_cache,
        crl_cache,
    ))
}

/// Generate a new CA certificate
async fn generate_ca(
    cert_dir: &Path,
) -> Result<(
    CertificateDer<'static>,
    PrivatePkcs8KeyDer<'static>,
    Issuer<'static, KeyPair>,
)> {
    let mut params =
        CertificateParams::new(Vec::default()).context("Failed to create CA params")?;

    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "CRYYPT");
    dn.push(DnType::CommonName, "CRYYPT CA");
    params.distinguished_name = dn;

    let key_pair = KeyPair::generate()?;
    let cert = params.clone().self_signed(&key_pair)?;

    // Save to disk
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    tokio::fs::write(cert_dir.join("ca.crt"), &cert_pem).await?;

    // Encrypt private key before saving
    let encrypted_key = encrypt_private_key(&key_pem)?;
    tokio::fs::write(cert_dir.join("ca.key"), &encrypted_key).await?;

    // Set permissions on key file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(cert_dir.join("ca.key"))
            .await?
            .permissions();
        perms.set_mode(0o600);
        tokio::fs::set_permissions(cert_dir.join("ca.key"), perms).await?;
    }

    let cert_der_bytes = cert.der();
    let key_der = key_pair.serialize_der();

    // Create issuer for signing other certificates
    let issuer = Issuer::new(params, key_pair);

    Ok((cert_der_bytes.clone(), key_der.into(), issuer))
}

/// Load existing CA certificate
async fn load_ca(
    cert_dir: &Path,
) -> Result<(
    CertificateDer<'static>,
    PrivatePkcs8KeyDer<'static>,
    Issuer<'static, KeyPair>,
)> {
    let cert_pem = tokio::fs::read_to_string(cert_dir.join("ca.crt")).await?;

    // Read and decrypt the encrypted key file
    let encrypted_key_data = tokio::fs::read(cert_dir.join("ca.key")).await?;
    let decrypted_key = decrypt_private_key(&encrypted_key_data)?;
    let key_pem = String::from_utf8(decrypted_key.as_bytes().to_vec())
        .map_err(|e| TlsError::KeyProtection(format!("Invalid UTF-8 in decrypted key: {e}")))?;

    // Parse certificate
    let cert_der_data = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow::anyhow!("No certificate in CA file"))??;

    // Parse key
    let key_der = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow::anyhow!("No private key in CA file"))??;

    // Parse the loaded certificate to extract actual parameters
    let parsed_cert = parse_certificate_from_pem(&cert_pem)
        .map_err(|e| anyhow::anyhow!("Failed to parse loaded CA certificate: {}", e))?;

    // Validate certificate time constraints
    validate_certificate_time(&parsed_cert)
        .map_err(|e| anyhow::anyhow!("CA certificate time validation failed: {}", e))?;

    // Validate BasicConstraints for CA certificate
    validate_basic_constraints(&parsed_cert, true)
        .map_err(|e| anyhow::anyhow!("CA certificate BasicConstraints validation failed: {}", e))?;

    // Validate KeyUsage for CA certificate
    validate_key_usage(&parsed_cert, CertificateUsage::CertificateAuthority)
        .map_err(|e| anyhow::anyhow!("CA certificate KeyUsage validation failed: {}", e))?;

    // Create KeyPair from decrypted PEM key
    let key_pair = KeyPair::from_pem(&key_pem)?;

    // Create Issuer from certificate PEM and key pair
    let ca_issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)?;

    Ok((
        CertificateDer::from(cert_der_data.to_vec()),
        key_der,
        ca_issuer,
    ))
}

/// Generate server certificate signed by CA
async fn generate_server_cert(
    ca_issuer: &Issuer<'_, KeyPair>,
    cert_dir: &Path,
) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    let mut params = CertificateParams::new(Vec::default())?;

    // Add SAN entries
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];

    // Add hostname if available
    if let Ok(hostname) = hostname::get()
        && let Some(hostname_str) = hostname.to_str()
    {
        params
            .subject_alt_names
            .push(SanType::DnsName(hostname_str.try_into()?));
    }

    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "CRYYPT");
    dn.push(DnType::CommonName, "CRYYPT Server");
    params.distinguished_name = dn;

    // Key usage will be set by rcgen defaults for server certificates

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, ca_issuer)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Save to disk
    tokio::fs::write(cert_dir.join("server.crt"), &cert_pem).await?;

    // Encrypt private key before saving
    let encrypted_key = encrypt_private_key(&key_pem)?;
    tokio::fs::write(cert_dir.join("server.key"), &encrypted_key).await?;

    // Set permissions on key file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(cert_dir.join("server.key"))
            .await?
            .permissions();
        perms.set_mode(0o600);
        tokio::fs::set_permissions(cert_dir.join("server.key"), perms).await?;
    }

    let cert_der_encoded = cert.der();
    let key_der = key_pair.serialize_der();

    Ok((cert_der_encoded.clone(), key_der.clone().into()))
}
