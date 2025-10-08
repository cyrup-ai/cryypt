//! HTTP client for OCSP and CRL requests

use crate::tls::errors::TlsError;
use base64::engine::Engine;
use reqwest::Client;
use std::time::Duration;

/// HTTP client wrapper for TLS-related requests
#[derive(Clone, Debug)]
pub struct TlsHttpClient {
    client: Client,
}

impl TlsHttpClient {
    /// Create a new TLS HTTP client
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP client initialization fails
    /// - System TLS configuration is invalid
    /// - Required dependencies are missing
    pub fn new() -> Result<Self, TlsError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("cryypt-quic/1.0")
            .build()
            .map_err(|e| TlsError::HttpClientInit {
                source: Box::new(e),
                context: "Failed to initialize HTTP client for OCSP/CRL validation",
            })?;

        Ok(Self { client })
    }

    /// Send OCSP request
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Network request fails
    /// - OCSP server returns error status
    /// - Response body reading fails
    /// - Request timeout exceeded
    pub async fn post_ocsp(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, TlsError> {
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .body(body)
            .send()
            .await
            .map_err(|e| TlsError::NetworkError(format!("OCSP request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(TlsError::NetworkError(format!(
                "OCSP server returned status: {}",
                response.status()
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TlsError::NetworkError(format!("Failed to read OCSP response: {e}")))
    }

    /// Download CRL
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Network request fails
    /// - CRL server returns error status
    /// - Response body reading fails
    /// - Request timeout exceeded
    pub async fn get_crl(&self, url: &str) -> Result<Vec<u8>, TlsError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| TlsError::NetworkError(format!("CRL download failed: {e}")))?;

        if !response.status().is_success() {
            return Err(TlsError::NetworkError(format!(
                "CRL server returned status: {}",
                response.status()
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TlsError::NetworkError(format!("Failed to read CRL: {e}")))
    }

    /// Download CA certificate and convert to PEM format
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Network request fails
    /// - CA certificate server returns error status
    /// - Certificate format conversion fails
    /// - Response body reading fails
    /// - Request timeout exceeded
    pub async fn get_ca_certificate(&self, url: &str) -> Result<String, TlsError> {
        let response =
            self.client.get(url).send().await.map_err(|e| {
                TlsError::NetworkError(format!("CA certificate download failed: {e}"))
            })?;

        if !response.status().is_success() {
            return Err(TlsError::NetworkError(format!(
                "CA certificate server returned status: {}",
                response.status()
            )));
        }

        let cert_bytes =
            response.bytes().await.map(|b| b.to_vec()).map_err(|e| {
                TlsError::NetworkError(format!("Failed to read CA certificate: {e}"))
            })?;

        // Check if already PEM format (starts with "-----BEGIN")
        if cert_bytes.starts_with(b"-----BEGIN") {
            // Already PEM format
            let pem_string = String::from_utf8(cert_bytes).map_err(|e| {
                TlsError::ParseError(format!("Invalid UTF-8 in PEM certificate: {e}"))
            })?;
            return Ok(pem_string);
        }

        // Assume DER format - convert to PEM
        let base64_cert = base64::engine::general_purpose::STANDARD.encode(&cert_bytes);

        // Format as PEM with proper line breaks (64 characters per line)
        let mut pem_lines = Vec::new();
        pem_lines.push("-----BEGIN CERTIFICATE-----".to_string());

        for chunk in base64_cert.as_bytes().chunks(64) {
            let line = String::from_utf8_lossy(chunk);
            pem_lines.push(line.to_string());
        }

        pem_lines.push("-----END CERTIFICATE-----".to_string());

        Ok(pem_lines.join("\n"))
    }
}
