//! HTTP client for OCSP and CRL requests

use std::time::Duration;
use reqwest::Client;
use crate::tls::errors::TlsError;

/// HTTP client wrapper for TLS-related requests
#[derive(Clone)]
pub struct TlsHttpClient {
    client: Client,
}

impl TlsHttpClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("cryypt-quic/1.0")
            .build()
            .expect("Failed to create HTTP client");
        
        Self { client }
    }

    /// Send OCSP request
    pub async fn post_ocsp(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, TlsError> {
        let response = self.client
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .body(body)
            .send()
            .await
            .map_err(|e| TlsError::NetworkError(format!("OCSP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(TlsError::NetworkError(format!(
                "OCSP server returned status: {}", response.status()
            )));
        }

        response.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TlsError::NetworkError(format!("Failed to read OCSP response: {}", e)))
    }

    /// Download CRL
    pub async fn get_crl(&self, url: &str) -> Result<Vec<u8>, TlsError> {
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(|e| TlsError::NetworkError(format!("CRL download failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(TlsError::NetworkError(format!(
                "CRL server returned status: {}", response.status()
            )));
        }

        response.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TlsError::NetworkError(format!("Failed to read CRL: {}", e)))
    }
}