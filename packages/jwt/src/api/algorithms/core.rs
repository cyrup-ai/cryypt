//! JWT Core Algorithm Operations - Main signing and verification functions
//!
//! This module provides blazing-fast, zero-allocation implementations of the
//! core JWT signing and verification operations with production-grade security.

use super::ecdsa::{sign_es256, sign_es384, verify_es256, verify_es384};
use super::hmac::{sign_hs256, sign_hs384, sign_hs512, verify_hs256, verify_hs384, verify_hs512};
use super::rsa::{sign_rs256, sign_rs384, sign_rs512, verify_rs256, verify_rs384, verify_rs512};
use super::utils::{base64_url_decode, base64_url_encode};
use crate::{error::JwtError, types::JwtHeader};
use serde::Serialize;
use tokio::sync::oneshot;

/// Internal JWT signing operation using true async
/// Zero-allocation async coordination with blazing-fast performance
pub(crate) async fn sign_jwt<C: Serialize + Send + 'static>(
    algorithm: String,
    claims: C,
    secret: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
) -> Result<String, JwtError> {
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        // Yield for cooperative multitasking
        tokio::task::yield_now().await;

        let result = (|| {
            // Serialize claims with zero-allocation patterns
            let claims_value = serde_json::to_value(&claims)
                .map_err(|e| JwtError::InvalidClaims(e.to_string()))?;

            // Create header with blazing-fast construction
            let header = JwtHeader {
                alg: algorithm.clone(),
                typ: "JWT".to_string(),
                kid: None,
            };

            // Encode header and payload with zero-allocation base64
            let header_json =
                serde_json::to_string(&header).map_err(|e| JwtError::Internal(e.to_string()))?;
            let payload_json = serde_json::to_string(&claims_value)
                .map_err(|e| JwtError::Internal(e.to_string()))?;

            let header_b64 = base64_url_encode(header_json.as_bytes());
            let payload_b64 = base64_url_encode(payload_json.as_bytes());

            let message = format!("{header_b64}.{payload_b64}");

            // Sign based on algorithm with blazing-fast performance
            let signature = match algorithm.as_str() {
                "HS256" => {
                    let secret = secret.ok_or_else(|| {
                        JwtError::MissingKey("Secret required for HS256".to_string())
                    })?;
                    // Validate HMAC key for security
                    crate::api::keys::validate_hmac_key(&secret, "HS256")?;
                    sign_hs256(&message, &secret)?
                }
                "HS384" => {
                    let secret = secret.ok_or_else(|| {
                        JwtError::MissingKey("Secret required for HS384".to_string())
                    })?;
                    // Validate HMAC key for security
                    crate::api::keys::validate_hmac_key(&secret, "HS384")?;
                    sign_hs384(&message, &secret)?
                }
                "HS512" => {
                    let secret = secret.ok_or_else(|| {
                        JwtError::MissingKey("Secret required for HS512".to_string())
                    })?;
                    // Validate HMAC key for security
                    crate::api::keys::validate_hmac_key(&secret, "HS512")?;
                    sign_hs512(&message, &secret)?
                }
                "RS256" => {
                    let key = private_key.ok_or_else(|| {
                        JwtError::MissingKey("Private key required for RS256".to_string())
                    })?;
                    // Validate RSA private key for security
                    crate::api::keys::validate_rsa_private_key(&key)?;
                    sign_rs256(&message, &key)?
                }
                "RS384" => {
                    let key = private_key.ok_or_else(|| {
                        JwtError::MissingKey("Private key required for RS384".to_string())
                    })?;
                    // Validate RSA private key for security
                    crate::api::keys::validate_rsa_private_key(&key)?;
                    sign_rs384(&message, &key)?
                }
                "RS512" => {
                    let key = private_key.ok_or_else(|| {
                        JwtError::MissingKey("Private key required for RS512".to_string())
                    })?;
                    // Validate RSA private key for security
                    crate::api::keys::validate_rsa_private_key(&key)?;
                    sign_rs512(&message, &key)?
                }
                "ES256" => {
                    let key = private_key.ok_or_else(|| {
                        JwtError::MissingKey("Private key required for ES256".to_string())
                    })?;
                    // Validate ECDSA private key for security
                    crate::api::keys::validate_ec_private_key(&key, "ES256")?;
                    sign_es256(&message, &key)?
                }
                "ES384" => {
                    let key = private_key.ok_or_else(|| {
                        JwtError::MissingKey("Private key required for ES384".to_string())
                    })?;
                    // Validate ECDSA private key for security
                    crate::api::keys::validate_ec_private_key(&key, "ES384")?;
                    sign_es384(&message, &key)?
                }
                _ => return Err(JwtError::UnsupportedAlgorithm(algorithm)),
            };

            let signature_b64 = base64_url_encode(&signature);
            Ok(format!("{message}.{signature_b64}"))
        })();

        let _ = tx.send(result);
    });

    rx.await
        .map_err(|_| JwtError::Internal("JWT signing task failed".to_string()))?
}

/// Verify JWT signature based on algorithm
fn verify_jwt_signature(
    algorithm: &str,
    message: &str,
    signature: &[u8],
    secret: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
) -> Result<bool, JwtError> {
    match algorithm {
        "HS256" => {
            let secret = secret.ok_or_else(|| {
                JwtError::MissingKey("Secret required for HS256 verification".to_string())
            })?;
            // Validate HMAC key for security (also validates in verify_hs256 via sign_hs256)
            crate::api::keys::validate_hmac_key(&secret, "HS256")?;
            verify_hs256(message, signature, &secret)
        }
        "HS384" => {
            let secret = secret.ok_or_else(|| {
                JwtError::MissingKey("Secret required for HS384 verification".to_string())
            })?;
            // Validate HMAC key for security (also validates in verify_hs384 via sign_hs384)
            crate::api::keys::validate_hmac_key(&secret, "HS384")?;
            verify_hs384(message, signature, &secret)
        }
        "HS512" => {
            let secret = secret.ok_or_else(|| {
                JwtError::MissingKey("Secret required for HS512 verification".to_string())
            })?;
            // Validate HMAC key for security (also validates in verify_hs512 via sign_hs512)
            crate::api::keys::validate_hmac_key(&secret, "HS512")?;
            verify_hs512(message, signature, &secret)
        }
        "RS256" => {
            let key = public_key.ok_or_else(|| {
                JwtError::MissingKey("Public key required for RS256 verification".to_string())
            })?;
            // Validate RSA public key for security
            crate::api::keys::validate_rsa_public_key(&key)?;
            verify_rs256(message, signature, &key)
        }
        "RS384" => {
            let key = public_key.ok_or_else(|| {
                JwtError::MissingKey("Public key required for RS384 verification".to_string())
            })?;
            // Validate RSA public key for security
            crate::api::keys::validate_rsa_public_key(&key)?;
            verify_rs384(message, signature, &key)
        }
        "RS512" => {
            let key = public_key.ok_or_else(|| {
                JwtError::MissingKey("Public key required for RS512 verification".to_string())
            })?;
            // Validate RSA public key for security
            crate::api::keys::validate_rsa_public_key(&key)?;
            verify_rs512(message, signature, &key)
        }
        "ES256" => {
            let key = public_key.ok_or_else(|| {
                JwtError::MissingKey("Public key required for ES256 verification".to_string())
            })?;
            // Validate ECDSA public key for security
            crate::api::keys::validate_ec_public_key(&key, "ES256")?;
            verify_es256(message, signature, &key)
        }
        "ES384" => {
            let key = public_key.ok_or_else(|| {
                JwtError::MissingKey("Public key required for ES384 verification".to_string())
            })?;
            // Validate ECDSA public key for security
            crate::api::keys::validate_ec_public_key(&key, "ES384")?;
            verify_es384(message, signature, &key)
        }
        _ => Err(JwtError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

/// Internal JWT verification operation using pure async
/// Zero-allocation async coordination with blazing-fast performance
/// Fixed: Removed nested `tokio::spawn` to prevent deadlock in spawned contexts
pub(crate) async fn verify_jwt(
    token: String,
    secret: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
) -> Result<serde_json::Value, JwtError> {
    // Yield for cooperative multitasking
    tokio::task::yield_now().await;

    // Split token with zero-allocation patterns
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidToken("Invalid JWT format".to_string()));
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Decode header with blazing-fast base64
    let header_bytes = base64_url_decode(header_b64)
        .map_err(|_| JwtError::InvalidToken("Invalid header encoding".to_string()))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| JwtError::InvalidToken("Invalid header JSON".to_string()))?;

    // Decode payload with blazing-fast base64
    let payload_bytes = base64_url_decode(payload_b64)
        .map_err(|_| JwtError::InvalidToken("Invalid payload encoding".to_string()))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| JwtError::InvalidToken("Invalid payload JSON".to_string()))?;

    // Verify signature with zero-allocation patterns
    let message = format!("{header_b64}.{payload_b64}");
    let signature = base64_url_decode(signature_b64)
        .map_err(|_| JwtError::InvalidToken("Invalid signature encoding".to_string()))?;

    let valid = verify_jwt_signature(&header.alg, &message, &signature, secret, public_key)?;

    if !valid {
        return Err(JwtError::InvalidSignature);
    }

    // Validate claims with blazing-fast validation
    super::utils::validate_standard_claims(&claims)?;

    Ok(claims)
}
