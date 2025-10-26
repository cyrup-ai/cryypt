//! JWT Authentication Handler for Vault Operations
//!
//! This module provides cryptographic JWT authentication with strict security validation.
//! Every vault operation must provide a valid, unexpired JWT token for access.

use crate::error::{VaultError, VaultResult};
use cryypt_jwt::{Jwt, JwtError};
use cryypt_key::api::{MasterKeyBuilder, MasterKeyProvider};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT claims structure for vault authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultJwtClaims {
    /// Subject - always "vault_user" for vault operations
    pub sub: String,
    /// Expiration time (unix timestamp)
    pub exp: i64,
    /// Issued at time (unix timestamp)
    pub iat: i64,
    /// Vault identifier (unique per vault file)
    pub vault_id: String,
    /// Session identifier (unique per login session)
    pub session_id: String,
}

/// JWT authentication handler for vault operations
#[derive(Debug)]
pub struct JwtHandler {
    vault_id: String,
    private_key_pkcs8: Vec<u8>,  // PKCS8 DER format for RS256 signing
    public_key_spki: Vec<u8>,    // SPKI DER format for RS256 verification
}

impl JwtHandler {
    /// Create new JWT handler with RSA keys for RS256 signing
    pub fn new(vault_id: String, private_key_pkcs8: Vec<u8>, public_key_spki: Vec<u8>) -> Self {
        Self {
            vault_id,
            private_key_pkcs8,
            public_key_spki,
        }
    }
    
    /// Get the vault ID for this handler
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    /// Create JWT token using RS256 asymmetric signing
    ///
    /// # Arguments
    /// * `session_duration_hours` - Token expiration time in hours (default: 1)
    ///
    /// # Returns
    /// JWT token string signed with RSA private key
    ///
    /// # Security
    /// - Uses RS256 (RSA-SHA256) asymmetric algorithm
    /// - Private key never leaves this handler
    /// - Token includes standard claims: sub, exp, iat, vault_id, session_id
    pub async fn create_jwt_token(
        &self,
        session_duration_hours: Option<u64>,
    ) -> VaultResult<String> {
        let duration_hours = session_duration_hours.unwrap_or(1);

        // Create JWT claims
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VaultError::Internal("System time error".to_string()))?
            .as_secs() as i64;

        let claims = VaultJwtClaims {
            sub: "vault_user".to_string(),
            exp: now + (duration_hours as i64 * 3600),
            iat: now,
            vault_id: self.vault_id.clone(),
            session_id: uuid::Uuid::new_v4().to_string(),
        };

        // Sign JWT with RS256 using RSA private key via builder pattern
        use cryypt_jwt::api::algorithm_builders::rs256_builder::RsJwtBuilder;

        let token_bytes = RsJwtBuilder::new()
            .with_private_key(&self.private_key_pkcs8)
            .with_claims(claims)
            .on_result(|result| {
                result.unwrap_or_else(|e| {
                    log::error!("JWT signing failed: {}", e);
                    Vec::new()
                })
            })
            .sign()
            .await;

        // Validate token bytes are not empty
        if token_bytes.is_empty() {
            return Err(VaultError::AuthenticationFailed(
                "JWT signing returned empty token".to_string(),
            ));
        }

        // Convert bytes to string
        let token = String::from_utf8(token_bytes)
            .map_err(|e| VaultError::AuthenticationFailed(format!("Invalid JWT token encoding: {}", e)))?;

        Ok(token)
    }

    /// Validate JWT token using RS256 asymmetric verification
    ///
    /// # Arguments
    /// * `token` - JWT token string provided by user
    ///
    /// # Returns
    /// Validated JWT claims if token is valid and unexpired
    ///
    /// # Security
    /// - Verifies signature using RSA public key
    /// - Validates expiration timestamp (strict - no grace period)
    /// - Validates vault_id claim matches current vault
    pub async fn validate_jwt_token(&self, token: &str) -> VaultResult<VaultJwtClaims> {
        // Verify JWT token with RS256 using RSA public key via manual verification
        use cryypt_jwt::api::algorithms::rsa::verify_rs256;

        // Split token into parts
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(VaultError::AuthenticationFailed(
                "Malformed JWT token".to_string(),
            ));
        }

        let signature_input = format!("{}.{}", parts[0], parts[1]);
        let signature_b64 = parts[2];

        // Decode signature
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|e| VaultError::AuthenticationFailed(format!("Invalid signature encoding: {}", e)))?;

        // Verify signature
        let is_valid = verify_rs256(&signature_input, &signature, &self.public_key_spki)
            .map_err(|e| VaultError::AuthenticationFailed(format!("Signature verification failed: {}", e)))?;

        if !is_valid {
            return Err(VaultError::AuthenticationFailed(
                "Invalid JWT signature".to_string(),
            ));
        }

        // Decode claims from payload
        let payload_b64 = parts[1];
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| VaultError::AuthenticationFailed(format!("Invalid payload encoding: {}", e)))?;

        let claims_value: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| VaultError::AuthenticationFailed(format!("Invalid claims format: {}", e)))?;

        // Check expiration
        if let Some(exp) = claims_value.get("exp").and_then(|v| v.as_i64()) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| VaultError::Internal("System time error".to_string()))?
                .as_secs() as i64;

            if exp <= now {
                return Err(VaultError::AuthenticationFailed(
                    "JWT token expired. Please login again.".to_string(),
                ));
            }
        }

        // Parse claims into our structure
        let claims: VaultJwtClaims = serde_json::from_value(claims_value).map_err(|e| {
            VaultError::AuthenticationFailed(format!("Invalid JWT claims structure: {}", e))
        })?;

        // Validate vault-specific claims
        self.validate_vault_claims(&claims)?;

        Ok(claims)
    }

    /// Check if JWT token is valid for current vault context
    pub async fn is_jwt_valid(&self, token: &str) -> bool {
        self.validate_jwt_token(token).await.is_ok()
    }



    /// Validate vault-specific JWT claims
    ///
    /// # Arguments
    /// * `claims` - JWT claims to validate
    ///
    /// # Security
    /// - Ensures vault_id claim matches current vault
    /// - Validates subject field is correct
    /// - Additional vault-specific validation rules
    fn validate_vault_claims(&self, claims: &VaultJwtClaims) -> VaultResult<()> {
        // Validate subject
        if claims.sub != "vault_user" {
            return Err(VaultError::AuthenticationFailed(
                "Invalid JWT subject claim".to_string(),
            ));
        }

        // Validate vault ID matches current vault
        if claims.vault_id != self.vault_id {
            return Err(VaultError::AuthenticationFailed(
                "JWT token not valid for this vault".to_string(),
            ));
        }

        // Validate session ID is present and properly formatted
        if claims.session_id.is_empty() {
            return Err(VaultError::AuthenticationFailed(
                "Missing session ID in JWT claims".to_string(),
            ));
        }

        // Validate UUID format for session_id
        uuid::Uuid::parse_str(&claims.session_id).map_err(|_| {
            VaultError::AuthenticationFailed("Invalid session ID format in JWT claims".to_string())
        })?;

        Ok(())
    }
}

// REMOVED: extract_jwt_from_env() - VAULT_JWT environment variable support is unauthorized
// JWT tokens must be provided explicitly via --jwt command-line flag

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to generate test RSA keys for JWT testing
    fn generate_test_rsa_keys() -> (Vec<u8>, Vec<u8>) {
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        
        let mut rng = rand::rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        
        let private_pkcs8 = private_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let public_spki = public_key.to_public_key_der().unwrap().as_bytes().to_vec();
        
        (private_pkcs8, public_spki)
    }

    #[tokio::test]
    async fn test_jwt_creation_and_validation() {
        let vault_id = "test_vault_123".to_string();
        let (private_pkcs8, public_spki) = generate_test_rsa_keys();
        let handler = JwtHandler::new(vault_id, private_pkcs8, public_spki);

        // Create JWT token
        let token = handler.create_jwt_token(Some(1)).await.unwrap();
        assert!(!token.is_empty());

        // Validate JWT token
        let claims = handler
            .validate_jwt_token(&token)
            .await
            .unwrap();
        assert_eq!(claims.sub, "vault_user");
        assert_eq!(claims.vault_id, "test_vault_123");
        assert!(!claims.session_id.is_empty());
    }

    #[tokio::test]
    async fn test_jwt_expiration() {
        let vault_id = "test_vault_exp".to_string();
        let (private_pkcs8, public_spki) = generate_test_rsa_keys();
        let handler = JwtHandler::new(vault_id, private_pkcs8, public_spki);

        // Create JWT token with 0 hour expiration (immediately expired)
        let token = handler.create_jwt_token(Some(0)).await.unwrap();

        // Should fail validation due to expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let result = handler.validate_jwt_token(&token).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[tokio::test]
    async fn test_vault_id_validation() {
        // Generate two different RSA keypairs - one for each vault
        let (private_pkcs8_1, public_spki_1) = generate_test_rsa_keys();
        let (private_pkcs8_2, public_spki_2) = generate_test_rsa_keys();
        
        let handler1 = JwtHandler::new("vault_1".to_string(), private_pkcs8_1, public_spki_1);
        let handler2 = JwtHandler::new("vault_2".to_string(), private_pkcs8_2, public_spki_2);

        // Create token with vault_1
        let token = handler1
            .create_jwt_token(Some(1))
            .await
            .unwrap();

        // Should fail validation with vault_2 (different vault_id and different RSA keys)
        // This fails at signature verification because different RSA keys = different signatures
        let result = handler2.validate_jwt_token(&token).await;
        assert!(result.is_err());

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Invalid JWT signature"),
            "Expected error message to contain 'Invalid JWT signature', but got: '{}'",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let vault_id = "test_vault_sig".to_string();
        
        // Generate correct keys for signing
        let (correct_private_pkcs8, correct_public_spki) = generate_test_rsa_keys();
        let handler_sign = JwtHandler::new(vault_id.clone(), correct_private_pkcs8, correct_public_spki);
        
        // Generate wrong keys for verification
        let (wrong_private_pkcs8, wrong_public_spki) = generate_test_rsa_keys();
        let handler_verify = JwtHandler::new(vault_id, wrong_private_pkcs8, wrong_public_spki);

        // Create token with correct key
        let token = handler_sign.create_jwt_token(Some(1)).await.unwrap();

        // Should fail validation with wrong key
        let result = handler_verify.validate_jwt_token(&token).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }
}
