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
}

impl JwtHandler {
    /// Create new JWT handler for a specific vault
    pub fn new(vault_id: String) -> Self {
        Self { vault_id }
    }

    /// Get the vault ID for this handler
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    /// Create JWT token for authenticated user
    ///
    /// # Arguments
    /// * `master_key` - The vault master key used for JWT secret derivation
    /// * `session_duration_hours` - Token expiration time in hours (default: 1)
    ///
    /// # Returns
    /// JWT token string that user must provide for subsequent operations
    ///
    /// # Security
    /// - Derives unique JWT secret from master key using Argon2
    /// - Creates token with 1-hour expiration
    /// - Includes vault_id and session_id claims for access control
    pub async fn create_jwt_token(
        &self,
        master_key: &[u8],
        session_duration_hours: Option<u64>,
    ) -> VaultResult<String> {
        let duration_hours = session_duration_hours.unwrap_or(1);

        // Derive JWT signing secret from master key
        let jwt_secret = self.derive_jwt_secret(master_key)?;

        // Create JWT claims
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VaultError::Internal("System time error".to_string()))?
            .as_secs() as i64;

        let claims = VaultJwtClaims {
            sub: "vault_user".to_string(),
            exp: now + (duration_hours as i64 * 3600), // Expiration
            iat: now,
            vault_id: self.vault_id.clone(),
            session_id: uuid::Uuid::new_v4().to_string(),
        };

        // Create JWT builder with HS256 algorithm
        let jwt_builder = Jwt::builder()
            .with_algorithm("HS256")
            .with_secret(&jwt_secret);

        // Sign JWT token
        let token = jwt_builder
            .sign(claims)
            .await
            .map_err(|e| VaultError::AuthenticationFailed(format!("JWT creation failed: {}", e)))?;

        Ok(token)
    }

    /// Validate JWT token and extract claims
    ///
    /// # Arguments
    /// * `token` - JWT token string provided by user
    /// * `master_key` - The vault master key for JWT secret derivation
    ///
    /// # Returns
    /// Validated JWT claims if token is valid and unexpired
    ///
    /// # Security
    /// - Validates JWT signature using derived secret
    /// - Validates expiration timestamp (strict - no grace period)
    /// - Validates vault_id claim matches current vault
    /// - Uses cryypt_jwt validation which includes all standard claim checks
    pub async fn validate_jwt_token(
        &self,
        token: &str,
        master_key: &[u8],
    ) -> VaultResult<VaultJwtClaims> {
        // Derive JWT signing secret from master key
        let jwt_secret = self.derive_jwt_secret(master_key)?;

        // Create JWT builder for validation
        let jwt_builder = Jwt::builder()
            .with_algorithm("HS256")
            .with_secret(&jwt_secret);

        // Validate JWT token (includes signature and standard claims validation)
        let claims_value = jwt_builder.verify(token).await.map_err(|e| match e {
            JwtError::TokenExpired => VaultError::AuthenticationFailed(
                "JWT token expired. Please login again.".to_string(),
            ),
            JwtError::InvalidSignature => {
                VaultError::AuthenticationFailed("Invalid JWT signature".to_string())
            }
            JwtError::InvalidToken(msg) => {
                VaultError::AuthenticationFailed(format!("Invalid JWT token: {}", msg))
            }
            _ => VaultError::AuthenticationFailed(format!("JWT validation failed: {}", e)),
        })?;

        // Parse claims into our structure
        let claims: VaultJwtClaims = serde_json::from_value(claims_value).map_err(|e| {
            VaultError::AuthenticationFailed(format!("Invalid JWT claims structure: {}", e))
        })?;

        // Validate vault-specific claims
        self.validate_vault_claims(&claims)?;

        Ok(claims)
    }

    /// Check if JWT token is valid for current vault context
    ///
    /// # Arguments
    /// * `token` - JWT token string provided by user
    /// * `master_key` - The vault master key for JWT secret derivation
    ///
    /// # Returns
    /// true if token is valid and unexpired, false otherwise
    pub async fn is_jwt_valid(&self, token: &str, master_key: &[u8]) -> bool {
        self.validate_jwt_token(token, master_key).await.is_ok()
    }

    /// Derive JWT signing secret from master key using cryypt_key
    ///
    /// # Arguments
    /// * `master_key` - The vault master key
    ///
    /// # Returns
    /// 32-byte JWT signing secret derived deterministically from master key
    ///
    /// # Security
    /// - Uses cryypt_key with vault-specific context for key derivation
    /// - Generates consistent secret for same master key and vault
    /// - 32-byte output suitable for HS256 algorithm
    fn derive_jwt_secret(&self, master_key: &[u8]) -> VaultResult<Vec<u8>> {
        // Create vault-specific context for deterministic derivation
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
        let jwt_context = format!("jwt_auth_context_{}", self.vault_id);
        let combined_input = format!("{}:{}", BASE64_STANDARD.encode(master_key), jwt_context);

        // Use cryypt_key PassphraseMasterKey for secure JWT secret derivation
        let master_key_provider = MasterKeyBuilder::from_passphrase(&combined_input);
        let jwt_secret_bytes = master_key_provider
            .resolve()
            .map_err(|e| VaultError::Internal(format!("JWT secret derivation failed: {}", e)))?;

        Ok(jwt_secret_bytes.to_vec())
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

/// Extract JWT token from environment variable or command line context
///
/// # Returns
/// JWT token string if available from VAULT_JWT environment variable
///
/// # Usage
/// Users can provide JWT token via:
/// - `export VAULT_JWT="<token>"` environment variable
/// - `--jwt <token>` command line flag (handled by CLI parser)
pub fn extract_jwt_from_env() -> Option<String> {
    std::env::var("VAULT_JWT").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jwt_creation_and_validation() {
        let vault_id = "test_vault_123".to_string();
        let handler = JwtHandler::new(vault_id);
        let master_key = b"test_master_key_12345678901234567890";

        // Create JWT token
        let token = handler.create_jwt_token(master_key, Some(1)).await.unwrap();
        assert!(!token.is_empty());

        // Validate JWT token
        let claims = handler
            .validate_jwt_token(&token, master_key)
            .await
            .unwrap();
        assert_eq!(claims.sub, "vault_user");
        assert_eq!(claims.vault_id, "test_vault_123");
        assert!(!claims.session_id.is_empty());
    }

    #[tokio::test]
    async fn test_jwt_expiration() {
        let vault_id = "test_vault_exp".to_string();
        let handler = JwtHandler::new(vault_id);
        let master_key = b"test_master_key_12345678901234567890";

        // Create JWT token with 0 hour expiration (immediately expired)
        let token = handler.create_jwt_token(master_key, Some(0)).await.unwrap();

        // Should fail validation due to expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let result = handler.validate_jwt_token(&token, master_key).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[tokio::test]
    async fn test_vault_id_validation() {
        let handler1 = JwtHandler::new("vault_1".to_string());
        let handler2 = JwtHandler::new("vault_2".to_string());
        let master_key = b"test_master_key_12345678901234567890";

        // Create token with vault_1
        let token = handler1
            .create_jwt_token(master_key, Some(1))
            .await
            .unwrap();

        // Should fail validation with vault_2 (different vault_id)
        // This fails at signature verification because different vault_ids generate different JWT secrets
        let result = handler2.validate_jwt_token(&token, master_key).await;
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
        let handler = JwtHandler::new(vault_id);
        let master_key = b"test_master_key_12345678901234567890";
        let wrong_key = b"wrong_master_key_1234567890123456789";

        // Create token with correct key
        let token = handler.create_jwt_token(master_key, Some(1)).await.unwrap();

        // Should fail validation with wrong key
        let result = handler.validate_jwt_token(&token, wrong_key).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }
}
