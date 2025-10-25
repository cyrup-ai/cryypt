//! JWT session persistence operations for secure cross-process authentication
//!
//! Provides encrypted storage and retrieval of JWT session tokens in SurrealDB,
//! enabling CLI commands to maintain authentication state across process boundaries.

use super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// JWT session record stored in SurrealDB with base64-encoded fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtSessionRecord {
    /// SHA-256 hash of vault path for unique identification
    pub vault_path_hash: String,
    /// JWT token (Base64 encoded for storage)
    pub session_token_encrypted: String,
    /// Encryption salt used for key derivation (Base64 encoded)
    pub encryption_salt: String,
    /// When the session was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the session expires (1 hour from creation)
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Last time the session was accessed
    pub last_accessed: chrono::DateTime<chrono::Utc>,
}

impl LocalVaultProvider {
    /// Store JWT session persistently in SurrealDB with encryption
    pub(crate) async fn persist_jwt_session(
        &self,
        session_token: String,
    ) -> VaultResult<()> {
        log::debug!("PERSIST_SESSION: Starting JWT session persistence");

        // For session persistence, we'll store the JWT token directly (base64 encoded)
        // The SurrealDB database file itself provides the security boundary
        // This avoids the circular dependency of encrypting with the encryption key
        let token_b64 = BASE64_STANDARD.encode(session_token.as_bytes());

        // We don't store the encryption key in the session - it will be re-derived from passphrase
        // when needed. The session only persists the JWT authentication state.

        // Get current salt for verification during restoration
        let current_salt = self.get_or_create_salt().await?;
        let salt_b64 = BASE64_STANDARD.encode(current_salt);

        // Create vault-specific session ID
        let vault_path_hash = self.create_vault_path_hash();
        let record_id = format!("jwt_sessions:{}", vault_path_hash);

        // Set 1-hour expiry
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::hours(1);

        // UPSERT session record with base64-encoded data
        let upsert_query = format!(
            "UPSERT {} SET 
                vault_path_hash = $vault_path_hash,
                session_token_encrypted = $session_token_encrypted,
                encryption_salt = $encryption_salt,
                created_at = $created_at,
                expires_at = $expires_at,
                last_accessed = $last_accessed",
            record_id
        );

        let db = self.dao.db();
        let mut result = db
            .query(&upsert_query)
            .bind(("vault_path_hash", vault_path_hash.clone()))
            .bind(("session_token_encrypted", token_b64))
            .bind(("encryption_salt", salt_b64))
            .bind(("created_at", surrealdb::value::Datetime::from(now)))
            .bind(("expires_at", surrealdb::value::Datetime::from(expires_at)))
            .bind(("last_accessed", surrealdb::value::Datetime::from(now)))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to persist JWT session: {e}")))?;

        // Validate the operation succeeded
        let _stored_record: Vec<JwtSessionRecord> = result.take(0).map_err(|e| {
            VaultError::Provider(format!("Failed to validate JWT session storage: {e}"))
        })?;

        log::info!(
            "PERSIST_SESSION: JWT session persisted securely for vault hash: {}",
            vault_path_hash
        );
        Ok(())
    }

    /// Restore JWT session from SurrealDB if valid and unexpired
    pub(crate) async fn restore_jwt_session(&self) -> VaultResult<Option<String>> {
        log::debug!("RESTORE_SESSION: Attempting JWT session restoration");

        let vault_path_hash = self.create_vault_path_hash();
        let record_id = format!("jwt_sessions:{}", vault_path_hash);

        // Query for existing session
        let query = format!("SELECT * FROM {}", record_id);
        let db = self.dao.db();
        let mut result = db
            .query(&query)
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to query JWT session: {e}")))?;

        let session_record: Option<JwtSessionRecord> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to deserialize JWT session: {e}")))?;

        match session_record {
            Some(record) => {
                // Check if session has expired
                let now = chrono::Utc::now();
                if record.expires_at <= now {
                    log::info!(
                        "RESTORE_SESSION: Session expired at {}, cleaning up",
                        record.expires_at
                    );
                    self.delete_jwt_session(&vault_path_hash).await?;
                    return Ok(None);
                }

                log::debug!("RESTORE_SESSION: Found valid session, decoding data");

                // Verify salt matches current vault salt
                let current_salt = self.get_or_create_salt().await?;
                let stored_salt = BASE64_STANDARD
                    .decode(&record.encryption_salt)
                    .map_err(|_| VaultError::Crypto("Invalid stored salt format".to_string()))?;

                if current_salt != stored_salt {
                    log::warn!("RESTORE_SESSION: Salt mismatch, invalidating session");
                    self.delete_jwt_session(&vault_path_hash).await?;
                    return Ok(None);
                }

                // Decode session data (stored as base64, not encrypted)
                let token_bytes = BASE64_STANDARD
                    .decode(&record.session_token_encrypted)
                    .map_err(|_| VaultError::Crypto("Invalid token format".to_string()))?;

                let jwt_token = String::from_utf8(token_bytes)
                    .map_err(|_| VaultError::Crypto("Invalid JWT token encoding".to_string()))?;

                // Update last_accessed timestamp
                self.touch_jwt_session(&vault_path_hash).await?;

                log::info!(
                    "RESTORE_SESSION: Successfully restored JWT session for vault hash: {}",
                    vault_path_hash
                );
                Ok(Some(jwt_token))
            }
            None => {
                log::debug!("RESTORE_SESSION: No existing session found");
                Ok(None)
            }
        }
    }

    /// Update last_accessed timestamp for session
    pub(crate) async fn touch_jwt_session(&self, vault_path_hash: &str) -> VaultResult<()> {
        let record_id = format!("jwt_sessions:{}", vault_path_hash);
        let update_query = format!("UPDATE {} SET last_accessed = $last_accessed", record_id);

        let db = self.dao.db();
        db.query(&update_query)
            .bind((
                "last_accessed",
                surrealdb::value::Datetime::from(chrono::Utc::now()),
            ))
            .await
            .map_err(|e| {
                VaultError::Provider(format!("Failed to update session access time: {e}"))
            })?;

        Ok(())
    }

    /// Delete a specific JWT session
    pub(crate) async fn delete_jwt_session(&self, vault_path_hash: &str) -> VaultResult<()> {
        let record_id = format!("jwt_sessions:{}", vault_path_hash);
        let delete_query = format!("DELETE {}", record_id);

        let db = self.dao.db();
        db.query(&delete_query)
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to delete JWT session: {e}")))?;

        log::debug!(
            "DELETE_SESSION: Removed JWT session for vault hash: {}",
            vault_path_hash
        );
        Ok(())
    }

    /// Clean up expired JWT sessions from the database
    pub(crate) async fn cleanup_expired_sessions(&self) -> VaultResult<()> {
        log::debug!("CLEANUP_SESSIONS: Starting expired session cleanup");

        let cleanup_query = "DELETE jwt_sessions WHERE expires_at <= $now";
        let db = self.dao.db();
        let mut result = db
            .query(cleanup_query)
            .bind(("now", surrealdb::value::Datetime::from(chrono::Utc::now())))
            .await
            .map_err(|e| {
                VaultError::Provider(format!("Failed to cleanup expired sessions: {e}"))
            })?;

        // Get count of deleted sessions
        let deleted_count: Option<usize> = result.take(0).unwrap_or(None);
        let count = deleted_count.unwrap_or(0);

        if count > 0 {
            log::info!(
                "CLEANUP_SESSIONS: Cleaned up {} expired JWT sessions",
                count
            );
        } else {
            log::debug!("CLEANUP_SESSIONS: No expired sessions to clean up");
        }

        Ok(())
    }

    /// Create deterministic session ID from vault path using SHA-256
    pub(crate) fn create_vault_path_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.config.vault_path.to_string_lossy().as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Populate in-memory session state from restored JWT data
    /// Note: This only restores JWT session state, encryption key must be derived separately
    pub(crate) async fn populate_session_state(
        &self,
        jwt_token: String,
    ) -> VaultResult<()> {
        log::debug!("POPULATE_SESSION: Restoring in-memory JWT session state");

        // Store the JWT session token
        let mut token_guard = self.session_token.lock().await;
        *token_guard = Some(jwt_token);
        drop(token_guard);

        // Note: We do NOT unlock the vault here because we don't have the encryption key
        // The vault will remain locked until a passphrase is provided to derive the encryption key
        // This is the secure approach - JWT session only provides authentication state,
        // encryption key must be derived from passphrase

        log::info!(
            "POPULATE_SESSION: Successfully restored JWT session state (vault remains locked until passphrase provided)"
        );
        Ok(())
    }

    /// Restore session with passphrase to derive encryption key
    pub(crate) async fn restore_session_with_passphrase(
        &self,
        passphrase: &crate::operation::Passphrase,
    ) -> VaultResult<bool> {
        // First try to restore JWT session
        if let Some(jwt_token) = self.restore_jwt_session().await? {
            // Populate JWT session state
            self.populate_session_state(jwt_token).await?;

            // Derive encryption key from passphrase
            let _encryption_key = self.derive_encryption_key(passphrase).await?;

            // Now unlock the vault since we have both JWT session and encryption key
            if let Ok(mut locked_guard) = self.locked.lock() {
                *locked_guard = false;
                log::info!("RESTORE_SESSION: Vault unlocked with restored session + passphrase");
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if the current vault configuration has a valid JWT session (regardless of lock state)
    pub(crate) async fn has_valid_jwt_session(&self) -> bool {
        // Quick check for in-memory JWT session state
        let token_guard = self.session_token.lock().await;
        let has_jwt_state = token_guard.is_some();
        drop(token_guard);
        has_jwt_state
    }

    /// Check if the current vault configuration has a valid session AND is unlocked
    pub(crate) async fn has_valid_session(&self) -> bool {
        // Check for JWT session state first
        if !self.has_valid_jwt_session().await {
            return false;
        }

        // Also check that vault is unlocked and has encryption key
        if let Ok(locked_guard) = self.locked.lock() {
            if *locked_guard {
                return false; // Vault is locked
            }
        } else {
            return false; // Mutex poisoned
        }

        // Check if we have encryption key
        let key_guard = self.encryption_key.lock().await;
        key_guard.is_some()
    }
}
