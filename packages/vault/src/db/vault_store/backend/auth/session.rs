//! Session validation and JWT token management

use super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use cryypt_jwt::JwtMasterBuilder;
use std::time::{Duration, Instant};

/// Authentication state containing all session information
#[derive(Debug, Clone)]
pub struct AuthState {
    pub locked: bool,
    pub session_token: Option<String>,
    pub jwt_key: Option<Vec<u8>>,
    pub last_validated: Option<Instant>,
}

impl AuthState {
    pub fn new_locked() -> Self {
        Self {
            locked: true,
            session_token: None,
            jwt_key: None,
            last_validated: None,
        }
    }

    pub fn is_valid(&self, max_age: Duration) -> bool {
        if self.locked || self.session_token.is_none() || self.jwt_key.is_none() {
            return false;
        }
        
        if let Some(last_validated) = self.last_validated {
            last_validated.elapsed() < max_age
        } else {
            false
        }
    }
}

impl LocalVaultProvider {
    /// Check if vault is unlocked and session is valid
    pub(crate) async fn check_unlocked(&self) -> VaultResult<()> {
        // Fast path: check basic lock state first (sync)
        match self.locked.lock() {
            Ok(guard) => {
                if *guard {
                    println!("🔒 CHECK_UNLOCKED: Vault is locked (sync mutex)");
                    return Err(VaultError::VaultLocked);
                }
                println!("🔓 CHECK_UNLOCKED: Vault is unlocked (sync mutex), checking JWT...");
            }
            Err(_) => {
                println!("🔒 CHECK_UNLOCKED: Vault lock mutex poisoned");
                return Err(VaultError::VaultLocked);
            }
        }

        // Clone authentication data to avoid holding locks during validation
        let (token, jwt_key) = {
            let token_guard = self.session_token.lock().await;
            let jwt_key_guard = self.jwt_key.lock().await;
            (token_guard.clone(), jwt_key_guard.clone())
        }; // Locks released here

        // Validate outside of any locks
        match (token, jwt_key) {
            (Some(token), Some(jwt_key)) => {
                println!("🔐 CHECK_UNLOCKED: Have token and JWT key, validating...");
                // Direct async JWT validation with timeout to prevent deadlocks
                log::debug!("CHECK_UNLOCKED: Attempting JWT validation...");
                
                // Use direct async JWT validation - no spawn_blocking to avoid nested runtime issues
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    JwtMasterBuilder::default()
                        .with_algorithm("HS256")
                        .with_secret(&jwt_key)
                        .verify(token)
                ).await {
                    Ok(Ok(_)) => {
                        log::debug!("CHECK_UNLOCKED: JWT validation successful");
                        Ok(())
                    },
                    Ok(Err(e)) => {
                        log::error!("CHECK_UNLOCKED: JWT validation failed: {}", e);
                        // Token invalid, lock the vault
                        self.lock_impl().await?;
                        Err(VaultError::VaultLocked)
                    },
                    Err(_) => {
                        log::error!("CHECK_UNLOCKED: JWT validation timed out");
                        // Timed out, lock the vault
                        self.lock_impl().await?;
                        Err(VaultError::VaultLocked)
                    }
                }
            }
            _ => {
                println!("❌ CHECK_UNLOCKED: Missing token or JWT key");
                // No token or key present, lock the vault
                self.lock_impl().await?;
                Err(VaultError::VaultLocked)
            }
        }
    }

}