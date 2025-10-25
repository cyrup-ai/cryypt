//! Session validation and JWT token management

use super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use cryypt_jwt::Jwt;
use std::time::{Duration, Instant};

/// Authentication state containing all session information
#[derive(Debug, Clone)]
pub struct AuthState {
    pub locked: bool,
    pub session_token: Option<String>,
    pub last_validated: Option<Instant>,
}

impl AuthState {
    pub fn new_locked() -> Self {
        Self {
            locked: true,
            session_token: None,
            last_validated: None,
        }
    }

    pub fn is_valid(&self, max_age: Duration) -> bool {
        if self.locked || self.session_token.is_none() {
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
        let token = {
            let token_guard = self.session_token.lock().await;
            log::info!(
                "CHECK_UNLOCKED: Token present: {}",
                token_guard.is_some()
            );
            token_guard.clone()
        }; // Lock released here

        // Validate outside of any locks
        match token {
            Some(token) => {
                println!("🔐 CHECK_UNLOCKED: Have token, validating...");
                // Direct async JWT validation with timeout to prevent deadlocks
                log::debug!("CHECK_UNLOCKED: Attempting JWT validation...");

                // Load RSA keys from filesystem for validation
                use crate::auth::{RsaKeyManager, key_converter::{pkcs1_to_pkcs8, pkcs1_public_to_spki}};

                let rsa_manager = RsaKeyManager::new(RsaKeyManager::default_path());
                
                match rsa_manager.load().await {
                    Ok((private_pkcs1, public_pkcs1)) => {
                        // Convert keys to JWT formats
                        let private_pkcs8 = match pkcs1_to_pkcs8(&private_pkcs1) {
                            Ok(key) => key,
                            Err(e) => {
                                log::error!("CHECK_UNLOCKED: Private key conversion failed: {}", e);
                                if let Err(lockdown_error) = self.emergency_lockdown().await {
                                    log::error!("Emergency lockdown failed: {:?}", lockdown_error);
                                }
                                return Err(VaultError::VaultLocked);
                            }
                        };

                        let public_spki = match pkcs1_public_to_spki(&public_pkcs1) {
                            Ok(key) => key,
                            Err(e) => {
                                log::error!("CHECK_UNLOCKED: Public key conversion failed: {}", e);
                                if let Err(lockdown_error) = self.emergency_lockdown().await {
                                    log::error!("Emergency lockdown failed: {:?}", lockdown_error);
                                }
                                return Err(VaultError::VaultLocked);
                            }
                        };

                        // Create JWT handler with loaded keys
                        use crate::auth::JwtHandler;
                        let vault_id = self.config.vault_path.to_string_lossy().to_string();
                        let jwt_handler = JwtHandler::new(vault_id, private_pkcs8, public_spki);

                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            jwt_handler.is_jwt_valid(&token),
                        )
                        .await
                        {
                            Ok(result) if result => {
                                log::debug!("CHECK_UNLOCKED: JWT validation successful");
                                Ok(())
                            }
                            Ok(_) => {
                                log::error!("CHECK_UNLOCKED: JWT validation failed");
                                // Authentication failed - trigger emergency lockdown
                                if let Err(lockdown_error) = self.emergency_lockdown().await {
                                    log::error!("Emergency lockdown failed: {:?}", lockdown_error);
                                }
                                Err(VaultError::VaultLocked)
                            }
                            Err(_) => {
                                log::error!("CHECK_UNLOCKED: JWT validation timed out");
                                // Timed out - trigger emergency lockdown
                                if let Err(lockdown_error) = self.emergency_lockdown().await {
                                    log::error!("Emergency lockdown failed: {:?}", lockdown_error);
                                }
                                Err(VaultError::VaultLocked)
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("CHECK_UNLOCKED: Failed to load RSA keys: {}", e);
                        if let Err(lockdown_error) = self.emergency_lockdown().await {
                            log::error!("Emergency lockdown failed: {:?}", lockdown_error);
                        }
                        Err(VaultError::VaultLocked)
                    }
                }
            }
            None => {
                println!("❌ CHECK_UNLOCKED: Missing token");
                // No token present - trigger emergency lockdown
                if let Err(lockdown_error) = self.emergency_lockdown().await {
                    log::error!("Emergency lockdown failed: {:?}", lockdown_error);
                }
                Err(VaultError::VaultLocked)
            }
        }
    }
}
