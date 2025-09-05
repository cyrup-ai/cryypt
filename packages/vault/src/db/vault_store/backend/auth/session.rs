//! Session validation and JWT token management

use super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use cryypt_jwt::JwtMasterBuilder;

impl LocalVaultProvider {
    /// Check if vault is unlocked and session is valid
    pub(crate) async fn check_unlocked(&self) -> VaultResult<()> {
        match self.locked.lock() {
            Ok(guard) => {
                if *guard {
                    return Err(VaultError::VaultLocked);
                }
            }
            Err(_) => return Err(VaultError::VaultLocked), // Poisoned mutex, assume locked
        }

        // Validate JWT session token
        let token_guard = self.session_token.lock().await;
        if let Some(token) = token_guard.as_ref() {
            // Get the JWT signing key from session
            let jwt_key_guard = self.jwt_key.lock().await;
            let jwt_key = match jwt_key_guard.as_ref() {
                Some(key) => key,
                None => {
                    // No JWT key available, vault should be locked
                    drop(jwt_key_guard);
                    drop(token_guard);
                    self.lock_impl().await?;
                    return Err(VaultError::VaultLocked);
                }
            };

            // Validate JWT token using cryypt_jwt API with derived key
            let validation_result = JwtMasterBuilder::default()
                .with_algorithm("HS256")
                .with_secret(jwt_key) // Use the derived JWT key
                .verify(token.clone())
                .await;

            if validation_result.is_ok() {
                Ok(())
            } else {
                // Token invalid, lock the vault
                drop(token_guard);
                self.lock_impl().await?;
                Err(VaultError::VaultLocked)
            }
        } else {
            // No token present, vault should be locked
            drop(token_guard);
            self.lock_impl().await?;
            Err(VaultError::VaultLocked)
        }
    }
}
