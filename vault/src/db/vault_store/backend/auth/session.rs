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
            // Validate JWT token using cryypt_jwt API - use associated function syntax
            let validation_result = JwtMasterBuilder::default()
                .with_algorithm("HS256")
                .with_secret(b"vault_session_key") // Use a consistent secret
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
