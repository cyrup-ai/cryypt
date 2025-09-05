//! Vault locking operations with secure memory clearing

use super::super::super::LocalVaultProvider;
use crate::error::VaultResult;

impl LocalVaultProvider {
    /// Lock vault and clear all session data
    pub(crate) async fn lock_impl(&self) -> VaultResult<()> {
        // Lock the vault and securely clear all sensitive data from memory
        if let Ok(mut locked_guard) = self.locked.lock() {
            *locked_guard = true;
        }

        // Securely clear passphrase from memory (SecretString handles zeroization)
        let mut passphrase_guard = self.passphrase.lock().await;
        *passphrase_guard = None;
        drop(passphrase_guard);

        // Clear session token
        let mut token_guard = self.session_token.lock().await;
        *token_guard = None;
        drop(token_guard);

        // Securely clear encryption key from memory
        let mut key_guard = self.encryption_key.lock().await;
        if let Some(ref mut key) = key_guard.as_mut() {
            // Explicitly zero out the key bytes before dropping
            key.fill(0);
        }
        *key_guard = None;

        // Securely clear JWT signing key from memory
        let mut jwt_key_guard = self.jwt_key.lock().await;
        if let Some(ref mut jwt_key) = jwt_key_guard.as_mut() {
            // Explicitly zero out the JWT key bytes before dropping
            jwt_key.fill(0);
        }
        *jwt_key_guard = None;

        Ok(())
    }
}
