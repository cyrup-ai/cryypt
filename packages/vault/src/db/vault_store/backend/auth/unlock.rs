//! Vault unlocking operations with passphrase verification and session creation

use super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;

impl LocalVaultProvider {
    /// Unlock vault with passphrase verification and session creation
    pub(crate) async fn unlock_impl(&self, passphrase: Passphrase) -> VaultResult<()> {
        // Check if we already have a valid JWT session that just needs the encryption key
        if self.has_valid_jwt_session().await {
            log::debug!("Found existing JWT session, attempting to derive encryption key");
            // Try to derive encryption key and unlock
            if (self.derive_encryption_key(&passphrase).await).is_ok() {
                if let Ok(mut locked_guard) = self.locked.lock() {
                    *locked_guard = false;
                    log::info!("Vault unlocked using existing JWT session + passphrase");
                    return Ok(());
                }
            } else {
                log::warn!(
                    "Failed to derive encryption key from passphrase, proceeding with full unlock"
                );
            }
        }

        // Ensure vault is currently locked before proceeding with full unlock
        {
            if let Ok(guard) = self.locked.lock()
                && !*guard
            {
                return Err(VaultError::Provider(
                    "Vault is already unlocked".to_string(),
                ));
            }
            // If mutex is poisoned, proceed as if locked
        }

        // Step 1: Verify passphrase against stored hash if exists
        self.verify_passphrase(&passphrase).await?;

        // Step 2: Derive encryption key from passphrase using secure key derivation
        log::debug!("Deriving encryption key from passphrase...");
        let encryption_key = self.derive_encryption_key(&passphrase).await?;

        // Step 3: Validate that key derivation was successful
        if encryption_key.is_empty() {
            return Err(VaultError::KeyDerivation(
                "Key derivation failed - empty key".to_string(),
            ));
        }
        log::debug!(
            "Successfully derived {} byte encryption key",
            encryption_key.len()
        );

        // Step 4: Test encryption/decryption with derived key to ensure it works
        let test_data = b"vault_unlock_test";
        log::debug!("Testing encryption with {} byte test data", test_data.len());

        let encrypted_test = match self.encrypt_data(test_data).await {
            Ok(encrypted) => {
                log::debug!(
                    "Encryption successful, encrypted size: {} bytes",
                    encrypted.len()
                );
                encrypted
            }
            Err(e) => {
                log::error!("Encryption test failed: {}", e);
                return Err(VaultError::Crypto(format!("Encryption test failed: {e}")));
            }
        };

        let decrypted_test = match self.decrypt_data(&encrypted_test).await {
            Ok(decrypted) => {
                log::debug!(
                    "Decryption successful, decrypted size: {} bytes",
                    decrypted.len()
                );
                decrypted
            }
            Err(e) => {
                log::error!("Decryption test failed: {}", e);
                return Err(VaultError::Crypto(format!("Decryption test failed: {e}")));
            }
        };

        if decrypted_test != test_data {
            log::error!(
                "Encryption/decryption test data mismatch! Expected {} bytes, got {} bytes",
                test_data.len(),
                decrypted_test.len()
            );
            return Err(VaultError::Crypto(
                "Encryption/decryption test failed - data mismatch".to_string(),
            ));
        }

        log::debug!("Encryption/decryption test passed successfully");

        // Step 5: Derive secure JWT signing key from passphrase
        log::debug!("Deriving JWT signing key from passphrase...");
        let jwt_key = self.derive_jwt_key(&passphrase).await?;
        log::debug!(
            "Successfully derived {} byte JWT signing key",
            jwt_key.len()
        );

        // Step 6: Generate secure JWT session token with passphrase-derived key
        log::debug!("Creating JWT session token with passphrase-derived key...");
        
        use crate::auth::JwtHandler;

        // Use JwtHandler service (correct API)
        let vault_id = self.config.vault_path.to_string_lossy().to_string();
        let jwt_handler = JwtHandler::new(vault_id);
        let session_token = jwt_handler
            .create_jwt_token(&encryption_key, Some(24))  // 24 hour default
            .await?;
        log::debug!("Successfully created JWT session token with passphrase-derived key");

        // Step 8: Store passphrase hash for future verification (after successful validation)
        self.store_passphrase_hash(&passphrase).await?;

        // Step 9: Persist JWT session to secure storage for cross-process access
        // Store the passphrase-derived JWT key for proper session validation
        if let Err(e) = self
            .persist_jwt_session(session_token.clone(), jwt_key.clone())
            .await
        {
            // Log error but don't fail unlock - session persistence is not critical
            log::warn!("Failed to persist JWT session to storage: {}", e);
        } else {
            log::debug!("JWT session with passphrase-derived key persisted successfully");
        }

        // Step 10: Atomically update all session state
        {
            // Store the passphrase securely in memory (using SecretString from secrecy crate)
            let mut passphrase_guard = self.passphrase.lock().await;
            *passphrase_guard = Some(passphrase.clone());
            drop(passphrase_guard);

            // Store the JWT session token
            let mut token_guard = self.session_token.lock().await;
            *token_guard = Some(session_token);
            drop(token_guard);

            // Store the encryption key for crypto operations
            let mut key_guard = self.encryption_key.lock().await;
            *key_guard = Some(encryption_key);
            drop(key_guard);

            // Store the JWT signing key for session validation
            let mut jwt_key_guard = self.jwt_key.lock().await;
            *jwt_key_guard = Some(jwt_key);
            drop(jwt_key_guard);

            // Finally, unlock the vault
            if let Ok(mut locked_guard) = self.locked.lock() {
                log::debug!("UNLOCK: Setting locked state to false");
                *locked_guard = false;
                log::debug!("UNLOCK: Vault unlocked, locked state = {}", *locked_guard);
            } else {
                log::error!("UNLOCK: Failed to acquire lock mutex");
            }
        }

        log::info!("Vault successfully unlocked with full crypto integration");

        // Verify the unlock state before returning
        match self.locked.lock() {
            Ok(guard) => {
                log::debug!("UNLOCK: Final verification - locked state = {}", *guard);
                if *guard {
                    log::error!("UNLOCK: ERROR - Vault still shows as locked after unlock!");
                    return Err(VaultError::Other("Unlock verification failed".to_string()));
                }
            }
            Err(_) => {
                log::error!("UNLOCK: ERROR - Cannot verify unlock state, mutex poisoned");
                return Err(VaultError::Other(
                    "Unlock verification failed - mutex poisoned".to_string(),
                ));
            }
        }

        Ok(())
    }
}
