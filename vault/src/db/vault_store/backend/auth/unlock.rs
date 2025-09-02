//! Vault unlocking operations with passphrase verification and session creation

use super::super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;
use cryypt_jwt::JwtMasterBuilder;

impl LocalVaultProvider {
    /// Unlock vault with passphrase verification and session creation
    pub(crate) async fn unlock_impl(&self, passphrase: Passphrase) -> VaultResult<()> {
        // Ensure vault is currently locked before proceeding
        {
            match self.locked.lock() {
                Ok(guard) => {
                    if !*guard {
                        return Err(VaultError::Provider(
                            "Vault is already unlocked".to_string(),
                        ));
                    }
                }
                Err(_) => {} // Poisoned mutex, proceed as if locked
            }
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
                return Err(VaultError::Crypto(format!("Encryption test failed: {}", e)));
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
                return Err(VaultError::Crypto(format!("Decryption test failed: {}", e)));
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

        // Step 6: Generate secure JWT session token with enhanced claims
        let session_claims = serde_json::json!({
            "session": "vault_unlocked",
            "vault_path": self.config.vault_path.to_string_lossy(),
            "issued_at": chrono::Utc::now().timestamp(),
            "exp": chrono::Utc::now().timestamp() + 3600,
            "nbf": chrono::Utc::now().timestamp()
        });

        let token_result = JwtMasterBuilder::default()
            .with_algorithm("HS256")
            .with_secret(&jwt_key)
            .sign(session_claims)
            .await;

        // Step 7: Generate JWT session token with proper error handling
        let session_token = match token_result {
            Ok(token) => token,
            Err(e) => {
                log::error!("JWT session token generation failed: {}", e);
                return Err(VaultError::Crypto(
                    "Failed to generate session token".to_string(),
                ));
            }
        };

        // Step 8: Store passphrase hash for future verification (after successful validation)
        self.store_passphrase_hash(&passphrase).await?;

        // Step 9: Atomically update all session state
        {
            // Store the passphrase securely in memory (using SecretString from secrecy crate)
            let mut passphrase_guard = self.passphrase.lock().await;
            *passphrase_guard = Some(passphrase.clone());
            drop(passphrase_guard);

            // Store the JWT session token
            let mut token_guard = self.session_token.lock().await;
            *token_guard = Some(session_token);
            drop(token_guard);

            // Finally, unlock the vault
            if let Ok(mut locked_guard) = self.locked.lock() {
                *locked_guard = false;
            }
        }

        log::info!("Vault successfully unlocked with full crypto integration");
        Ok(())
    }
}
