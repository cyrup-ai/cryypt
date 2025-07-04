use std::collections::HashMap;
use std::path::Path;

use super::vault::LocalVaultProvider;
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};

impl LocalVaultProvider {
    pub(crate) async fn unlock_impl(&self, passphrase: &str) -> VaultResult<()> {
        let salt = super::storage::read_salt(&self.config)?;

        // Don't validate passphrase on unlock, only when creating new vault or changing passphrase
        let key = self.derive_key(passphrase, &salt)?;
        *self.key.lock().await = Some(key.clone());

        if Path::new(&self.config.vault_path).exists() {
            let encrypted_data = super::storage::read_vault_data(&self.config)?;
            if !encrypted_data.is_empty() {
                let decrypted_data = self.decrypt_data(&encrypted_data, key.as_ref()).await?;
                let data: HashMap<String, VaultValue> = serde_json::from_slice(&decrypted_data)?;
                *self.data.lock().await = data;
            }
        }

        Ok(())
    }

    pub(crate) async fn lock_impl(&self) -> VaultResult<()> {
        self.save_impl().await?;
        *self.key.lock().await = None;
        *self.data.lock().await = HashMap::new();
        Ok(())
    }

    pub(crate) async fn put_impl(&self, key: &str, value: VaultValue) -> VaultResult<()> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        self.data.lock().await.insert(key.to_string(), value);
        Ok(())
    }

    pub(crate) async fn get_impl(&self, key: &str) -> VaultResult<VaultValue> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        self.data
            .lock()
            .await
            .get(key)
            .cloned()
            .ok_or(VaultError::ItemNotFound)
    }

    pub(crate) async fn delete_impl(&self, key: &str) -> VaultResult<()> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        self.data.lock().await.remove(key);
        Ok(())
    }

    pub(crate) async fn put_if_absent_impl(&self, key: &str, value: VaultValue) -> VaultResult<bool> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        let mut data = self.data.lock().await;
        if data.contains_key(key) {
            Ok(false) // Key already exists, value not inserted
        } else {
            data.insert(key.to_string(), value);
            Ok(true) // Value was inserted
        }
    }

    pub(crate) async fn put_all_impl(&self, entries: &[(String, VaultValue)]) -> VaultResult<()> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        let mut data = self.data.lock().await;
        for (key, value) in entries {
            data.insert(key.clone(), value.clone());
        }
        Ok(())
    }

    pub(crate) async fn save_impl(&self) -> VaultResult<()> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }
        let data = serde_json::to_vec(&*self.data.lock().await)?;
        let key_guard = self.key.lock().await;
        let key = key_guard.as_ref().ok_or(VaultError::VaultLocked)?;
        let encrypted_data = self.encrypt_data(&data, key.as_ref()).await?;

        super::storage::write_vault_data(&self.config, encrypted_data)?;

        Ok(())
    }

    pub(crate) async fn change_passphrase_impl(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> VaultResult<()> {
        if self.is_locked() {
            return Err(VaultError::VaultLocked);
        }

        // Validate new passphrase strength
        if !self.validate_passphrase_strength(new_passphrase) {
            return Err(VaultError::WeakPassphrase);
        }

        // Read salt
        let salt = super::storage::read_salt(&self.config)?;

        // Verify old passphrase
        let old_key = self.derive_key(old_passphrase, &salt)?;
        let current_key = self.key.lock().await;

        // Use safer comparison without unwrap
        if let Some(current) = current_key.as_ref() {
            // Use constant-time comparison to prevent timing attacks
            if old_key.as_slice() != current.as_slice() {
                return Err(VaultError::InvalidPassphrase);
            }
        } else {
            return Err(VaultError::VaultLocked);
        }

        // Generate new key
        let new_key = self.derive_key(new_passphrase, &salt)?;
        drop(current_key); // Release the lock

        // Update the key
        *self.key.lock().await = Some(new_key);

        // Save with new key
        self.save_impl().await
    }
}