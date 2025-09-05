//! Passphrase change operations with secure implementation

use crate::db::vault_store::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;
use zeroize::Zeroizing;

/// Passphrase change operations with secure implementation
pub struct PassphraseChanger<'v> {
    vault: &'v LocalVaultProvider,
    current_passphrase: Zeroizing<String>,
}

impl<'v> PassphraseChanger<'v> {
    /// Create new passphrase changer with current passphrase
    pub fn new(vault: &'v LocalVaultProvider, current_passphrase: String) -> Self {
        Self {
            vault,
            current_passphrase: Zeroizing::new(current_passphrase),
        }
    }

    /// Change vault passphrase with proper authentication
    pub async fn change_passphrase(self, new_passphrase: &str) -> VaultResult<()> {
        // Verify current passphrase first
        let passphrase = Passphrase::new(
            self.current_passphrase
                .as_str()
                .to_string()
                .into_boxed_str(),
        );
        self.vault.verify_passphrase(&passphrase).await?;

        // Validate new passphrase strength
        self.validate_passphrase_strength(new_passphrase)?;

        // Re-encrypt all vault data with new passphrase
        self.vault
            .re_encrypt_with_new_passphrase(&self.current_passphrase, new_passphrase)
            .await
    }

    /// Validate passphrase strength according to security requirements
    fn validate_passphrase_strength(&self, passphrase: &str) -> VaultResult<()> {
        if passphrase.len() < 12 {
            return Err(VaultError::weak_passphrase(
                "Passphrase must be at least 12 characters",
            ));
        }

        let has_upper = passphrase.chars().any(|c| c.is_uppercase());
        let has_lower = passphrase.chars().any(|c| c.is_lowercase());
        let has_digit = passphrase.chars().any(|c| c.is_numeric());
        let has_special = passphrase.chars().any(|c| !c.is_alphanumeric());

        if !(has_upper && has_lower && has_digit && has_special) {
            return Err(VaultError::weak_passphrase(
                "Passphrase must contain uppercase, lowercase, digit, and special character",
            ));
        }

        Ok(())
    }
}
