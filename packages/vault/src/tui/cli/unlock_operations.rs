//! Vault unlock operations for CLI commands

use crate::core::Vault;
use crate::logging::log_security_event;
use dialoguer::{Password, theme::ColorfulTheme};

/// Ensures the vault is unlocked using the provided passphrase or prompting if needed
/// If using JSON mode, a passphrase must be provided via --passphrase option
pub async fn ensure_unlocked(
    vault: &Vault,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if vault.is_locked().await {
        // Use provided passphrase or prompt for it
        let passphrase = if let Some(pass) = passphrase_option {
            log_security_event(
                "CLI_UNLOCK",
                "Using passphrase from command line option",
                true,
            );
            pass.to_string()
        } else if use_json {
            // In JSON mode, don't prompt interactively - require --passphrase option
            log_security_event(
                "CLI_UNLOCK",
                "Failed to unlock vault in JSON mode - no passphrase provided",
                false,
            );
            return Err("No passphrase provided. Use --passphrase option when using --json".into());
        } else {
            // Only prompt interactively in normal mode
            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter vault passphrase")
                .interact()?
        };

        match vault.unlock(&passphrase).await {
            Ok(_) => {
                log_security_event("CLI_UNLOCK", "Vault unlocked for CLI operation", true);
            }
            Err(e) => {
                log_security_event(
                    "CLI_UNLOCK",
                    &format!("Failed to unlock vault: {}", e),
                    false,
                );
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}
