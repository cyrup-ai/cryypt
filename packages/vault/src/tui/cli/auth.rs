//! Authentication and vault unlocking utilities

use crate::core::Vault;
use crate::logging::log_security_event;
use dialoguer::{Password, theme::ColorfulTheme};

/// Ensures the vault is unlocked by prompting for a passphrase if needed
/// If using JSON mode or CYSEC_PASSPHRASE environment variable, no prompt is shown
pub async fn ensure_unlocked(
    vault: &Vault,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Layer 1: Check authentication first (JWT-based)
    if !vault.is_authenticated().await {
        if !use_json {
            eprintln!(
                "Authentication required. Set VAULT_JWT environment variable with valid JWT token."
            );
        }
        return Err("Authentication failed: No valid JWT token provided".into());
    }

    // Layer 2: Check if vault is PQCrypto armored
    if vault.is_locked().await {
        // First check for env var passphrase - allows non-interactive use
        let passphrase = if let Ok(pass) = std::env::var("CYSEC_PASSPHRASE") {
            log_security_event(
                "CLI_UNLOCK",
                "Using passphrase from environment variable",
                true,
            );
            pass
        } else if use_json {
            // In JSON mode, don't prompt interactively - return an error instead
            log_security_event(
                "CLI_UNLOCK",
                "Failed to unlock vault in JSON mode - no passphrase available",
                false,
            );
            return Err("No passphrase provided. Set CYSEC_PASSPHRASE environment variable when using --json".into());
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
                log_security_event("CLI_UNLOCK", &format!("Failed to unlock vault: {e}"), false);
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}
