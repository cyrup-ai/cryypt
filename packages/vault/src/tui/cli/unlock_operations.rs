//! Vault authentication operations for CLI commands

use crate::core::Vault;
use crate::logging::log_security_event;
use dialoguer::{Password, theme::ColorfulTheme};

/// Ensures the vault is accessible using JWT authentication or passphrase fallback
/// 
/// # Security Model
/// 1. First priority: JWT token authentication (via VAULT_JWT env var or --jwt flag)
/// 2. Fallback: Passphrase authentication (for initial setup or when JWT expires)
/// 
/// # Arguments
/// * `vault` - The vault instance to authenticate against
/// * `passphrase_option` - Optional passphrase from command line
/// * `use_json` - Whether to output in JSON format (affects prompting behavior)
/// 
/// # Returns
/// Ok(()) if vault is accessible, Err if authentication failed
pub async fn ensure_unlocked(
    vault: &Vault,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Layer 1: Check authentication first (JWT-based)
    if !vault.is_authenticated().await {
        return Err("Authentication failed: No valid JWT token provided. Set VAULT_JWT environment variable.".into());
    }

    // Layer 2: Check if vault is PQCrypto armored
    if !vault.is_locked().await {
        log_security_event("CLI_AUTH", "Vault is not PQCrypto armored - no unlock needed", true);
        return Ok(());
    }

    // Vault is PQCrypto armored - need to unlock with passphrase
    log_security_event("CLI_AUTH", "Vault is locked - attempting passphrase authentication", true);

    // Use provided passphrase or prompt for it
    let passphrase = if let Some(pass) = passphrase_option {
        log_security_event(
            "CLI_AUTH",
            "Using passphrase from command line option",
            true,
        );
        pass.to_string()
    } else if use_json {
        // In JSON mode, don't prompt interactively - require --passphrase option
        log_security_event(
            "CLI_AUTH",
            "Failed to authenticate in JSON mode - no passphrase provided and no valid JWT token",
            false,
        );
        return Err("Authentication failed. Provide a valid JWT token via VAULT_JWT environment variable or --jwt flag, or use --passphrase option for passphrase authentication".into());
    } else {
        // Only prompt interactively in normal mode
        println!("🔐 Vault is locked. Authentication required.");
        println!("💡 Tip: Use 'vault login' to get a JWT token for passwordless operations");
        Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter vault passphrase")
            .interact()?
    };

    // Attempt to unlock with passphrase
    match vault.unlock(&passphrase).await {
        Ok(unlock_request) => {
            // Wait for unlock to complete
            match unlock_request.await {
                Ok(_) => {
                    log_security_event("CLI_AUTH", "Vault unlocked successfully with passphrase", true);
                    Ok(())
                }
                Err(e) => {
                    log_security_event(
                        "CLI_AUTH",
                        &format!("Failed to unlock vault with passphrase: {e}"),
                        false,
                    );
                    Err(Box::new(e))
                }
            }
        }
        Err(e) => {
            log_security_event(
                "CLI_AUTH",
                &format!("Failed to initiate unlock operation: {e}"),
                false,
            );
            Err(Box::new(e))
        }
    }
}
