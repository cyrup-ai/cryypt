//! Security operations for vault CLI

use crate::core::Vault;
use crate::logging::log_security_event;
use dialoguer::{Password, theme::ColorfulTheme};
use serde_json::json;

pub async fn handle_change_passphrase(
    vault: &Vault,
    old_passphrase: Option<String>,
    new_passphrase: Option<String>,
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

    let old_pass = match old_passphrase {
        Some(pass) => pass,
        None => Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter current passphrase")
            .interact()?,
    };

    let new_pass = match new_passphrase {
        Some(pass) => pass,
        None => Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter new passphrase")
            .with_confirmation("Confirm new passphrase", "Passphrases don't match")
            .interact()?,
    };

    if !use_json {
        println!("Changing passphrase...");
    }

    // First unlock with old passphrase if locked
    if vault.is_locked().await {
        log_security_event(
            "CLI_UNLOCK",
            "Attempting to unlock vault for passphrase change",
            true,
        );
        match vault.unlock(&old_pass).await {
            Ok(_) => {
                log_security_event("CLI_UNLOCK", "Vault unlocked for passphrase change", true);
            }
            Err(e) => {
                log_security_event(
                    "CLI_UNLOCK",
                    &format!("Failed to unlock vault for passphrase change: {e}"),
                    false,
                );

                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "change_passphrase",
                            "error": format!("Failed to unlock vault: {e}")
                        })
                    );
                    return Ok(());
                } else {
                    return Err(Box::new(e));
                }
            }
        }
    }

    // Use the change_passphrase method directly
    match vault.change_passphrase(&old_pass, &new_pass).await {
        Ok(_) => {
            log_security_event(
                "CLI_PASSPHRASE_CHANGE",
                "Passphrase changed successfully",
                true,
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": true,
                        "operation": "change_passphrase"
                    })
                );
            } else {
                println!("Passphrase changed successfully");
            }
        }
        Err(e) => {
            log_security_event(
                "CLI_PASSPHRASE_CHANGE",
                &format!("Failed to change passphrase: {e}"),
                false,
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "change_passphrase",
                        "error": format!("Failed to change passphrase: {e}")
                    })
                );
                return Ok(());
            } else {
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}
