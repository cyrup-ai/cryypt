//! Passphrase management operations for vault CLI commands

use crate::core::Vault;
use crate::logging::log_security_event;
use dialoguer::{Password, theme::ColorfulTheme};
use serde_json::json;
use std::io::IsTerminal;

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
        None => {
            // Check if we're in a non-interactive environment
            if use_json || !std::io::stdin().is_terminal() {
                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "change_passphrase",
                            "error": "Old passphrase required in non-interactive mode. Provide via command line arguments."
                        })
                    );
                } else {
                    eprintln!("Error: Old passphrase required in non-interactive mode.");
                    eprintln!("Usage: vault change-passphrase --old-passphrase <OLD> --new-passphrase <NEW>");
                }
                return Err("Passphrase required in non-interactive mode".into());
            }
            
            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter current passphrase")
                .interact()?
        }
    };

    let new_pass = match new_passphrase {
        Some(pass) => pass,
        None => {
            // Check if we're in a non-interactive environment
            if use_json || !std::io::stdin().is_terminal() {
                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "change_passphrase",
                            "error": "New passphrase required in non-interactive mode. Provide via command line arguments."
                        })
                    );
                } else {
                    eprintln!("Error: New passphrase required in non-interactive mode.");
                    eprintln!("Usage: vault change-passphrase --old-passphrase <OLD> --new-passphrase <NEW>");
                }
                return Err("Passphrase required in non-interactive mode".into());
            }
            
            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter new passphrase")
                .with_confirmation("Confirm new passphrase", "Passphrases don't match")
                .interact()?
        }
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
            Ok(req) => {
                // Complete the unlock operation by awaiting the request
                if let Err(e) = req.await {
                    log_security_event(
                        "CLI_UNLOCK",
                        &format!("Failed to complete unlock for passphrase change: {e}"),
                        false,
                    );

                    if use_json {
                        println!(
                            "{}",
                            json!({
                                "success": false,
                                "operation": "change_passphrase",
                                "error": format!("Failed to complete unlock: {e}")
                            })
                        );
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
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

    // Use the change_passphrase method directly (requires double await for VaultChangePassphraseRequest)
    let change_request = match vault.change_passphrase(&old_pass, &new_pass).await {
        Ok(request) => request,
        Err(e) => {
            log_security_event(
                "CLI_PASSPHRASE_CHANGE",
                &format!("Failed to initiate passphrase change: {e}"),
                false,
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "change_passphrase",
                        "error": format!("Failed to initiate passphrase change: {e}")
                    })
                );
                return Ok(());
            } else {
                return Err(Box::new(e));
            }
        }
    };

    match change_request.await {
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
