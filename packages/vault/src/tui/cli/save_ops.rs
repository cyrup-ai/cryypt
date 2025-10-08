//! Save operations for vault CLI

use super::auth::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use dialoguer::{Password, theme::ColorfulTheme};
use serde_json::json;

pub async fn handle_save(vault: &Vault, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ensure_unlocked(vault, use_json).await {
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "save",
                    "error": format!("Failed to unlock vault: {e}")
                })
            );
            return Ok(());
        } else {
            return Err(e);
        }
    }

    if !use_json {
        println!("Saving vault data to disk...");
    }

    // For the "Save" command, we need to lock and unlock to save to disk
    match vault.lock().await {
        Ok(_) => {
            // Re-unlock with same passphrase that was used earlier
            let passphrase = match std::env::var("CYSEC_PASSPHRASE") {
                Ok(pass) => pass,
                Err(_) => {
                    if use_json {
                        println!(
                            "{}",
                            json!({
                                "success": false,
                                "operation": "save",
                                "error": "No passphrase available for re-unlocking vault"
                            })
                        );
                        return Ok(());
                    } else {
                        Password::with_theme(&ColorfulTheme::default())
                            .with_prompt("Enter vault passphrase to re-unlock")
                            .interact()?
                    }
                }
            };

            match vault.unlock(&passphrase).await {
                Ok(_) => {
                    log_security_event("CLI_SAVE", "Vault data saved", true);

                    if use_json {
                        println!(
                            "{}",
                            json!({
                                "success": true,
                                "operation": "save"
                            })
                        );
                    } else {
                        println!("Vault data saved successfully");
                    }
                }
                Err(e) => {
                    log_security_event(
                        "CLI_SAVE",
                        &format!("Failed to re-unlock vault after save: {e}"),
                        false,
                    );

                    if use_json {
                        println!(
                            "{}",
                            json!({
                                "success": false,
                                "operation": "save",
                                "error": format!("Failed to re-unlock vault after save: {e}")
                            })
                        );
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        }
        Err(e) => {
            log_security_event(
                "CLI_SAVE",
                &format!("Failed to save vault data: {e}"),
                false,
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "save",
                        "error": format!("Failed to save vault data: {e}")
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
