//! Login operations for vault CLI commands
//!
//! This module provides JWT-based authentication for secure vault access.
//! Users login once with their passphrase and receive a JWT token for subsequent operations.

use crate::auth::JwtHandler;
use crate::core::Vault;
use crate::error::{VaultError, VaultResult};
use crate::logging::log_security_event;
use crate::operation::Passphrase;
use crate::tui::cli::commands;
use crate::tui::cli::vault_detection::{VaultState, detect_vault_state};
use dialoguer::{Password, theme::ColorfulTheme};
use serde_json::json;
use std::io::IsTerminal;
use std::path::Path;

/// Handle vault login with auto-detection and JWT token generation
///
/// This function performs a complete login workflow:
/// 1. Auto-detects vault state (.vault vs .db)
/// 2. Unlocks .vault file automatically if needed (converts .vault → .db)
/// 3. Unlocks in-memory vault with passphrase
/// 4. Generates JWT token with specified expiration
/// 5. Provides clear success/error messages
///
/// # Arguments
/// * `vault` - The vault instance to authenticate against
/// * `vault_path` - Optional path to vault file (defaults to "vault")
/// * `passphrase_option` - Optional passphrase from command line
/// * `expires_in_hours` - JWT token expiration time in hours
/// * `use_json` - Whether to output in JSON format
///
/// # Returns
/// JWT token string for subsequent vault operations
///
/// # Security
/// - Auto-unlocks .vault files using PQCrypto
/// - Validates passphrase by attempting to unlock vault
/// - Generates JWT token with specified expiration
/// - Logs authentication events for security auditing
pub async fn handle_login(
    vault: &Vault,
    vault_path: Option<&Path>,
    passphrase_option: Option<&str>,
    expires_in_hours: u64,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Auto-detect vault state (.vault vs .db)
    let vault_state = detect_vault_state(vault_path.unwrap_or(Path::new("vault")))?;

    // Step 2: Unlock .vault file if needed (PQCrypto armor removal)
    match vault_state {
        VaultState::Locked {
            vault_file,
            db_file: _,
        } => {
            if use_json {
                println!(
                    "{}",
                    json!({
                        "operation": "unlock",
                        "message": "Vault is locked, unlocking automatically",
                        "file": vault_file.display().to_string()
                    })
                );
            } else {
                println!("🔓 Vault is locked, unlocking automatically...");
            }

            // Call unlock command to convert .vault → .db
            commands::handle_unlock_command(&vault_file, None, "pq_armor", 1, use_json).await?;
        }
        VaultState::Unlocked { .. } => {
            if use_json {
                println!(
                    "{}",
                    json!({
                        "operation": "unlock",
                        "message": "Vault already unlocked",
                        "status": "skipped"
                    })
                );
            } else {
                println!("🔓 Vault already unlocked");
            }
        }
    }

    // Step 3: Get passphrase from user input or command line
    let passphrase = match passphrase_option {
        Some(pass) => pass.to_string(),
        None => {
            // Check if we're in a non-interactive environment
            if use_json || !std::io::stdin().is_terminal() {
                return Err("Passphrase required in non-interactive mode. Use --passphrase option or CYSEC_PASSPHRASE environment variable.".into());
            }

            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter vault passphrase")
                .interact()
                .map_err(|e| format!("Failed to read passphrase: {}", e))?
        }
    };

    // Step 4: Unlock in-memory vault with passphrase
    match vault.unlock(&passphrase).await {
        Ok(unlock_request) => {
            // Wait for unlock to complete
            match unlock_request.await {
                Ok(_) => {
                    log_security_event(
                        "CLI_LOGIN",
                        "Vault unlocked successfully for JWT generation",
                        true,
                    );

                    // Step 5: Generate JWT token
                    match vault.create_jwt_token(expires_in_hours).await {
                        Ok(jwt_token) => {
                            log_security_event(
                                "CLI_LOGIN",
                                &format!(
                                    "JWT token generated successfully (expires in {} hours)",
                                    expires_in_hours
                                ),
                                true,
                            );

                            if use_json {
                                println!(
                                    "{}",
                                    json!({
                                        "success": true,
                                        "operation": "login",
                                        "jwt_token": jwt_token,
                                        "expires_in_hours": expires_in_hours,
                                        "usage_instructions": {
                                            "environment_variable": "export VAULT_JWT=\"<token>\"",
                                            "command_example": "vault get mykey"
                                        }
                                    })
                                );
                            } else {
                                println!("✅ Login successful!");
                                println!();
                                println!("🎫 JWT Token (expires in {} hours):", expires_in_hours);
                                println!("{}", jwt_token);
                                println!();
                                println!("📋 Usage Instructions:");
                                println!("1. Save the token in your environment:");
                                println!("   export VAULT_JWT=\"{}\"", jwt_token);
                                println!();
                                println!(
                                    "2. Now you can run vault operations without password prompts:"
                                );
                                println!("   vault get mykey");
                                println!("   vault put newkey \"new value\"");
                                println!("   vault list");
                                println!();
                                println!("⚠️  Security Notes:");
                                println!(
                                    "   • Keep this token secure - it provides full vault access"
                                );
                                println!("   • Token expires in {} hours", expires_in_hours);
                                println!("   • Run 'vault login' again when token expires");
                            }
                        }
                        Err(e) => {
                            let error_msg = format!("Failed to generate JWT token: {}", e);
                            log_security_event("CLI_LOGIN", &error_msg, false);

                            if use_json {
                                println!(
                                    "{}",
                                    json!({
                                        "success": false,
                                        "operation": "login",
                                        "error": error_msg
                                    })
                                );
                            } else {
                                println!("❌ Error: {}", error_msg);
                            }
                            return Err(error_msg.into());
                        }
                    }
                }
                Err(e) => {
                    let error_msg = format!("Failed to unlock vault: {}", e);
                    log_security_event("CLI_LOGIN", &error_msg, false);

                    if use_json {
                        println!(
                            "{}",
                            json!({
                                "success": false,
                                "operation": "login",
                                "error": error_msg
                            })
                        );
                    } else {
                        println!("❌ Error: {}", error_msg);
                    }
                    return Err(error_msg.into());
                }
            }
        }
        Err(e) => {
            let error_msg = format!("Authentication failed: {}", e);
            log_security_event("CLI_LOGIN", &error_msg, false);

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "login",
                        "error": error_msg
                    })
                );
            } else {
                println!("❌ {}", error_msg);
                println!("Please check your passphrase and try again.");
            }
            return Err(error_msg.into());
        }
    }

    Ok(())
}
