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
use std::path::Path;

/// Handle vault login and JWT token generation
///
/// # Arguments
/// * `vault` - The vault instance to authenticate against
/// * `passphrase_option` - Optional passphrase from command line
/// * `expires_in_hours` - JWT token expiration time in hours
/// * `use_json` - Whether to output in JSON format
///
/// # Returns
/// JWT token string for subsequent vault operations
///
/// # Security
/// - Validates passphrase by attempting to unlock vault
/// - Generates JWT token with specified expiration
/// - Logs authentication events for security auditing
/// - Returns token that user must save for future operations
pub async fn handle_login(
    vault: &Vault,
    passphrase_option: Option<&str>,
    expires_in_hours: u64,
    use_json: bool,
) -> VaultResult<()> {
    // Get passphrase from user input or command line
    let passphrase = match passphrase_option {
        Some(pass) => pass.to_string(),
        None => {
            if use_json {
                return Err(VaultError::InvalidInput(
                    "Passphrase required in JSON mode. Use --passphrase option.".to_string(),
                ));
            }

            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter vault passphrase")
                .interact()
                .map_err(|e| VaultError::Io(std::io::Error::other(e)))?
        }
    };

    // Attempt to unlock vault with provided passphrase
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

                    // Generate JWT token using vault's public API
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
        }
    }

    Ok(())
}

/// Enhanced login handler (alias for handle_login for compatibility)
pub async fn handle_enhanced_login(
    vault: &Vault,
    _vault_path: Option<&std::path::Path>,
    passphrase_option: Option<&str>,
    expires_in_hours: u64,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    handle_login(vault, passphrase_option, expires_in_hours, use_json)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}
