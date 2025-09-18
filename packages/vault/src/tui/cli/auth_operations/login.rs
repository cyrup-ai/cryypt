//! Login operations for vault CLI commands
//!
//! This module provides JWT-based authentication for secure vault access.
//! Users login once with their passphrase and receive a JWT token for subsequent operations.

use crate::auth::JwtHandler;
use crate::core::Vault;
use crate::error::{VaultError, VaultResult};
use crate::logging::log_security_event;
use crate::operation::Passphrase;
use dialoguer::{Password, theme::ColorfulTheme};
use serde_json::json;

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
) -> Result<(), Box<dyn std::error::Error>> {
    if !use_json {
        println!("🔐 Vault Login");
        println!("Logging in to generate JWT token for secure vault access...");
    }

    // Get passphrase from user
    let passphrase = if let Some(pass) = passphrase_option {
        log_security_event(
            "CLI_LOGIN",
            "Using passphrase from command line option",
            true,
        );
        pass.to_string()
    } else if use_json {
        // In JSON mode, don't prompt interactively - require --passphrase option
        log_security_event(
            "CLI_LOGIN",
            "Failed to login in JSON mode - no passphrase provided",
            false,
        );
        println!(
            "{}",
            json!({
                "success": false,
                "operation": "login",
                "error": "No passphrase provided. Use --passphrase option when using --json"
            })
        );
        return Ok(());
    } else {
        // Prompt for passphrase interactively
        Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter vault passphrase")
            .interact()?
    };

    // Attempt to unlock vault to validate passphrase
    match vault.unlock(&passphrase).await {
        Ok(unlock_request) => {
            // Wait for unlock to complete
            match unlock_request.await {
                Ok(_) => {
                    log_security_event("CLI_LOGIN", "Vault unlocked successfully for JWT generation", true);
                    
                    // Get JWT operations (handler and encryption key)
                    match vault.get_jwt_operations().await {
                        Ok((jwt_handler, encryption_key)) => {
                            // Generate JWT token
                            match jwt_handler.create_jwt_token(&encryption_key, Some(expires_in_hours)).await {
                                Ok(jwt_token) => {
                                    log_security_event(
                                        "CLI_LOGIN", 
                                        &format!("JWT token generated successfully (expires in {} hours)", expires_in_hours), 
                                        true
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
                                        println!("2. Now you can run vault operations without password prompts:");
                                        println!("   vault get mykey");
                                        println!("   vault put newkey \"new value\"");
                                        println!("   vault list");
                                        println!();
                                        println!("⚠️  Security Notes:");
                                        println!("   • Keep this token secure - it provides full vault access");
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
                            let error_msg = format!("Failed to access JWT operations: {}", e);
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

/// Handle vault logout (clear JWT session)
/// 
/// # Arguments
/// * `use_json` - Whether to output in JSON format
/// 
/// # Security
/// - Provides instructions for clearing JWT token
/// - Logs logout events for security auditing
pub async fn handle_logout(use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    log_security_event("CLI_LOGOUT", "User logout requested", true);

    if use_json {
        println!(
            "{}",
            json!({
                "success": true,
                "operation": "logout",
                "message": "To logout, unset the VAULT_JWT environment variable",
                "instructions": "unset VAULT_JWT"
            })
        );
    } else {
        println!("🔓 Vault Logout");
        println!();
        println!("To logout and clear your JWT session:");
        println!("   unset VAULT_JWT");
        println!();
        println!("Or restart your terminal session.");
        println!("✅ Logout instructions provided.");
    }

    Ok(())
}