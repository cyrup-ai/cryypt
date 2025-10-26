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
/// 4. Loads RSA keys for JWT signing
/// 5. Generates JWT token with specified expiration
/// 6. Provides clear success/error messages
///
/// # Arguments
/// * `vault` - The vault instance to authenticate against
/// * `vault_path` - Optional path to vault file (defaults to "vault")
/// * `passphrase_option` - Optional passphrase from command line
/// * `key_path_option` - Optional RSA key path (overrides stored config)
/// * `expires_in_hours` - JWT token expiration time in hours
/// * `use_json` - Whether to output in JSON format
///
/// # Returns
/// JWT token string for subsequent vault operations
///
/// # Security
/// - Auto-unlocks .vault files using PQCrypto
/// - Validates passphrase by attempting to unlock vault
/// - Uses RSA keys for RS256 JWT signing
/// - Logs authentication events for security auditing
pub async fn handle_login(
    vault: &Vault,
    vault_path: Option<&Path>,
    passphrase_option: Option<&str>,
    key_path_option: Option<std::path::PathBuf>,
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

            // Read key ID from .vault file
            use crate::services::armor::read_key_id_from_vault_file;
            let vault_path = vault_file.with_extension("vault");
            let key_id = read_key_id_from_vault_file(&vault_path)
                .await
                .map_err(|e| format!("Failed to read key ID from vault file: {}", e))?;

            // Call unlock command to convert .vault → .db
            commands::handle_unlock_command(&vault_file, None, &key_id, use_json).await?;
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

    // Step 4: Check if vault is already authenticated (has valid JWT session and encryption key)
    let needs_unlock = !vault.is_authenticated().await;

    if needs_unlock {
        if use_json {
            println!(
                "{}",
                json!({
                    "operation": "unlock",
                    "message": "Unlocking vault with passphrase"
                })
            );
        } else {
            println!("🔓 Unlocking vault with passphrase...");
        }

        // Unlock in-memory vault with passphrase
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
    } else {
        if use_json {
            println!(
                "{}",
                json!({
                    "operation": "unlock",
                    "message": "Vault already authenticated, skipping unlock",
                    "status": "skipped"
                })
            );
        } else {
            println!("✅ Vault already authenticated, generating new JWT token");
        }
        log_security_event(
            "CLI_LOGIN",
            "Vault already authenticated, skipping unlock for JWT generation",
            true,
        );
    }

    // Step 4.5: Load RSA keys for JWT signing
    use crate::auth::RsaKeyManager;

    // Try to load vault config to get stored RSA key path
    let rsa_key_path = match vault.load_vault_config().await {
        Ok(Some(config)) => {
            // Use stored key path, or override with CLI --key if provided
            key_path_option.unwrap_or_else(|| std::path::PathBuf::from(config.rsa_key_path))
        }
        Ok(None) => {
            // No stored config, use CLI --key or default
            key_path_option.unwrap_or_else(RsaKeyManager::default_path)
        }
        Err(e) => {
            let error_msg = format!("Failed to load vault config: {}", e);
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
    };

    // Load RSA keys in JWT-compatible format
    let rsa_manager = RsaKeyManager::new(rsa_key_path.clone());
    let (private_pkcs8, public_spki) = match rsa_manager.load_for_jwt().await {
        Ok(keys) => keys,
        Err(e) => {
            let error_msg = format!("Failed to load RSA key from {}: {}", rsa_key_path.display(), e);
            log_security_event("CLI_LOGIN", &error_msg, false);
            
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "login",
                        "error": error_msg,
                        "hint": "Run 'vault new' to generate RSA keys"
                    })
                );
            } else {
                println!("❌ Error: {}", error_msg);
                println!("Hint: Run 'vault new' to generate RSA keys");
            }
            return Err(error_msg.into());
        }
    };

    // Step 5: Create JWT handler with RSA keys and generate token
    let vault_config = vault.config().await.map_err(|e| {
        let error_msg = format!("Failed to get vault config: {}", e);
        log_security_event("CLI_LOGIN", &error_msg, false);
        error_msg
    })?;
    let vault_id = vault_config.vault_path.to_string_lossy().to_string();
    let jwt_handler = JwtHandler::new(vault_id, private_pkcs8, public_spki);

    let jwt_token = match jwt_handler.create_jwt_token(Some(expires_in_hours)).await {
        Ok(token) => token,
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
    };

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
                    "jwt_flag": "--jwt <token>",
                    "command_example": "vault --jwt \"<token>\" get mykey"
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
        println!("Use the --jwt flag to run vault operations without password prompts:");
        println!("   vault --jwt \"{}\" get mykey", jwt_token);
        println!("   vault --jwt \"{}\" put newkey \"new value\"", jwt_token);
        println!("   vault --jwt \"{}\" list", jwt_token);
        println!();
        println!("⚠️  Security Notes:");
        println!(
            "   • Keep this token secure - it provides full vault access"
        );
        println!("   • Token expires in {} hours", expires_in_hours);
        println!("   • Run 'vault login' again when token expires");
    }

    Ok(())
}
