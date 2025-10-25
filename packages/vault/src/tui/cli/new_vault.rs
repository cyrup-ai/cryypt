//! Vault initialization and creation
//!
//! This module handles the creation of new encrypted vaults with PQCrypto protection.
//! Vaults are created as SurrealDB databases (.db directory) with Argon2id-based encryption.
//! PQCrypto keypairs are generated and stored in the system keychain for optional file-level
//! encryption (via the separate `lock` command that creates a `.vault` armor file).

use crate::config::VaultConfig;
use crate::core::Vault;
use crate::logging::log_security_event;
use crate::tui::cli::commands;
use cryypt_pqcrypto::api::KyberSecurityLevel as SecurityLevel;
use dialoguer::{theme::ColorfulTheme, Password};
use serde_json::json;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

/// Get the default vault path using XDG Base Directory specification
///
/// Priority order:
/// 1. $XDG_CONFIG_HOME/cryypt/cryypt
/// 2. $HOME/.config/cryypt/cryypt
/// 3. Error if HOME not available
///
/// # Returns
/// Canonicalized PathBuf to the default vault location (without extension)
///
/// # Errors
/// Returns error if HOME directory cannot be determined
#[inline]
fn get_default_vault_path() -> Result<PathBuf, String> {
    // Try XDG_CONFIG_HOME first
    if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
        let mut path = PathBuf::from(xdg_config);
        path.push("cryypt");
        path.push("cryypt");
        return Ok(path);
    }

    // Fallback to $HOME/.config
    match dirs::home_dir() {
        Some(mut home) => {
            home.push(".config");
            home.push("cryypt");
            home.push("cryypt");
            Ok(home)
        }
        None => Err(
            "Cannot determine home directory. Please specify --vault-path explicitly.".to_string(),
        ),
    }
}

/// Ensure PQCrypto keypair exists in system keychain
///
/// This function checks if a keypair already exists for the given namespace and version.
/// If found, it reuses the existing keypair. If not found, it generates a new keypair
/// and stores it in the system keychain.
///
/// # Arguments
/// * `namespace` - Keychain namespace for the keypair (e.g., "pq_armor")
/// * `version` - Key version number (typically 1 for new vaults)
/// * `use_json` - Whether to output JSON format messages
///
/// # Returns
/// Ok(()) if keypair exists or was successfully generated
///
/// # Errors
/// Returns error if keypair generation or keychain storage fails
async fn ensure_pqcrypto_keypair(
    key_id: &str,
    use_json: bool,
) -> Result<(), String> {
    // Try to load existing keypair from keychain
    match commands::load_pq_key_from_keychain(key_id).await {
        Ok(_) => {
            // Keypair already exists, reuse it
            log_security_event(
                "VAULT_NEW",
                &format!(
                    "Using existing PQCrypto keypair from keychain: {}",
                    key_id
                ),
                true,
            );

            if !use_json {
                println!(
                    "🔑 Using existing PQCrypto keypair from keychain ({})",
                    key_id
                );
            }

            Ok(())
        }
        Err(_) => {
            // Keypair doesn't exist, generate new one
            if !use_json {
                println!("🔐 Generating new PQCrypto keypair...");
            }

            commands::generate_pq_keypair(key_id, SecurityLevel::Level3).await?;

            log_security_event(
                "VAULT_NEW",
                &format!(
                    "Generated new PQCrypto keypair and stored in keychain: {}",
                    key_id
                ),
                true,
            );

            Ok(())
        }
    }
}

/// Create a new encrypted vault with PQCrypto protection
///
/// This is the main entry point for vault creation. It performs the complete
/// initialization workflow:
///
/// 1. Determines vault path (custom or XDG default)
/// 2. Validates vault doesn't already exist
/// 3. Creates parent directories
/// 4. Collects passphrase (interactive or from CLI)
/// 5. Ensures PQCrypto keypair exists in keychain
/// 6. Creates and initializes vault database (.db directory)
/// 7. Generates RSA keys for JWT authentication
/// 8. Unlocks vault with passphrase to initialize encryption
/// 9. Locks vault to persist to disk
///
/// # Arguments
/// * `vault_path_option` - Optional custom vault path
/// * `passphrase_option` - Optional passphrase from command line
/// * `rsa_key_path_option` - Optional RSA key path (default: ~/.ssh/cryypt.rsa)
/// * `use_json` - Whether to output JSON format
///
/// # Returns
/// Ok(()) if vault was successfully created
///
/// # Errors
/// Returns error if:
/// - Vault already exists
/// - Cannot create directories
/// - Passphrase validation fails
/// - PQCrypto operations fail
/// - Database initialization fails
pub async fn handle_new_command(
    vault_path_option: Option<&Path>,
    passphrase_option: Option<&str>,
    rsa_key_path_option: Option<PathBuf>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Determine vault path
    let base_path = match vault_path_option {
        Some(path) => {
            // Use provided path, strip any .vault or .db extension
            let path_str = path.to_string_lossy();
            if let Some(stripped) = path_str.strip_suffix(".vault") {
                PathBuf::from(stripped)
            } else if let Some(stripped) = path_str.strip_suffix(".db") {
                PathBuf::from(stripped)
            } else {
                path.to_path_buf()
            }
        }
        None => get_default_vault_path()?,
    };

    // Step 2: Check if vault already exists
    let vault_file = base_path.with_extension("vault");
    let db_file = base_path.with_extension("db");

    if vault_file.exists() {
        let error_msg = format!(
            "Vault already exists at: {}\nUse a different path or remove the existing vault first.",
            vault_file.display()
        );

        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "new",
                    "error": error_msg
                })
            );
        } else {
            eprintln!("❌ {}", error_msg);
        }

        return Err(error_msg.into());
    }

    if db_file.exists() {
        let error_msg = format!(
            "Vault database already exists at: {}\nUse a different path or remove the existing database first.",
            db_file.display()
        );

        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "new",
                    "error": error_msg
                })
            );
        } else {
            eprintln!("❌ {}", error_msg);
        }

        return Err(error_msg.into());
    }

    // Step 3: Create parent directories
    if let Some(parent) = base_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            let error_msg = format!(
                "Failed to create parent directories for {}: {}",
                parent.display(),
                e
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "new",
                        "error": error_msg
                    })
                );
            }

            error_msg
        })?;
    }

    // Step 4: Get passphrase
    let passphrase = match passphrase_option {
        Some(pass) => {
            // Validate non-empty
            if pass.is_empty() {
                let error_msg = "Passphrase cannot be empty";
                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "new",
                            "error": error_msg
                        })
                    );
                }
                return Err(error_msg.into());
            }
            pass.to_string()
        }
        None => {
            // Check if we're in a non-interactive environment
            if use_json || !std::io::stdin().is_terminal() {
                let error_msg = "Passphrase required in non-interactive mode. Use --passphrase option.";
                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "new",
                            "error": error_msg
                        })
                    );
                }
                return Err(error_msg.into());
            }

            // Interactive passphrase collection with confirmation
            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter vault passphrase")
                .with_confirmation("Confirm passphrase", "Passphrases don't match")
                .interact()
                .map_err(|e| {
                    let error_msg = format!("Failed to read passphrase: {}", e);
                    if use_json {
                        println!(
                            "{}",
                            json!({
                                "success": false,
                                "operation": "new",
                                "error": error_msg
                            })
                        );
                    }
                    error_msg
                })?
        }
    };

    // Step 5: Generate unique UUID-based PQCrypto key_id for this vault
    let key_id = commands::generate_unique_key_id("pq_armor");
    ensure_pqcrypto_keypair(&key_id, use_json).await?;

    // Step 6: Create and initialize temporary .db file
    if !use_json {
        println!("📦 Creating vault database...");
    }

    // Create vault config pointing to the .db file
    let config = VaultConfig {
        vault_path: db_file.clone(),
        ..Default::default()
    };

    // Create vault with fortress encryption (initializes provider and database)
    let vault = Vault::with_fortress_encryption_async(config)
        .await
        .map_err(|e| {
            let error_msg = format!("Failed to create vault: {}", e);
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "new",
                        "error": error_msg
                    })
                );
            }
            error_msg
        })?;

    // Unlock vault with passphrase to initialize it
    let unlock_request = vault.unlock(&passphrase).await.map_err(|e| {
        let error_msg = format!("Failed to initialize vault: {}", e);
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "new",
                    "error": error_msg
                })
            );
        }
        error_msg
    })?;

    // Wait for unlock to complete
    unlock_request.await.map_err(|e| {
        let error_msg = format!("Failed to unlock vault during initialization: {}", e);
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "new",
                    "error": error_msg
                })
            );
        }
        error_msg
    })?;

    // Lock to save the vault to disk
    let lock_request = vault.lock().await.map_err(|e| {
        let error_msg = format!("Failed to save vault: {}", e);
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "new",
                    "error": error_msg
                })
            );
        }
        error_msg
    })?;

    // Wait for lock to complete (this saves the .db file)
    lock_request.await.map_err(|e| {
        let error_msg = format!("Failed to complete vault save: {}", e);
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "new",
                    "error": error_msg
                })
            );
        }
        error_msg
    })?;

    // Step 6.5: Generate and store RSA key configuration for JWT authentication
    if !use_json {
        println!("🔑 Setting up RSA key for JWT authentication...");
    }

    use crate::auth::RsaKeyManager;
    use crate::operation::Passphrase;

    // Determine RSA key path (custom or default)
    let rsa_key_path = rsa_key_path_option.unwrap_or_else(RsaKeyManager::default_path);

    // Generate RSA key pair
    let rsa_manager = RsaKeyManager::new(rsa_key_path.clone());
    let passphrase_wrapper = Passphrase::from(passphrase.clone());
    let (private_pkcs8, public_spki) = rsa_manager
        .generate_for_jwt(&passphrase_wrapper)
        .await
        .map_err(|e| {
            let error_msg = format!("Failed to generate RSA key: {}", e);
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "new",
                        "error": error_msg
                    })
                );
            }
            error_msg
        })?;

    // Store RSA key configuration in database
    vault
        .store_vault_config(&rsa_key_path.to_string_lossy(), &public_spki)
        .await
        .map_err(|e| {
            let error_msg = format!("Failed to store RSA key config: {}", e);
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "new",
                        "error": error_msg
                    })
                );
            }
            error_msg
        })?;

    log_security_event(
        "VAULT_NEW",
        &format!("RSA key generated and stored: {}", rsa_key_path.display()),
        true,
    );

    if !use_json {
        println!("✅ RSA key generated at: {}", rsa_key_path.display());
    }

    // Step 7: Apply PQCrypto armor immediately (.db → .vault)
    if !use_json {
        println!("🔐 Applying PQCrypto armor...");
    }

    use crate::services::{KeychainStorage, PQCryptoArmorService};
    let key_storage = KeychainStorage::default_app();
    let armor_service = PQCryptoArmorService::new(key_storage, SecurityLevel::Level3);
    let vault_file = base_path.with_extension("vault");

    // Reuse the same key_id generated earlier
    armor_service
        .armor(&db_file, &vault_file, &key_id)
        .await
        .map_err(|e| {
            let error_msg = format!("Failed to apply PQCrypto armor: {}", e);
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "new",
                        "error": error_msg
                    })
                );
            } else {
                eprintln!("❌ {}", error_msg);
            }
            error_msg
        })?;

    // Step 8: Output success message
    log_security_event(
        "VAULT_NEW",
        &format!("New vault created successfully at: {}", vault_file.display()),
        true,
    );

    if use_json {
        println!(
            "{}",
            json!({
                "success": true,
                "operation": "new",
                "vault_path": vault_file.display().to_string(),
                "message": "Vault created and armored with PQCrypto",
                "next_steps": {
                    "login": format!("vault --vault-path {} login --passphrase <pass>", base_path.display()),
                    "usage": format!("vault --vault-path {} put mykey \"myvalue\" --passphrase <pass>", base_path.display())
                }
            })
        );
    } else {
        println!();
        println!("✅ Vault created and secured with PQCrypto armor!");
        println!();
        println!("📍 Location: {}", vault_file.display());
        println!();
        println!("📋 Next steps:");
        println!("   1. Login to generate JWT token:");
        println!("      vault --vault-path {} login --passphrase <your-passphrase>", base_path.display());
        println!();
        println!("   2. Start using your vault:");
        println!(
            "      vault --vault-path {} put mykey \"myvalue\"",
            base_path.display()
        );
        println!(
            "      vault --vault-path {} get mykey",
            base_path.display()
        );
        println!();
        println!("🔐 Value encryption: Argon2id key derivation + AES-256-GCM");
        println!("🛡️  File armor: ML-KEM-768 (post-quantum) + AES-256-GCM");
        println!("🔑 Keys stored securely in system keychain");
    }

    Ok(())
}
