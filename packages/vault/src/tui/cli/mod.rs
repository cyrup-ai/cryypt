//! CLI module for command-line interface functionality

pub mod auth;
pub mod auth_operations;
pub mod commands;
pub mod crud_operations;
pub mod data_ops;
pub mod key_ops;
pub mod new_vault;
pub mod passphrase_operations;
pub mod query_operations;
pub mod run_command;
pub mod save_ops;
pub mod search_ops;
pub mod security_ops;
pub mod tokenization;
pub mod unlock_operations;
pub mod vault_detection;
pub mod vault_ops;

use crate::core::Vault;
pub use commands::{Cli, Commands};
use key_ops::BatchKeyConfig;
use std::path::PathBuf;

/// Process the CLI command
pub async fn process_command(
    vault: &Vault,
    command: Commands,
    global_vault_path: Option<PathBuf>,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::New {
            vault_path,
            passphrase,
        } => {
            // Prefer command-specific vault_path over global
            let final_vault_path = vault_path.or(global_vault_path);
            new_vault::handle_new_command(
                final_vault_path.as_deref(),
                passphrase.as_deref(),
                use_json,
            )
            .await
        }

        Commands::Save {} => vault_ops::handle_save(vault, passphrase_option, use_json).await,

        Commands::Put {
            key,
            value,
            namespace,
        } => {
            crud_operations::put::handle_put(
                vault,
                &key,
                &value,
                namespace.as_deref(),
                passphrase_option,
                use_json,
            )
            .await
        }

        Commands::Get { key, namespace } => {
            crud_operations::get::handle_get(
                vault,
                &key,
                namespace.as_deref(),
                passphrase_option,
                use_json,
            )
            .await
        }

        Commands::Delete { key, namespace } => {
            crud_operations::delete::handle_delete(
                vault,
                &key,
                namespace.as_deref(),
                passphrase_option,
                use_json,
            )
            .await
        }

        Commands::List {
            namespace,
            namespaces,
        } => {
            query_operations::handle_list(
                vault,
                namespace.as_deref(),
                namespaces,
                passphrase_option,
                use_json,
            )
            .await
        }

        Commands::Find { pattern, namespace } => {
            query_operations::handle_find(
                vault,
                &pattern,
                namespace.as_deref(),
                passphrase_option,
                use_json,
            )
            .await
        }

        Commands::ChangePassphrase {
            old_passphrase,
            new_passphrase,
        } => {
            vault_ops::handle_change_passphrase(vault, old_passphrase, new_passphrase, use_json)
                .await
        }

        Commands::Login {
            passphrase,
            expires_in,
        } => {
            let vault_path = global_vault_path.as_deref();
            auth_operations::handle_login(
                vault,
                vault_path,
                passphrase.as_deref(),
                expires_in,
                use_json,
            )
            .await
        }

        Commands::Logout { vault_path } => {
            let vault_path = vault_path
                .or(global_vault_path)
                .unwrap_or_else(|| PathBuf::from("vault"));
            auth_operations::handle_logout(vault, Some(&vault_path), use_json).await
        }

        Commands::Run {
            command,
            namespace,
            jwt,
        } => run_command::handle_enhanced_run(vault, command, namespace, jwt, use_json).await,

        Commands::GenerateKey {
            namespace,
            version,
            bits,
            store,
        } => {
            key_ops::handle_generate_key(
                vault,
                &namespace,
                version,
                bits,
                &store,
                passphrase_option,
                use_json,
            )
            .await
        }

        Commands::RetrieveKey {
            namespace,
            version,
            store,
        } => {
            key_ops::handle_retrieve_key(
                vault,
                &namespace,
                version,
                &store,
                passphrase_option,
                use_json,
            )
            .await
        }

        Commands::BatchGenerateKeys {
            namespace,
            version,
            bits,
            count,
            store,
        } => {
            key_ops::handle_batch_generate_keys(
                vault,
                BatchKeyConfig {
                    namespace: &namespace,
                    version,
                    bits,
                    count,
                    store: &store,
                    passphrase_option,
                    use_json,
                },
            )
            .await
        }

        Commands::Lock {
            vault_path,
            pq_public_key,
            keychain_namespace,
        } => {
            // Use command-specific path or fall back to global path
            let vault_path = vault_path
                .or(global_vault_path)
                .unwrap_or_else(|| PathBuf::from("vault.db"));

            // Auto-detect latest key version
            let key_version = commands::detect_current_key_version(&keychain_namespace)
                .await
                .map_err(|e| {
                    format!(
                        "No PQCrypto keys found for namespace '{}': {}",
                        keychain_namespace, e
                    )
                })?;

            commands::handle_lock_command(
                &vault_path,
                pq_public_key.as_deref(),
                &keychain_namespace,
                key_version,
                use_json,
            )
            .await
            .map_err(|e| e.into())
        }

        Commands::Unlock {
            vault_path,
            pq_private_key,
            keychain_namespace,
        } => {
            // Use command-specific path or fall back to global path
            let vault_path = vault_path
                .or(global_vault_path)
                .unwrap_or_else(|| PathBuf::from("vault.db"));

            // Auto-detect latest key version
            let key_version = commands::detect_current_key_version(&keychain_namespace)
                .await
                .map_err(|e| {
                    format!(
                        "No PQCrypto keys found for namespace '{}': {}",
                        keychain_namespace, e
                    )
                })?;

            commands::handle_unlock_command(
                &vault_path,
                pq_private_key.as_deref(),
                &keychain_namespace,
                key_version,
                use_json,
            )
            .await
            .map_err(|e| e.into())
        }

        Commands::RotateKeys { namespace, force } => {
            // Detect current version from keychain
            let current_version = commands::detect_current_key_version(&namespace)
                .await
                .unwrap_or(0u32); // Default to 0 if no keys exist, so new_version becomes 1

            // Discover vault files for re-encryption
            let vault_paths = match commands::discover_vault_files(&namespace, None).await {
                Ok(paths) => {
                    if paths.is_empty() {
                        log::warn!(
                            "No vaults found for key rotation in namespace '{}'",
                            namespace
                        );
                        if use_json {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "success": false,
                                    "operation": "rotate_keys",
                                    "error": "No vaults found for re-encryption",
                                    "suggestion": "Ensure vaults exist and are accessible"
                                })
                            );
                        } else {
                            eprintln!("⚠️  No vaults found for key rotation");
                            eprintln!(
                                "   Suggestion: Ensure vaults exist in current directory or ~/.cryypt/"
                            );
                        }
                    }
                    paths
                }
                Err(e) => {
                    log::error!("Failed to discover vaults: {}", e);
                    if use_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "success": false,
                                "operation": "rotate_keys",
                                "error": format!("Vault discovery failed: {}", e)
                            })
                        );
                    } else {
                        eprintln!("❌ Failed to discover vaults: {}", e);
                    }
                    return Err(e.into());
                }
            };

            match commands::rotate_pq_keys(&namespace, current_version, vault_paths).await {
                Ok(new_version) => {
                    if use_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "success": true,
                                "operation": "rotate_keys",
                                "namespace": namespace,
                                "old_version": current_version,
                                "new_version": new_version
                            })
                        );
                    } else {
                        println!("✅ PQCrypto keys rotated successfully");
                        println!("   Namespace: {}", namespace);
                        println!("   New version: {}", new_version);
                    }
                    Ok(())
                }
                Err(e) => {
                    if use_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "success": false,
                                "operation": "rotate_keys",
                                "error": e.to_string()
                            })
                        );
                    } else {
                        eprintln!("❌ Failed to rotate keys: {}", e);
                    }
                    Err(e.into())
                }
            }
        }
    }
}
