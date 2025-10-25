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
    rsa_key_path: Option<PathBuf>,
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
                rsa_key_path,
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
                rsa_key_path,
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

            // Smart key_id determination:
            // - If .vault file exists, read and reuse existing key_id
            // - If .vault doesn't exist, generate new UUID-based key_id
            let vault_file = vault_path.with_extension("vault");
            let key_id = if vault_file.exists() {
                // Reuse existing key from .vault file
                use crate::services::armor::read_key_id_from_vault_file;
                read_key_id_from_vault_file(&vault_file)
                    .await
                    .map_err(|e| {
                        format!(
                            "Failed to read key ID from {}: {}",
                            vault_file.display(), e
                        )
                    })?
            } else {
                // Generate new UUID-based key_id for fresh vault
                commands::generate_unique_key_id(&keychain_namespace)
            };

            commands::handle_lock_command(
                &vault_path,
                pq_public_key.as_deref(),
                &key_id,
                use_json,
            )
            .await
            .map_err(|e| e.into())
        }

        Commands::Unlock {
            vault_path,
            pq_private_key,
        } => {
            // Use command-specific path or fall back to global path
            let vault_path = vault_path
                .or(global_vault_path)
                .unwrap_or_else(|| PathBuf::from("vault.db"));

            // Read key ID from .vault file header
            use crate::services::armor::read_key_id_from_vault_file;
            let vault_file_path = vault_path.with_extension("vault");
            let key_id = read_key_id_from_vault_file(&vault_file_path)
                .await
                .map_err(|e| {
                    format!(
                        "Failed to read key ID from {}: {}",
                        vault_file_path.display(), e
                    )
                })?;

            commands::handle_unlock_command(
                &vault_path,
                pq_private_key.as_deref(),
                &key_id,
                use_json,
            )
            .await
            .map_err(|e| e.into())
        }

        Commands::RotateKeys { vault_path, namespace, force } => {
            // RotateKeys now requires explicit vault path
            match commands::rotate_pq_keys(&vault_path, &namespace).await {
                Ok(()) => {
                    if use_json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "success": true,
                                "operation": "rotate_keys",
                                "vault_path": vault_path.display().to_string(),
                                "namespace": namespace,
                                "message": "Key rotated successfully, old key deleted from keychain"
                            })
                        );
                    } else {
                        println!("✅ PQCrypto key rotated successfully");
                        println!("   Vault: {}", vault_path.display());
                        println!("   Namespace: {}", namespace);
                        println!("   🗑️  Old key deleted from keychain");
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
