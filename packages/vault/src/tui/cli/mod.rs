//! CLI module for command-line interface functionality

pub mod auth;
pub mod auth_operations;
pub mod commands;
pub mod crud_operations;
pub mod data_ops;
pub mod key_ops;
pub mod passphrase_operations;
pub mod query_operations;
pub mod run_command;
pub mod save_ops;
pub mod search_ops;
pub mod security_ops;
pub mod unlock_operations;
pub mod vault_ops;

use crate::core::Vault;
pub use commands::{Cli, Commands};

/// Process the CLI command
pub async fn process_command(
    vault: &Vault,
    command: Commands,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
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
            auth_operations::handle_login(
                vault,
                passphrase.as_deref(),
                expires_in,
                use_json,
            )
            .await
        }

        Commands::Run { command } => {
            run_command::handle_run(vault, command, passphrase_option, use_json).await
        }

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
                &namespace,
                version,
                bits,
                count,
                &store,
                passphrase_option,
                use_json,
            )
            .await
        }

        Commands::Lock {
            pq_public_key,
            keychain_namespace,
            key_version,
        } => {
            // For now, use a placeholder vault path. In a real implementation,
            // this would come from CLI args or vault configuration
            let vault_path = std::path::Path::new("vault");
            commands::handle_lock_command(
                vault_path,
                pq_public_key.as_deref(),
                &keychain_namespace,
                key_version,
                use_json,
            )
            .await
        }

        Commands::Unlock {
            pq_private_key,
            keychain_namespace,
            key_version,
        } => {
            // For now, use a placeholder vault path. In a real implementation,
            // this would come from CLI args or vault configuration
            let vault_path = std::path::Path::new("vault");
            commands::handle_unlock_command(
                vault_path,
                pq_private_key.as_deref(),
                &keychain_namespace,
                key_version,
                use_json,
            )
            .await
        }
    }
}
