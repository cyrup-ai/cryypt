//! CLI module for command-line interface functionality

pub mod auth;
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
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Save {} => vault_ops::handle_save(vault, use_json).await,

        Commands::Put { key, value } => vault_ops::handle_put(vault, &key, &value, use_json).await,

        Commands::Get { key } => vault_ops::handle_get(vault, &key, use_json).await,

        Commands::Delete { key } => vault_ops::handle_delete(vault, &key, use_json).await,

        Commands::List {} => vault_ops::handle_list(vault, use_json).await,

        Commands::Find { pattern } => vault_ops::handle_find(vault, &pattern, use_json).await,

        Commands::ChangePassphrase {
            old_passphrase,
            new_passphrase,
        } => {
            vault_ops::handle_change_passphrase(vault, old_passphrase, new_passphrase, use_json)
                .await
        }

        Commands::Run { command } => run_command::handle_run(vault, command, use_json).await,

        Commands::GenerateKey {
            namespace,
            version,
            bits,
            store,
        } => key_ops::handle_generate_key(vault, &namespace, version, bits, &store, use_json).await,

        Commands::RetrieveKey {
            namespace,
            version,
            store,
        } => key_ops::handle_retrieve_key(vault, &namespace, version, &store, use_json).await,

        Commands::BatchGenerateKeys {
            namespace,
            version,
            bits,
            count,
            store,
        } => {
            key_ops::handle_batch_generate_keys(
                vault, &namespace, version, bits, count, &store, use_json,
            )
            .await
        }
    }
}
