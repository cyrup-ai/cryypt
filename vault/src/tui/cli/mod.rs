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
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Save {} => vault_ops::handle_save(vault, passphrase_option, use_json).await,

        Commands::Put { key, value } => crud_operations::put::handle_put(vault, &key, &value, passphrase_option, use_json).await,

        Commands::Get { key } => crud_operations::get::handle_get(vault, &key, passphrase_option, use_json).await,

        Commands::Delete { key } => crud_operations::delete::handle_delete(vault, &key, passphrase_option, use_json).await,

        Commands::List {} => query_operations::handle_list(vault, passphrase_option, use_json).await,

        Commands::Find { pattern } => query_operations::handle_find(vault, &pattern, passphrase_option, use_json).await,

        Commands::ChangePassphrase {
            old_passphrase,
            new_passphrase,
        } => {
            vault_ops::handle_change_passphrase(vault, old_passphrase, new_passphrase, passphrase_option, use_json)
                .await
        }

        Commands::Run { command } => run_command::handle_run(vault, command, passphrase_option, use_json).await,

        Commands::GenerateKey {
            namespace,
            version,
            bits,
            store,
        } => key_ops::handle_generate_key(vault, &namespace, version, bits, &store, passphrase_option, use_json).await,

        Commands::RetrieveKey {
            namespace,
            version,
            store,
        } => key_ops::handle_retrieve_key(vault, &namespace, version, &store, passphrase_option, use_json).await,

        Commands::BatchGenerateKeys {
            namespace,
            version,
            bits,
            count,
            store,
        } => {
            key_ops::handle_batch_generate_keys(
                vault, &namespace, version, bits, count, &store, passphrase_option, use_json,
            )
            .await
        }
    }
}
