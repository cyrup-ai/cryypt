//! CLI module for command-line interface functionality

pub mod commands;
pub mod vault_ops;
pub mod key_ops;
pub mod run_command;

use commands::{Cli, Commands};
use crate::core::Vault;

/// Process the CLI command
pub async fn process_command(vault: &Vault, command: Commands, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Save {} => vault_ops::handle_save(vault, use_json).await,
        
        Commands::Put { key, value } => vault_ops::handle_put(vault, &key, &value, use_json).await,
        
        Commands::Get { key } => vault_ops::handle_get(vault, &key, use_json).await,
        
        Commands::Delete { key } => vault_ops::handle_delete(vault, &key, use_json).await,
        
        Commands::List {} => vault_ops::handle_list(vault, use_json).await,
        
        Commands::Find { pattern } => vault_ops::handle_find(vault, &pattern, use_json).await,
        
        Commands::ChangePassphrase { old_passphrase, new_passphrase } => {
            vault_ops::handle_change_passphrase(vault, old_passphrase, new_passphrase, use_json).await
        }
        
        Commands::Run { command } => run_command::handle_run(vault, command, use_json).await,
        
        Commands::GenerateKey { namespace, version, bits, store } => {
            key_ops::handle_generate_key(&namespace, version, bits, &store, use_json).await
        }
        
        Commands::RetrieveKey { namespace, version, store } => {
            key_ops::handle_retrieve_key(&namespace, version, store, use_json).await
        }
        
        Commands::BatchGenerateKeys { namespace, version, bits, count, store } => {
            key_ops::handle_batch_generate_keys(&namespace, version, bits, count, &store, use_json).await
        }
    }
}