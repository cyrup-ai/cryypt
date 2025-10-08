//! Single key retrieval operations for CLI commands

use super::master_key::derive_master_key_from_vault;
use crate::core::Vault;
use crate::logging::log_security_event;
use cryypt_key::{api::KeyStore, store::FileKeyStore};
use serde_json::json;

pub async fn handle_retrieve_key(
    vault: &Vault,
    namespace: &str,
    version: u32,
    store: &str,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !use_json {
        println!(
            "Retrieving key with namespace '{}', version {}...",
            namespace, version
        );
    }

    // Retrieve the key using README.md pattern with on_result unwrapping
    let master_key = derive_master_key_from_vault(vault, passphrase_option)
        .await
        .map_err(|e| format!("Failed to derive master key: {e}"))?;

    let key_bytes = if store.starts_with("file:") {
        let path = store
            .strip_prefix("file:")
            .ok_or("Invalid file store path format")?;
        let store = FileKeyStore::at(path).with_master_key(master_key);

        match store.retrieve_key(namespace, version).await {
            Ok(key_bytes) => {
                log::info!("Key retrieval successful");
                key_bytes
            }
            Err(e) => {
                log::error!("Key retrieval failed: {}", e);
                log_security_event("KEY_RETRIEVAL_FAILED", &e.to_string(), false);
                Vec::new()
            }
        }
    } else {
        // Use temporary file store for "memory" option
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(".cryypt_temp_keys");
        let store = FileKeyStore::at(temp_path).with_master_key(master_key);

        match store.retrieve_key(namespace, version).await {
            Ok(key_bytes) => {
                log::info!("Key retrieval successful");
                key_bytes
            }
            Err(e) => {
                log::error!("Key retrieval failed: {}", e);
                log_security_event("KEY_RETRIEVAL_FAILED", &e.to_string(), false);
                Vec::new()
            }
        }
    };

    // Key bytes are now fully unwrapped
    if key_bytes.is_empty() {
        let key_id = format!("{}:v{}", namespace, version);
        log_security_event(
            "CLI_RETRIEVE_KEY",
            &format!("Failed to retrieve key: {key_id}"),
            false,
        );

        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "retrieve_key",
                    "key_id": key_id,
                    "error": "Key not found or retrieval failed"
                })
            );
        } else {
            println!("Key retrieval failed: key not found");
        }
    } else {
        let key_id = format!("{}:v{}", namespace, version);
        log_security_event(
            "CLI_RETRIEVE_KEY",
            &format!("Retrieved key: {key_id}"),
            true,
        );

        if use_json {
            println!(
                "{}",
                json!({
                    "success": true,
                    "operation": "retrieve_key",
                    "key_id": key_id,
                    "size_bytes": key_bytes.len(),
                    "store": store
                })
            );
        } else {
            println!("Key retrieved successfully:");
            println!("  ID: {}", key_id);
            println!("  Size: {} bytes", key_bytes.len());
        }
    }
    Ok(())
}
