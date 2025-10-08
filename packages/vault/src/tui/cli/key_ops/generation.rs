//! Single key generation operations for CLI commands

use super::master_key::derive_master_key_from_vault;
use crate::core::Vault;
use crate::logging::log_security_event;
use cryypt_key::{api::KeyStore, store::FileKeyStore};
use serde_json::json;

pub async fn handle_generate_key(
    vault: &Vault,
    namespace: &str,
    version: u32,
    bits: u32,
    store: &str,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !use_json {
        println!(
            "Generating key with namespace '{}', version {}, {} bits...",
            namespace, version, bits
        );
    }

    // Generate the key using README.md pattern with on_result unwrapping
    let master_key = derive_master_key_from_vault(vault, passphrase_option)
        .await
        .map_err(|e| format!("Failed to derive master key: {e}"))?;

    let key_bytes = if store.starts_with("file:") {
        let path = store
            .strip_prefix("file:")
            .ok_or("Invalid file store path format")?;
        let store = FileKeyStore::at(path).with_master_key(master_key);

        match store.generate_key(bits, namespace, version).await {
            Ok(key_bytes) => {
                log::info!("Key generation successful");
                key_bytes
            }
            Err(e) => {
                log::error!("Key generation failed: {}", e);
                log_security_event("KEY_GENERATION_FAILED", &e.to_string(), false);
                Vec::new()
            }
        }
    } else {
        // Use temporary file store for "memory" option
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(".cryypt_temp_keys");
        let store = FileKeyStore::at(temp_path).with_master_key(master_key);

        match store.generate_key(bits, namespace, version).await {
            Ok(key_bytes) => {
                log::info!("Key generation successful");
                key_bytes
            }
            Err(e) => {
                log::error!("Key generation failed: {}", e);
                log_security_event("KEY_GENERATION_FAILED", &e.to_string(), false);
                Vec::new()
            }
        }
    };

    // Key bytes are now fully unwrapped
    if key_bytes.is_empty() {
        log_security_event(
            "CLI_GENERATE_KEY",
            &format!("Failed to generate key: {}:v{}", namespace, version),
            false,
        );

        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "generate_key",
                    "error": "Key generation failed"
                })
            );
        } else {
            println!("Key generation failed");
        }
    } else {
        log_security_event(
            "CLI_GENERATE_KEY",
            &format!("Generated key: {}:v{}", namespace, version),
            true,
        );

        if use_json {
            println!(
                "{}",
                json!({
                    "success": true,
                    "operation": "generate_key",
                    "namespace": namespace,
                    "version": version,
                    "size_bits": bits,
                    "size_bytes": key_bytes.len(),
                    "store": store
                })
            );
        } else {
            println!("Key generated successfully: {} bytes", key_bytes.len());
        }
    }
    Ok(())
}
