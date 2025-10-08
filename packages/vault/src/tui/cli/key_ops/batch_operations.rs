//! Batch key operations for CLI commands

use super::master_key::derive_master_key_from_vault;
use crate::core::Vault;
use crate::logging::log_security_event;
use cryypt_key::{api::KeyStore, store::FileKeyStore};
use serde_json::json;

/// Configuration for batch key generation operations
pub struct BatchKeyConfig<'a> {
    pub namespace: &'a str,
    pub version: u32,
    pub bits: u32,
    pub count: usize,
    pub store: &'a str,
    pub passphrase_option: Option<&'a str>,
    pub use_json: bool,
}

pub async fn handle_batch_generate_keys(
    vault: &Vault,
    config: BatchKeyConfig<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !config.use_json {
        println!(
            "Generating {} keys with namespace '{}', version {}, {} bits...",
            config.count, config.namespace, config.version, config.bits
        );
    }

    // Generate keys in batch using README.md pattern with on_result unwrapping
    let master_key = derive_master_key_from_vault(vault, config.passphrase_option)
        .await
        .map_err(|e| format!("Failed to derive master key: {e}"))?;

    let keys = if config.store.starts_with("file:") {
        let path = config
            .store
            .strip_prefix("file:")
            .ok_or("Invalid file store path format")?;
        let store = FileKeyStore::at(path).with_master_key(master_key);

        let mut keys = Vec::new();
        for i in 0..config.count {
            let key = match store
                .generate_key(config.bits, config.namespace, config.version + i as u32)
                .await
            {
                Ok(key_bytes) => {
                    log::info!("Batch key generation succeeded for index {}", i);
                    key_bytes
                }
                Err(e) => {
                    log::error!("Batch key generation failed for index {}: {}", i, e);
                    log_security_event(
                        "BATCH_KEY_GENERATION_FAILED",
                        &format!("Index {i}: {e}"),
                        false,
                    );
                    Vec::new()
                }
            };
            if !key.is_empty() {
                keys.push(key);
            }
        }
        keys
    } else {
        // Use temporary file store for "memory" option
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(".cryypt_temp_keys");
        let store = FileKeyStore::at(temp_path).with_master_key(master_key);

        let mut keys = Vec::new();
        for i in 0..config.count {
            let key = match store
                .generate_key(config.bits, config.namespace, config.version + i as u32)
                .await
            {
                Ok(key_bytes) => {
                    log::info!("Batch key generation succeeded for index {}", i);
                    key_bytes
                }
                Err(e) => {
                    log::error!("Batch key generation failed for index {}: {}", i, e);
                    log_security_event(
                        "BATCH_KEY_GENERATION_FAILED",
                        &format!("Index {i}: {e}"),
                        false,
                    );
                    Vec::new()
                }
            };
            if !key.is_empty() {
                keys.push(key);
            }
        }
        keys
    };

    // Keys are now fully unwrapped
    if keys.is_empty() {
        log_security_event(
            "CLI_BATCH_GENERATE",
            &format!(
                "Failed to generate any keys for {}:v{}",
                config.namespace, config.version
            ),
            false,
        );

        if config.use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "batch_generate_keys",
                    "error": "No keys could be generated"
                })
            );
        } else {
            println!("Batch generation failed: no keys could be generated");
        }
    } else {
        log_security_event(
            "CLI_BATCH_GENERATE",
            &format!(
                "Generated {} keys for {}:v{}",
                keys.len(),
                config.namespace,
                config.version
            ),
            true,
        );

        if config.use_json {
            println!(
                "{}",
                json!({
                    "success": true,
                    "operation": "batch_generate_keys",
                    "namespace": config.namespace,
                    "version": config.version,
                    "size_bits": config.bits,
                    "count": keys.len(),
                    "total_bytes": keys.iter().map(|k| k.len()).sum::<usize>(),
                    "store": config.store
                })
            );
        } else {
            println!("Batch generation successful:");
            println!("  Keys generated: {}", keys.len());
            println!(
                "  Key size: {} bytes each",
                keys.first().map_or(0, |k| k.len())
            );
            println!(
                "  Total bytes: {}",
                keys.iter().map(|k| k.len()).sum::<usize>()
            );
        }
    }
    Ok(())
}
