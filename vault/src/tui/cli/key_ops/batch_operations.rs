//! Batch key operations for CLI commands

use super::master_key::derive_master_key_from_vault;
use crate::core::Vault;
use crate::logging::log_security_event;
use cryypt_key::{api::KeyStore, store::FileKeyStore};
use serde_json::json;

pub async fn handle_batch_generate_keys(
    vault: &Vault,
    namespace: &str,
    version: u32,
    bits: u32,
    count: usize,
    store: &str,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !use_json {
        println!(
            "Generating {} keys with namespace '{}', version {}, {} bits...",
            count, namespace, version, bits
        );
    }

    // Generate keys in batch using README.md pattern with on_result unwrapping
    let master_key = derive_master_key_from_vault(vault)
        .await
        .map_err(|e| format!("Failed to derive master key: {}", e))?;

    let keys = if store.starts_with("file:") {
        let path = store
            .strip_prefix("file:")
            .ok_or("Invalid file store path format")?;
        let store = FileKeyStore::at(path).with_master_key(master_key);

        let mut keys = Vec::new();
        for i in 0..count {
            let key = store
                .generate_key(bits, namespace, version + i as u32)
                .on_result(|result| {
                    match result {
                        Ok(key) => key,
                        Err(e) => {
                            log::error!("Batch key generation failed for index {}: {}", i, e);
                            Vec::new() // Skip failed key
                        }
                    }
                })
                .await;
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
        for i in 0..count {
            let key = store
                .generate_key(bits, namespace, version + i as u32)
                .on_result(|result| {
                    match result {
                        Ok(key) => key,
                        Err(e) => {
                            log::error!("Batch key generation failed for index {}: {}", i, e);
                            Vec::new() // Skip failed key
                        }
                    }
                })
                .await;
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
            &format!("Failed to generate any keys for {}:v{}", namespace, version),
            false,
        );

        if use_json {
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
                namespace,
                version
            ),
            true,
        );

        if use_json {
            println!(
                "{}",
                json!({
                    "success": true,
                    "operation": "batch_generate_keys",
                    "namespace": namespace,
                    "version": version,
                    "size_bits": bits,
                    "count": keys.len(),
                    "total_bytes": keys.iter().map(|k| k.len()).sum::<usize>(),
                    "store": store
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
