//! Key management operations for CLI commands

use crate::logging::log_security_event;
use cryypt_key::{api::KeyStore, store::FileKeyStore};
use serde_json::json;

pub async fn handle_generate_key(
    namespace: &str,
    version: u32,
    bits: u32,
    store: &str,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !use_json {
        println!(
            "Generating key with namespace '{}', version {}, {} bits...",
            namespace, version, bits
        );
    }

    // Generate the key using README.md pattern with on_result unwrapping
    let master_key = [0u8; 32]; // TODO: Get proper master key from context

    let key_bytes = if store.starts_with("file:") {
        let path = store.strip_prefix("file:").unwrap();
        let store = FileKeyStore::at(path).with_master_key(master_key);

        store
            .generate_key(bits, namespace, version)
            .on_result(|result| {
                match result {
                    Ok(key) => key,
                    Err(e) => {
                        log::error!("Key generation failed: {}", e);
                        Vec::new() // Return empty key on error
                    }
                }
            })
            .await
    } else {
        // Use temporary file store for "memory" option
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(".cryypt_temp_keys");
        let store = FileKeyStore::at(temp_path).with_master_key(master_key);

        store
            .generate_key(bits, namespace, version)
            .on_result(|result| {
                match result {
                    Ok(key) => key,
                    Err(e) => {
                        log::error!("Key generation failed: {}", e);
                        Vec::new() // Return empty key on error
                    }
                }
            })
            .await
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

pub async fn handle_retrieve_key(
    namespace: &str,
    version: u32,
    store: &str,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !use_json {
        println!(
            "Retrieving key with namespace '{}', version {}...",
            namespace, version
        );
    }

    // Retrieve the key using README.md pattern with on_result unwrapping
    let master_key = [0u8; 32]; // TODO: Get proper master key from context

    let key_bytes = if store.starts_with("file:") {
        let path = store.strip_prefix("file:").unwrap();
        let store = FileKeyStore::at(path).with_master_key(master_key);

        store
            .retrieve_key(namespace, version)
            .on_result(|result| {
                match result {
                    Ok(key) => key,
                    Err(e) => {
                        log::error!("Key retrieval failed: {}", e);
                        Vec::new() // Return empty key on error
                    }
                }
            })
            .await
    } else {
        // Use temporary file store for "memory" option
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(".cryypt_temp_keys");
        let store = FileKeyStore::at(temp_path).with_master_key(master_key);

        store
            .retrieve_key(namespace, version)
            .on_result(|result| {
                match result {
                    Ok(key) => key,
                    Err(e) => {
                        log::error!("Key retrieval failed: {}", e);
                        Vec::new() // Return empty key on error
                    }
                }
            })
            .await
    };

    // Key bytes are now fully unwrapped
    if key_bytes.is_empty() {
        let key_id = format!("{}:v{}", namespace, version);
        log_security_event(
            "CLI_RETRIEVE_KEY",
            &format!("Failed to retrieve key: {}", key_id),
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
            &format!("Retrieved key: {}", key_id),
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

pub async fn handle_batch_generate_keys(
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
    let master_key = [0u8; 32]; // TODO: Get proper master key from context

    let keys = if store.starts_with("file:") {
        let path = store.strip_prefix("file:").unwrap();
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
