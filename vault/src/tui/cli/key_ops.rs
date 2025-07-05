//! Key management operations for CLI commands

use crate::logging::log_security_event;
use serde_json::json;
use cryypt_key::{
    KeyGenerator, KeyRetriever,
    api::SecureRetrievedKey,
    store::FileKeyStore,
    bits_macro::{BitSize, Bits},
};

pub async fn handle_generate_key(
    namespace: &str,
    version: u32,
    bits: u32,
    store: &str,
    use_json: bool
) -> Result<(), Box<dyn std::error::Error>> {
    if !use_json {
        println!("Generating key with namespace '{}', version {}, {} bits...", namespace, version, bits);
    }
    
    // Parse store type
    let store_backend: Box<dyn cryypt_key::traits::KeyStorage + Send + Sync> = if store.starts_with("file:") {
        let path = store.strip_prefix("file:").unwrap();
        Box::new(FileKeyStore::at(path))
    } else {
        // Use temporary file store for "memory" option
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(".cryypt_temp_keys");
        Box::new(FileKeyStore::at(temp_path))
    };
    
    // Generate the key
    match KeyGenerator::new()
        .size(bits.bits())
        .with_store(store_backend)
        .with_namespace(namespace)
        .and_then(|g| g.version(version))
    {
        Ok(generator) => {
            match generator.generate(|result| result).await {
                Ok(key_bytes) => {
                    log_security_event("CLI_GENERATE_KEY", &format!("Generated key: {}:v{}", namespace, version), true);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": true,
                            "operation": "generate_key",
                            "namespace": namespace,
                            "version": version,
                            "size_bits": bits,
                            "size_bytes": key_bytes.len(),
                            "store": store
                        }));
                    } else {
                        println!("Key generated successfully: {} bytes", key_bytes.len());
                    }
                }
                Err(e) => {
                    log_security_event("CLI_GENERATE_KEY", &format!("Failed to generate key: {}", e), false);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "generate_key",
                            "error": format!("Failed to generate key: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        }
        Err(e) => {
            log_security_event("CLI_GENERATE_KEY", &format!("Invalid key generation parameters: {}", e), false);
            
            if use_json {
                println!("{}", json!({
                    "success": false,
                    "operation": "generate_key",
                    "error": format!("Invalid parameters: {}", e)
                }));
                return Ok(());
            } else {
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}

pub async fn handle_retrieve_key(
    namespace: &str,
    version: u32,
    store: &str,
    use_json: bool
) -> Result<(), Box<dyn std::error::Error>> {
    if !use_json {
        println!("Retrieving key with namespace '{}', version {}...", namespace, version);
    }
    
    // Parse store type
    let store_backend: Box<dyn cryypt_key::traits::KeyStorage + cryypt_key::traits::KeyRetrieval + Send + Sync> = if store.starts_with("file:") {
        let path = store.strip_prefix("file:").unwrap();
        Box::new(FileKeyStore::at(path))
    } else {
        // Use temporary file store for "memory" option
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(".cryypt_temp_keys");
        Box::new(FileKeyStore::at(temp_path))
    };
    
    // Retrieve the key
    match KeyRetriever::new()
        .with_store(store_backend)
        .with_namespace(namespace)
        .and_then(|ret| ret.version(version))
    {
        Ok(retriever) => {
            match retriever.retrieve(|result| result).await {
                Ok(secure_key) => {
                    log_security_event("CLI_RETRIEVE_KEY", &format!("Retrieved key: {}", secure_key.id().id()), true);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": true,
                            "operation": "retrieve_key",
                            "key_id": secure_key.id().id(),
                            "size_bytes": secure_key.key_bytes().len(),
                            "store": store
                        }));
                    } else {
                        println!("Key retrieved successfully:");
                        println!("  ID: {}", secure_key.id().id());
                        println!("  Size: {} bytes", secure_key.key_bytes().len());
                    }
                }
                Err(e) => {
                    log_security_event("CLI_RETRIEVE_KEY", &format!("Failed to retrieve key: {}", e), false);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "retrieve_key",
                            "error": format!("Failed to retrieve key: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        }
        Err(e) => {
            log_security_event("CLI_RETRIEVE_KEY", &format!("Invalid key retrieval parameters: {}", e), false);
            
            if use_json {
                println!("{}", json!({
                    "success": false,
                    "operation": "retrieve_key",
                    "error": format!("Invalid parameters: {}", e)
                }));
                return Ok(());
            } else {
                return Err(Box::new(e));
            }
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
    use_json: bool
) -> Result<(), Box<dyn std::error::Error>> {
    if !use_json {
        println!("Generating {} keys with namespace '{}', version {}, {} bits...", count, namespace, version, bits);
    }
    
    // Parse store type
    let store_backend: Box<dyn cryypt_key::traits::KeyStorage + cryypt_key::traits::KeyImport + Send + Sync> = if store.starts_with("file:") {
        let path = store.strip_prefix("file:").unwrap();
        Box::new(FileKeyStore::at(path))
    } else {
        // Use temporary file store for "memory" option
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(".cryypt_temp_keys");
        Box::new(FileKeyStore::at(temp_path))
    };
    
    // Generate keys in batch
    match KeyGenerator::new()
        .size(bits.bits())
        .with_store(store_backend)
        .with_namespace(namespace)
        .and_then(|g| g.version(version))
        .and_then(|g| g.batch(count))
    {
        Ok(batch_gen) => {
            match batch_gen.generate_collect().await {
                Ok(keys) => {
                    log_security_event("CLI_BATCH_GENERATE", &format!("Generated {} keys for {}:v{}", keys.len(), namespace, version), true);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": true,
                            "operation": "batch_generate_keys",
                            "namespace": namespace,
                            "version": version,
                            "size_bits": bits,
                            "count": keys.len(),
                            "total_bytes": keys.iter().map(|k| k.len()).sum::<usize>(),
                            "store": store
                        }));
                    } else {
                        println!("Batch generation successful:");
                        println!("  Keys generated: {}", keys.len());
                        println!("  Key size: {} bytes each", keys.first().map_or(0, |k| k.len()));
                        println!("  Total bytes: {}", keys.iter().map(|k| k.len()).sum::<usize>());
                    }
                }
                Err(e) => {
                    log_security_event("CLI_BATCH_GENERATE", &format!("Failed to generate batch: {}", e), false);
                    
                    if use_json {
                        println!("{}", json!({
                            "success": false,
                            "operation": "batch_generate_keys",
                            "error": format!("Failed to generate batch: {}", e)
                        }));
                        return Ok(());
                    } else {
                        return Err(Box::new(e));
                    }
                }
            }
        }
        Err(e) => {
            log_security_event("CLI_BATCH_GENERATE", &format!("Invalid batch generation parameters: {}", e), false);
            
            if use_json {
                println!("{}", json!({
                    "success": false,
                    "operation": "batch_generate_keys",
                    "error": format!("Invalid parameters: {}", e)
                }));
                return Ok(());
            } else {
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}