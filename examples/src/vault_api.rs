//! Vault API examples - EXACTLY matching vault/README.md

use cryypt::{Cryypt, VaultValue};

/// Vault Operations example from README
async fn vault_operations() -> Result<(), Box<dyn std::error::Error>> {
    let passphrase = "strong_passphrase";
    
    // Create and unlock vault
    let vault = Cryypt::vault()
        .create("./my-vault")
        .with_passphrase(passphrase)
        .on_result(|result| {
            match result {
                Ok(vault) => vault,
                Err(e) => {
                    log::error!("Key generation error: {}", e);
                    panic!("Failed to create vault")
                }
            }
        })
        .await; // Returns fully unwrapped value - no Result wrapper

    // Store secret
    vault
        .with_key("api_key")
        .on_result(|result| {
            match result {
                Ok(value) => value,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    ()
                }
            }
        })
        .set(VaultValue::Secret("sk-1234567890"))
        .await; // Returns fully unwrapped value - no Result wrapper

    // Store with TTL
    vault
        .with_key("temp_token")
        .with_ttl(3600)
        .on_result(|result| {
            match result {
                Ok(value) => value,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    ()
                }
            }
        })
        .set(VaultValue::Secret("tmp-abc123"))
        .await; // Returns fully unwrapped value - no Result wrapper

    // Retrieve secret
    let api_key = vault
        .on_result(|result| {
            match result {
                Ok(value) => value,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    ()
                }
            }
        })
        .get("api_key")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Retrieved API key: {:?}", api_key);

    // Stream all secrets
    let mut secret_stream = vault
        .on_chunk(|chunk| {
            match chunk {
                Ok(data) => Some(data),
                Err(e) => {
                    log::error!("Vault stream error: {}", e);
                    None
                }
            }
        })
        .find(".*");

    // Collect all secrets
    let mut secrets = Vec::new();
    while let Some(secret) = secret_stream.next().await {
        secrets.push(secret);
    }
    println!("Found {} secrets", secrets.len());

    // Batch operations  
    vault
        .on_result(|result| {
            match result {
                Ok(value) => value,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    ()
                }
            }
        })
        .put_all({
            "db_host" => "localhost",
            "db_port" => 5432,
            "db_ssl" => true,
            "db_user" => "admin",
            "api_key" => "sk-1234567890",
        })
        .await; // Returns fully unwrapped value - no Result wrapper

    // Lock vault
    vault
        .on_result(|result| {
            match result {
                Ok(value) => value,
                Err(e) => {
                    log::error!("Operation error: {}", e);
                    ()
                }
            }
        })
        .lock()
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Vault locked successfully");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Vault Operations ===");
    vault_operations().await?;
    
    Ok(())
}