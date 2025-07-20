use cryypt::{Cryypt, on_result};
use serde_json::json;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Cryypt Vault API Examples");
    
    // Create and unlock vault
    let vault = Cryypt::vault()
        .create("./my-vault")
        .with_passphrase("strong_passphrase")
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Vault creation error: {}", e);
                panic!("Failed to create vault")
            }
        })
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("✅ Vault created and unlocked");

    // Store different types of secrets
    vault
        .with_key("api_key")
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("API key storage error: {}", e);
                ()
            }
        })
        .set("sk-1234567890")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("✅ API key stored");

    // Store with TTL (Time To Live)
    vault
        .with_key("temp_token")
        .with_ttl(3600) // Expires in 1 hour
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Temp token storage error: {}", e);
                ()
            }
        })
        .set("tmp-abc123")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("✅ Temporary token stored with TTL");

    // Store structured data
    let database_config = json!({
        "host": "localhost",
        "port": 5432,
        "database": "myapp",
        "ssl": true
    });

    vault
        .with_key("db_config")
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Database config storage error: {}", e);
                ()
            }
        })
        .set(database_config.to_string())
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("✅ Database config stored");

    // Retrieve secrets
    let api_key = vault
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("API key retrieval error: {}", e);
                String::new()
            }
        })
        .get("api_key")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Retrieved API key: {}", if api_key.is_empty() { "❌ Failed" } else { "✅ Success" });

    let db_config = vault
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("DB config retrieval error: {}", e);
                String::new()
            }
        })
        .get("db_config")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Retrieved DB config: {}", if db_config.is_empty() { "❌ Failed" } else { "✅ Success" });

    // Batch operations - store multiple values at once
    let mut batch_data = HashMap::new();
    batch_data.insert("db_host".to_string(), "localhost".to_string());
    batch_data.insert("db_port".to_string(), "5432".to_string());
    batch_data.insert("db_ssl".to_string(), "true".to_string());
    batch_data.insert("db_user".to_string(), "admin".to_string());

    vault
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Batch storage error: {}", e);
                ()
            }
        })
        .put_all(batch_data)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("✅ Batch data stored");

    // List all stored keys
    let keys = vault
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Key listing error: {}", e);
                Vec::new()
            }
        })
        .list_keys()
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Stored keys: {:?}", keys);

    // Search for secrets with pattern
    let search_results = vault
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Search error: {}", e);
                Vec::new()
            }
        })
        .find("db_.*") // Find all keys starting with "db_"
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Database-related keys found: {}", search_results.len());

    // Update a secret
    vault
        .with_key("api_key")
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("API key update error: {}", e);
                ()
            }
        })
        .set("sk-new-updated-key-9876543210")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("✅ API key updated");

    // Delete a secret
    vault
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Deletion error: {}", e);
                ()
            }
        })
        .delete("temp_token")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("✅ Temporary token deleted");

    // Change vault passphrase
    vault
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Passphrase change error: {}", e);
                ()
            }
        })
        .change_passphrase("even_stronger_passphrase")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("✅ Vault passphrase changed");

    // Lock vault (optional - vault auto-locks when dropped)
    vault
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(e) => {
                    log::error!("Vault lock error: {}", e);
                    ()
                }
            }
        })
        .lock()
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("✅ Vault locked");

    println!("\n🎉 Vault operations completed successfully!");

    Ok(())
}