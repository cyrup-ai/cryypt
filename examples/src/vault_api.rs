//! Vault API Examples - Exactly matching README.md patterns
//! These examples demonstrate secure secret storage with fully unwrapped returns

use cryypt::{Cryypt, on_result, on_chunk};
use tokio_stream::StreamExt;

#[derive(Debug)]
enum VaultValue {
    Secret(String),
    Number(i64),
    Boolean(bool),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Example 1: Create and unlock vault
    let vault = example_create_vault().await?;
    
    // Example 2: Store and retrieve secrets
    example_store_secrets(&vault).await?;
    
    // Example 3: Stream all secrets
    example_stream_secrets(&vault).await?;
    
    // Example 4: Batch operations
    example_batch_operations(&vault).await?;
    
    // Example 5: Lock vault
    example_lock_vault(vault).await?;
    
    Ok(())
}

async fn example_create_vault() -> Result<Vault, Box<dyn std::error::Error>> {
    println!("\n=== Example 1: Create and Unlock Vault ===");
    
    // Create and unlock vault
    let vault = Cryypt::vault()
        .create("/tmp/my-vault")
        .with_passphrase("strong_passphrase")
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Key generation error: {}", e))
        })
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Vault created and unlocked at /tmp/my-vault");
    
    Ok(vault)
}

async fn example_store_secrets(vault: &Vault) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 2: Store and Retrieve Secrets ===");
    
    // Store secret
    vault
        .with_key("api_key")
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .set(VaultValue::Secret("sk-1234567890".to_string()))
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Stored API key");
    
    // Store with TTL
    vault
        .with_key("temp_token")
        .with_ttl(3600)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .set(VaultValue::Secret("tmp-abc123".to_string()))
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Stored temporary token with 1 hour TTL");
    
    // Retrieve secret
    let api_key = vault
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .get("api_key")
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Retrieved API key: {:?}", api_key);
    
    Ok(())
}

async fn example_stream_secrets(vault: &Vault) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 3: Stream All Secrets ===");
    
    // Stream all secrets
    let mut secret_stream = vault
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => {
                log::error!("Vault stream error: {}", e);
                return;
            }
        })
        .find(".*");
    
    // Collect all secrets
    let mut secrets = Vec::new();
    while let Some(secret) = secret_stream.next().await {
        println!("Found secret: {:?}", secret);
        secrets.push(secret);
    }
    
    println!("Total secrets found: {}", secrets.len());
    
    Ok(())
}

async fn example_batch_operations(vault: &Vault) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 4: Batch Operations ===");
    
    // Batch operations  
    vault
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .put_all(vec![
            ("db_host", VaultValue::Secret("localhost".to_string())),
            ("db_port", VaultValue::Number(5432)),
            ("db_ssl", VaultValue::Boolean(true)),
            ("db_user", VaultValue::Secret("admin".to_string())),
            ("api_key", VaultValue::Secret("sk-1234567890".to_string())),
        ])
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Batch stored 5 configuration values");
    
    Ok(())
}

async fn example_lock_vault(vault: Vault) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 5: Lock Vault ===");
    
    // Lock vault
    vault
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .lock()
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Vault locked successfully");
    
    Ok(())
}

// Placeholder Vault struct for the example
#[derive(Debug)]
struct Vault {
    path: String,
}

impl Vault {
    fn with_key(&self, _key: &str) -> &Self { self }
    fn with_ttl(&self, _ttl: u64) -> &Self { self }
    async fn set(&self, _value: VaultValue) {}
    async fn get(&self, _key: &str) -> VaultValue { VaultValue::Secret("example".to_string()) }
    fn find(&self, _pattern: &str) -> impl Stream<Item = (String, VaultValue)> {
        tokio_stream::iter(vec![
            ("key1".to_string(), VaultValue::Secret("value1".to_string())),
            ("key2".to_string(), VaultValue::Number(42)),
        ])
    }
    async fn put_all(&self, _items: Vec<(&str, VaultValue)>) {}
    async fn lock(self) {}
}