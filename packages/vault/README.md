# cryypt_vault

Secure encrypted storage vault for the Cryypt cryptography suite.

## Installation

```toml
[dependencies]
cryypt_vault = "0.1"
```

## API Examples

### Vault Operations

```rust
use cryypt::{Cryypt, on_result};

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

// Store secret
vault
    .with_key("api_key")
    .on_result(|result| {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            ()
        }
    })
    .set(VaultValue::Secret("sk-1234567890"))
    .await; // Returns fully unwrapped value - no Result wrapper

// Store with TTL
vault
    .with_key("temp_token")
    .with_ttl(3600)
    .on_result(|result| {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            ()
        }
    })
    .set(VaultValue::Secret("tmp-abc123"))
    .await; // Returns fully unwrapped value - no Result wrapper

// Retrieve secret
let api_key = vault
    .on_result(|result| {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            ()
        }
    })
    .get("api_key")
    .await; // Returns fully unwrapped value - no Result wrapper

// Stream all secrets
let mut secret_stream = vault
    .on_chunk(|chunk| {
        Ok => chunk.into(),
        Err(e) => {
            log::error!("Vault stream error: {}", e);
            BadChunk::from_error(e)
        }
    })
    .find(".*");

// Collect all secrets
let mut secrets = Vec::new();
while let Some(secret) = secret_stream.next().await {
    secrets.push(secret);
}

// Batch operations  
vault
    .on_result(|result| {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            ()
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
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            ()
        }
    })
    .lock()
    .await; // Returns fully unwrapped value - no Result wrapper
```