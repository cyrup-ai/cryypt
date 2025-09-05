# cryypt_jwt

JSON Web Token (JWT) creation and verification for the Cryypt cryptography suite.

## Installation

```toml
[dependencies]
cryypt_jwt = "0.1"
```

## API Examples

### JWT Creation and Verification

```rust
use cryypt::{Cryypt, on_result};

// Create and sign JWT
let claims = Claims {
    sub: "user123".to_string(),
    exp: 3600,
    custom: json!({"role": "admin"}),
};

let token = Cryypt::jwt()
    .with_algorithm("HS256")
    .with_secret(b"secret_key")
    .on_result(|result| {
        result.unwrap_or_else(|e| {
            log::error!("JWT operation failed: {}", e);
            String::new()
        })
    })
    .sign(claims)
    .await; // Returns fully unwrapped value - no Result wrapper

// Verify and decode JWT
let claims = Cryypt::jwt()
    .with_secret(b"secret_key")
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("JWT verification failed: {}", e);
            serde_json::Value::Null
        }
    })
    .verify(token)
    .await; // Returns fully unwrapped value - no Result wrapper

// RS256 with key pair
let token = Cryypt::jwt()
    .with_algorithm("RS256")
    .with_private_key(private_key)
    .on_result(|result| {
        result.unwrap_or_else(|e| {
            log::error!("JWT operation failed: {}", e);
            String::new()
        })
    })
    .sign(claims)
    .await; // Returns fully unwrapped value - no Result wrapper
```