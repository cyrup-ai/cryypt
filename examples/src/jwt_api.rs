//! JWT API Examples - Exactly matching README.md patterns
//! These examples demonstrate JWT signing and verification with fully unwrapped returns

use cryypt::{Cryypt, on_result};
use serde_json::json;

#[derive(Debug, Clone)]
struct Claims {
    sub: String,
    exp: u64,
    custom: serde_json::Value,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    // Example 1: Create and sign JWT with HS256
    example_jwt_hs256().await?;
    
    // Example 2: RS256 with key pair
    example_jwt_rs256().await?;
    
    Ok(())
}

async fn example_jwt_hs256() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 1: JWT with HS256 ===");
    
    // Create claims
    let claims = Claims {
        sub: "user123".to_string(),
        exp: 3600,
        custom: json!({"role": "admin"}),
    };
    
    // Create and sign JWT
    let token = Cryypt::jwt()
        .with_algorithm("HS256")
        .with_secret(b"secret_key")
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .sign(claims.clone())
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("JWT token created: {}", &token[..50]);
    
    // Verify and decode JWT
    let verified_claims = Cryypt::jwt()
        .with_secret(b"secret_key")
        .on_result!(|result| {
            Ok => Ok(result),
            Err(e) => {
                log::error!("JWT verification failed: {}", e);
                Err(e)
            }
        })
        .verify(token)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("JWT verified successfully");
    println!("Claims: {:?}", verified_claims);
    
    Ok(())
}

async fn example_jwt_rs256() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Example 2: JWT with RS256 ===");
    
    // In a real app, load these from files or secure storage
    let private_key = b"-----BEGIN PRIVATE KEY-----
...private key content...
-----END PRIVATE KEY-----";
    
    let public_key = b"-----BEGIN PUBLIC KEY-----
...public key content...
-----END PUBLIC KEY-----";
    
    // Create claims
    let claims = Claims {
        sub: "user456".to_string(),
        exp: 7200,
        custom: json!({"role": "user", "permissions": ["read", "write"]}),
    };
    
    // RS256 with key pair
    let token = Cryypt::jwt()
        .with_algorithm("RS256")
        .with_private_key(private_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .sign(claims)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("RS256 JWT token created: {}", &token[..50]);
    
    // Verify with public key
    let verified_claims = Cryypt::jwt()
        .with_algorithm("RS256")
        .with_public_key(public_key)
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Verification error: {}", e))
        })
        .verify(token)
        .await;
    
    println!("RS256 JWT verified successfully");
    println!("Claims: {:?}", verified_claims);
    
    Ok(())
}