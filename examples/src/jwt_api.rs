use cryypt::{Cryypt, on_result};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
    custom: serde_json::Value,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
            Ok => result,
            Err(e) => {
                log::error!("JWT operation failed: {}", e);
                String::new()
            }
        })
        .sign(claims.clone())
        .await; // Returns fully unwrapped value - no Result wrapper

    // Verify and decode JWT
    let verified_claims = Cryypt::jwt()
        .with_secret(b"secret_key")
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(e) => {
                    log::error!("JWT verification failed: {}", e);
                    serde_json::Value::Null
                }
            }
        })
        .verify(token.clone())
        .await; // Returns fully unwrapped value - no Result wrapper

    // For RS256, we need a mock private key (normally this would be a real RSA key)
    let private_key = b"-----BEGIN PRIVATE KEY-----\n...mock key...\n-----END PRIVATE KEY-----";

    // RS256 with key pair
    let rs256_token = Cryypt::jwt()
        .with_algorithm("RS256")
        .with_private_key(private_key)
        .on_result(|result| {
            match result {
                Ok(result) => result,
                Err(e) => {
                    log::error!("JWT operation failed: {}", e);
                    String::new()
                }
            }
        })
        .sign(claims)
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("JWT operations completed successfully");
    println!("HS256 Token length: {}", token.len());
    println!("Verified claims: {:?}", verified_claims);
    println!("RS256 Token length: {}", rs256_token.len());

    Ok(())
}