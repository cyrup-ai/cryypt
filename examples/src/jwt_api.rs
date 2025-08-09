use cryypt::{Cryypt, BadChunk};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    let token: String = Cryypt::jwt()
        .with_algorithm("HS256")
        .with_secret(b"secret_key")
        .on_result(|result| {
            Ok(token) => token,
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
            Ok(claims) => claims,
            Err(e) => {
                log::error!("JWT verification failed: {}", e);
                serde_json::Value::Null
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
            Ok(token) => token,
            Err(e) => {
                log::error!("JWT operation failed: {}", e);
                String::new()
            }
        })
        .sign(claims)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Test streaming JWT operations with on_chunk
    println!("\nStreaming JWT signing with on_chunk:");
    let stream_claims = Claims {
        sub: "stream_user".to_string(),
        exp: 7200,
        custom: json!({"streaming": true}),
    };

    let mut token_stream = Cryypt::jwt()
        .with_algorithm("HS256")
        .with_secret(b"stream_secret")
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("JWT streaming error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .sign_stream(stream_claims);

    use futures::StreamExt;
    let mut token_chunks = Vec::new();
    while let Some(chunk) = token_stream.next().await {
        token_chunks.extend_from_slice(&chunk);
        println!("Token stream chunk received: {} bytes", chunk.len());
    }
    
    let stream_token = String::from_utf8_lossy(&token_chunks).to_string();
    println!("Stream-generated token length: {}", stream_token.len());

    // Test streaming JWT verification with on_chunk
    println!("\nStreaming JWT verification with on_chunk:");
    let mut verify_stream = Cryypt::jwt()
        .with_secret(b"stream_secret")
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("JWT verification stream error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .verify_stream(stream_token);

    let mut verify_chunks = Vec::new();
    while let Some(chunk) = verify_stream.next().await {
        verify_chunks.extend_from_slice(&chunk);
        println!("Verification stream chunk received: {} bytes", chunk.len());
    }
    
    let verified_data = String::from_utf8_lossy(&verify_chunks);
    println!("Stream-verified data: {}", verified_data);

    println!("\nJWT operations including streaming completed successfully");
    println!("HS256 Token length: {}", token.len());
    println!("Verified claims: {:?}", verified_claims);
    println!("RS256 Token length: {}", rs256_token.len());
    println!("Stream token length: {}", stream_token.len());

    Ok(())
}
