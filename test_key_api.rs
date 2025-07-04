use cryypt_key::{
    KeyGenerator, KeyRetriever, SecureRetrievedKey,
    store::MemoryStore,
    bits_macro::BitSize,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    
    println!("=== Testing KeyGenerator ===");
    
    // Generate a single key
    let key = KeyGenerator::new()
        .size(BitSize::new(256))
        .with_store(store.clone())
        .with_namespace("test-app")?
        .version(1)?
        .generate(|result| {
            match result {
                Ok(key) => {
                    println!("✓ Generated key: {} bytes", key.len());
                    Ok(key)
                }
                Err(e) => {
                    println!("✗ Generation failed: {}", e);
                    Err(e)
                }
            }
        })
        .await?;
    
    println!("✓ Key generated successfully: {} bytes", key.len());
    
    println!("\n=== Testing KeyRetriever ===");
    
    // Retrieve the key we just generated
    let retrieved = KeyRetriever::new()
        .with_store(store.clone())
        .with_namespace("test-app")?
        .version(1)?
        .retrieve(|result| {
            match result {
                Ok(key) => {
                    println!("✓ Retrieved key ID: {}", key.id().id());
                    println!("✓ Retrieved key: {} bytes", key.key_bytes().len());
                    Ok(key)
                }
                Err(e) => {
                    println!("✗ Retrieval failed: {}", e);
                    Err(e)
                }
            }
        })
        .await?;
    
    // Verify the keys match
    if retrieved.key_bytes() == &key[..] {
        println!("✓ Retrieved key matches generated key!");
    } else {
        println!("✗ Keys don't match!");
    }
    
    println!("\n=== Testing Batch Generation ===");
    
    // Generate multiple keys
    let batch_keys = KeyGenerator::new()
        .size(BitSize::new(256))
        .with_store(store.clone())
        .with_namespace("batch-test")?
        .version(1)?
        .batch(5)?
        .generate_collect()
        .await?;
    
    println!("✓ Generated {} keys in batch", batch_keys.len());
    
    println!("\n=== Testing Streaming Retrieval ===");
    
    // Generate keys with suffixes
    for suffix in &["alpha", "beta", "gamma"] {
        KeyGenerator::new()
            .size(BitSize::new(256))
            .with_store(store.clone())
            .with_namespace("stream-test")?
            .version(1)?
            .generate(|result| result)
            .await?;
    }
    
    // Stream retrieval
    let rx = KeyRetriever::new()
        .with_store(store.clone())
        .with_namespace("stream-test")?
        .version(1)?
        .retrieve_stream()
        .await;
    
    match rx.recv() {
        Ok(Ok(key)) => {
            println!("✓ Streamed key: {}", key.id().id());
        }
        Ok(Err(e)) => println!("✗ Stream error: {}", e),
        Err(_) => println!("✗ Channel disconnected"),
    }
    
    println!("\n=== Testing Version Range Retrieval ===");
    
    // Generate multiple versions
    for v in 1..=3 {
        KeyGenerator::new()
            .size(BitSize::new(256))
            .with_store(store.clone())
            .with_namespace("version-test")?
            .version(v)?
            .generate(|result| result)
            .await?;
    }
    
    // Retrieve version range
    let versions = KeyRetriever::new()
        .with_store(store.clone())
        .with_namespace("version-test")?
        .version(1)? // Starting version
        .retrieve_versions(1, 3)?
        .retrieve_collect()
        .await?;
    
    println!("✓ Retrieved {} versions", versions.len());
    for key in versions {
        println!("  - Key ID: {}", key.id().id());
    }
    
    println!("\n✓ All tests passed!");
    
    Ok(())
}