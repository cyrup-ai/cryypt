use cryypt::{Bits, Cryypt, FileKeyStore, KeyRetriever, BadChunk};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup master key (in production, this should be securely generated)
    let master_key = [1u8; 32]; // 32 bytes for AES-256

    // Generate a NEW key (one-time setup)
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let generated_key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Key generation failed");
                    Vec::new() // Return empty key on error
                }
            }
        })
        .generate()
        .await; // Returns Key - the actual key object, fully unwrapped

    // Retrieve EXISTING key (normal usage)
    let retrieved_key = Cryypt::key()
        .retrieve()
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Key retrieval failed");
                    Vec::new() // Return empty key on error
                }
            }
        })
        .retrieve("my-app:v1:default")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Use generated key with cipher - README.md pattern: use Cryypt::cipher() not key.aes()
    let encrypted = Cryypt::cipher()
        .aes()
        .with_key(generated_key.clone())
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Operation failed");
                    Vec::new() // Return empty on error
                }
            }
        })
        .encrypt(b"Secret message")
        .await; // Returns Vec<u8> - the encrypted bytes, fully unwrapped

    // Use generated key with cipher for decryption - README.md pattern: use Cryypt::cipher() not key.aes()
    let plaintext: Vec<u8> = Cryypt::cipher()
        .aes()
        .with_key(generated_key.clone())
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Operation failed");
                    Vec::new() // Return empty on error
                }
            }
        })
        .decrypt(encrypted.clone())
        .await; // Returns Vec<u8> - the decrypted plaintext bytes, fully unwrapped

    // Or use ChaCha20 with retrieved key - README.md pattern: use Cryypt::cipher() not key.chacha20()
    let encrypted_chacha = Cryypt::cipher()
        .chacha20()
        .with_key(retrieved_key.clone())
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Operation failed");
                    Vec::new() // Return empty on error
                }
            }
        })
        .encrypt(b"Secret message")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Alternative: Direct builders are also available
    let key_alt = KeyRetriever::new()
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Key retrieval failed");
                    Vec::new() // Return empty key on error
                }
            }
        })
        .retrieve("my-app:v1:default")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Generate new key version
    let new_key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(2) // New version
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Key generation failed");
                    Vec::new() // Return empty key on error
                }
            }
        })
        .generate()
        .await; // Returns fully unwrapped value - no Result wrapper

    // Re-encrypt data with new key
    let old_key = Cryypt::key()
        .retrieve()
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1) // Old version
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Key generation failed");
                    Vec::new() // Return empty key on error
                }
            }
        })
        .retrieve("my-app:v1:old")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Decrypt with old key (using the encrypted data from earlier)
    let ciphertext = encrypted; // Use the encrypted data from earlier
    let plaintext_old = Cryypt::cipher()
        .aes()
        .with_key(old_key)
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Operation failed");
                    Vec::new() // Return empty on error
                }
            }
        })
        .decrypt(ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Re-encrypt with new key
    let new_ciphertext = Cryypt::cipher()
        .aes()
        .with_key(new_key)
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Operation failed");
                    Vec::new() // Return empty on error
                }
            }
        })
        .encrypt(plaintext_old)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Demonstrate alternative key retrieval API with key_alt
    let alt_encrypted = Cryypt::cipher()
        .aes()
        .with_key(key_alt.clone())
        .on_result(|result| {
            Ok(key) => key.into(),
                Err(_e) => {
                    log::error!("Alternative key encryption failed");
                    Vec::new() // Return empty on error
                }
            }
        })
        .encrypt(b"Message using alternative key retrieval API")
        .await; // Returns fully unwrapped value - no Result wrapper

    println!("Key management operations completed successfully");
    println!("Generated key length: {}", generated_key.len());
    println!("Retrieved key length: {}", retrieved_key.len());
    println!("Alternative retrieved key length: {}", key_alt.len());
    println!(
        "Original plaintext: {}",
        String::from_utf8_lossy(&plaintext)
    );
    println!("ChaCha20 encrypted length: {}", encrypted_chacha.len());
    println!("Re-encrypted data length: {}", new_ciphertext.len());
    println!("Alternative API encrypted length: {}", alt_encrypted.len());

    // Test streaming key generation with on_chunk
    println!("\nStreaming key generation with on_chunk:");
    let store_for_stream = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let mut key_stream = Cryypt::key()
        .size(256u32.bits())
        .with_store(store_for_stream)
        .with_namespace("streaming-app")
        .version(1)
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("Key generation stream error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .generate_stream();

    use futures::StreamExt;
    let mut key_chunks = Vec::new();
    while let Some(chunk) = key_stream.next().await {
        key_chunks.extend_from_slice(&chunk);
        println!("Key generation chunk received: {} bytes", chunk.len());
    }
    
    if !key_chunks.is_empty() {
        println!("Generated key from stream: {} bytes", key_chunks.len());
        
        // Test the generated key by encrypting some data
        let test_data = b"Testing stream-generated key";
        let stream_encrypted = Cryypt::cipher()
            .aes()
            .with_key(key_chunks)
            .on_result(|result| {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("Stream key encryption error: {}", e);
                    Vec::new()
                }
            })
            .encrypt(test_data)
            .await;
            
        println!("Stream key encryption successful: {} bytes", stream_encrypted.len());
    }

    Ok(())
}
