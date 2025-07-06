//! Test file to verify README.md patterns compile and work

use cryypt::{Cryypt, FileKeyStore, Bits};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test key generation pattern from README.md
    let master_key = [1u8; 32];
    let store = FileKeyStore::at("/tmp/test_keys").with_master_key(master_key);
    
    // Generate a NEW key (one-time setup)
    let key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Error: {}", e);
                    vec![]
                }
            }
        })
        .await?;

    // Test encryption pattern from README.md
    let encrypted = key
        .aes()
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Error: {}", e);
                    vec![]
                }
            }
        })
        .encrypt(b"Secret message")
        .await?;

    println!("Encryption successful! Ciphertext length: {}", encrypted.len());

    // Test decryption pattern from README.md
    let plaintext = key
        .aes()
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Error: {}", e);
                    vec![]
                }
            }
        })
        .decrypt(&encrypted)
        .await?;

    println!("Decryption successful! Plaintext: {:?}", String::from_utf8_lossy(&plaintext));

    // Test key retrieval pattern from README.md
    let retrieved_key = Cryypt::key()
        .retrieve()
        .with_store(store)
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Error: {}", e);
                    vec![]
                }
            }
        })
        .await?;

    // Test ChaCha20 pattern from README.md
    let chacha_encrypted = retrieved_key
        .chacha20()
        .on_result(|result| {
            match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("Error: {}", e);
                    vec![]
                }
            }
        })
        .encrypt(b"Secret message")
        .await?;

    println!("ChaCha20 encryption successful! Ciphertext length: {}", chacha_encrypted.len());

    Ok(())
}