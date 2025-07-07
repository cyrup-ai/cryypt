use cryypt::{Cryypt, FileKeyStore, on_result, Bits, KeyGenerator, KeyRetriever};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup master key (in production, this should be securely generated)
    let master_key = [1u8; 32]; // 32 bytes for AES-256
    
    // Generate a NEW key (one-time setup)
    let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
    let key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Key generation failed: {}", e);
                Vec::new() // Return empty key on error
            }
        })
        .await; // Returns Key - the actual key object, fully unwrapped

    // Retrieve EXISTING key (normal usage)
    let key = Cryypt::key()
        .retrieve()
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1)
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Key generation failed: {}", e);
                Vec::new() // Return empty key on error
            }
        })
        .await; // Returns fully unwrapped value - no Result wrapper

    // Use key directly for encryption
    let encrypted = key
        .aes()
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Operation failed: {}", e);
                Vec::new() // Return empty on error
            }
        })
        .encrypt(b"Secret message")
        .await; // Returns Vec<u8> - the encrypted bytes, fully unwrapped

    // Use key directly for decryption
    let plaintext = key
        .aes()
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Operation failed: {}", e);
                Vec::new() // Return empty on error
            }
        })
        .decrypt(&encrypted)
        .await; // Returns Vec<u8> - the decrypted plaintext bytes, fully unwrapped

    // Or use ChaCha20
    let encrypted_chacha = key
        .chacha20()
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Operation failed: {}", e);
                Vec::new() // Return empty on error
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
            Ok => result,
            Err(e) => {
                log::error!("Key retrieval failed: {}", e);
                Vec::new() // Return empty key on error
            }
        })
        .retrieve()
        .await; // Returns fully unwrapped value - no Result wrapper

    // Generate new key version
    let new_key = Cryypt::key()
        .generate()
        .size(256.bits())
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(2) // New version
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Key generation failed: {}", e);
                Vec::new() // Return empty key on error
            }
        })
        .await; // Returns fully unwrapped value - no Result wrapper

    // Re-encrypt data with new key
    let old_key = Cryypt::key()
        .retrieve()
        .with_store(store.clone())
        .with_namespace("my-app")
        .version(1) // Old version
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Key generation failed: {}", e);
                Vec::new() // Return empty key on error
            }
        })
        .await; // Returns fully unwrapped value - no Result wrapper

    // Decrypt with old key (using the encrypted data from earlier)
    let ciphertext = encrypted; // Use the encrypted data from earlier
    let plaintext_old = Cryypt::cipher()
        .aes()
        .with_key(old_key)
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Operation failed: {}", e);
                Vec::new() // Return empty on error
            }
        })
        .decrypt(ciphertext)
        .await; // Returns fully unwrapped value - no Result wrapper

    // Re-encrypt with new key
    let new_ciphertext = Cryypt::cipher()
        .aes()
        .with_key(new_key)
        .on_result(|result| {
            Ok => result,
            Err(e) => {
                log::error!("Operation failed: {}", e);
                Vec::new() // Return empty on error
            }
        })
        .encrypt(plaintext_old)
        .await; // Returns fully unwrapped value - no Result wrapper
    
    println!("Key management operations completed successfully");
    println!("Original plaintext: {}", String::from_utf8_lossy(&plaintext));
    println!("ChaCha20 encrypted length: {}", encrypted_chacha.len());
    println!("Re-encrypted data length: {}", new_ciphertext.len());
    
    Ok(())
}