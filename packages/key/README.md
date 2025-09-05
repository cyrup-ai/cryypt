# cryypt_key

Key generation and management for the Cryypt cryptography suite.

## Installation

```toml
[dependencies]
cryypt_key = "0.1"
```

## API Examples

### Key Generation and Retrieval

```rust
use cryypt::{Cryypt, FileKeyStore, on_result, Bits};

// Generate a NEW key (one-time setup)
let store = FileKeyStore::at("/secure/keys").with_master_key(master_key);
let key = Cryypt::key()
    .generate()
    .size(256.bits())
    .with_store(store.clone())
    .with_namespace("my-app")
    .version(1)
    .on_result(|result| match result {
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
    .with_store(store)
    .with_namespace("my-app")
    .version(1)
    .on_result(|result| match result {
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
    .on_result(|result| match result {
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
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation failed: {}", e);
            Vec::new() // Return empty on error
        }
    })
    .decrypt(&encrypted)
    .await; // Returns Vec<u8> - the decrypted plaintext bytes, fully unwrapped

// Or use ChaCha20
let encrypted = key
    .chacha20()
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation failed: {}", e);
            Vec::new() // Return empty on error
        }
    })
    .encrypt(b"Secret message")
    .await; // Returns fully unwrapped value - no Result wrapper

// Alternative: Direct builders are also available
use cryypt::{KeyGenerator, KeyRetriever};
let key = KeyRetriever::new()
    .with_store(store)
    .with_namespace("my-app")
    .version(1)
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Key retrieval failed: {}", e);
            Vec::new() // Return empty key on error
        }
    })
    .retrieve()
    .await; // Returns fully unwrapped value - no Result wrapper
```

### Key Rotation

```rust
use cryypt::{Cryypt, on_result, Bits};

// Generate new key version
let new_key = Cryypt::key()
    .generate()
    .size(256.bits())
    .with_store(store)
    .with_namespace("my-app")
    .version(2) // New version
    .on_result(|result| match result {
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
    .with_store(store)
    .with_namespace("my-app")
    .version(1) // Old version
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Key generation failed: {}", e);
            Vec::new() // Return empty key on error
        }
    })
    .await; // Returns fully unwrapped value - no Result wrapper

// Decrypt with old key
let plaintext = Cryypt::cipher()
    .aes()
    .with_key(old_key)
    .on_result(|result| match result {
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
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation failed: {}", e);
            Vec::new() // Return empty on error
        }
    })
    .encrypt(plaintext)
    .await; // Returns fully unwrapped value - no Result wrapper
```