# cryypt_pqcrypto

Post-quantum cryptography algorithms (Kyber, Dilithium, Falcon, SPHINCS+) for the Cryypt cryptography suite.

## Installation

```toml
[dependencies]
cryypt_pqcrypto = "0.1"
```

## API Examples

### Kyber Key Exchange

```rust
use cryypt::{Cryypt, on_result};

// Kyber key exchange
let (public_key, secret_key) = Cryypt::pqcrypto()
    .kyber()
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            panic!("PQ crypto operation failed")
        }
    })
    .generate_keypair()
    .await; // Returns fully unwrapped value - no Result wrapper

// Encapsulate shared secret
let (ciphertext, shared_secret) = Cryypt::pqcrypto()
    .kyber()
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            panic!("PQ crypto operation failed")
        }
    })
    .encapsulate(public_key)
    .await; // Returns fully unwrapped value - no Result wrapper

// Decapsulate shared secret
let shared_secret = Cryypt::pqcrypto()
    .kyber()
    .with_secret_key(secret_key)
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            panic!("PQ crypto operation failed")
        }
    })
    .decapsulate(ciphertext)
    .await; // Returns fully unwrapped value - no Result wrapper
```

### Dilithium Signatures

```rust
// Dilithium signatures
let (public_key, secret_key) = Cryypt::pqcrypto()
    .dilithium()
    .with_security_level(3)
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            panic!("PQ crypto operation failed")
        }
    })
    .generate_keypair()
    .await; // Returns fully unwrapped value - no Result wrapper

let signature = Cryypt::pqcrypto()
    .dilithium()
    .with_secret_key(secret_key)
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            panic!("PQ crypto operation failed")
        }
    })
    .sign(message)
    .await; // Returns fully unwrapped value - no Result wrapper

let valid = Cryypt::pqcrypto()
    .dilithium()
    .with_public_key(public_key)
    .with_signature(signature)
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            panic!("PQ crypto operation failed")
        }
    })
    .verify(message)
    .await; // Returns fully unwrapped value - no Result wrapper
```

### Secure Multi-party Communication

```rust
use cryypt::{Cryypt, on_result};

// Alice generates keypair
let (alice_public, alice_secret) = Cryypt::pqcrypto()
    .kyber()
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            panic!("PQ crypto operation failed")
        }
    })
    .generate_keypair()
    .await; // Returns fully unwrapped value - no Result wrapper

// Bob encapsulates shared secret
let (ciphertext, bob_shared_secret) = Cryypt::pqcrypto()
    .kyber()
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            panic!("PQ crypto operation failed")
        }
    })
    .encapsulate(alice_public)
    .await; // Returns fully unwrapped value - no Result wrapper

// Alice decapsulates to get same shared secret
let alice_shared_secret = Cryypt::pqcrypto()
    .kyber()
    .with_secret_key(alice_secret)
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            panic!("PQ crypto operation failed")
        }
    })
    .decapsulate(ciphertext)
    .await; // Returns fully unwrapped value - no Result wrapper

// Now both can use shared secret for symmetric encryption
let encrypted = Cryypt::cipher()
    .aes()
    .with_key(bob_shared_secret)
    .on_result(|result| match result {
        Ok => result,
        Err(e) => {
            log::error!("Operation error: {}", e);
            panic!("PQ crypto operation failed")
        }
    })
    .encrypt(b"Secret message")
    .await; // Returns fully unwrapped value - no Result wrapper
```