# Post-Quantum Cryptography (PQCrypto) Module

**NIST FIPS 204/203 Compliant Post-Quantum Cryptography Implementation**

The `pqcrypto` module provides production-ready implementations of NIST-standardized post-quantum cryptographic algorithms, designed to be secure against both classical and quantum computer attacks.

## 🛡️ Security Notice

This module implements **NIST FIPS 204** (ML-DSA) and **NIST FIPS 203** (ML-KEM) standards using battle-tested cryptographic libraries. All algorithms are quantum-resistant and suitable for protecting data against future quantum computer threats.

## 📚 Table of Contents

- [Quick Start](#quick-start)
- [Supported Algorithms](#supported-algorithms)
- [Key Encapsulation Mechanisms (KEM)](#key-encapsulation-mechanisms-kem)
- [Digital Signatures](#digital-signatures)
- [Hybrid Encryption Patterns](#hybrid-encryption-patterns)
- [Key Management](#key-management)
- [Error Handling](#error-handling)
- [Performance Considerations](#performance-considerations)
- [Security Guidelines](#security-guidelines)
- [Algorithm Specifications](#algorithm-specifications)
- [Migration Guide](#migration-guide)

## 🚀 Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
cryypt = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
```

### Basic KEM Example

```rust
use cryypt::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key pair
    let keypair = KemBuilder::ml_kem_768().generate().await?;
    
    // Alice: Encapsulate shared secret
    let encapsulation = KemBuilder::ml_kem_768()
        .with_public_key(keypair.public_key_vec())?
        .encapsulate()
        .await?;
    
    // Bob: Decapsulate shared secret
    let decapsulation = KemBuilder::ml_kem_768()
        .with_secret_key(keypair.secret_key_vec())?
        .with_ciphertext(encapsulation.ciphertext())
        .decapsulate()
        .await?;
    
    // Shared secrets match!
    assert_eq!(
        encapsulation.shared_secret().as_bytes(),
        decapsulation.shared_secret().as_bytes()
    );
    
    Ok(())
}
```

### Basic Digital Signature Example

```rust
use cryypt::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate signing key pair
    let keypair = SignatureBuilder::ml_dsa_65().generate().await?;
    
    let message = b"Important document requiring digital signature";
    
    // Sign message
    let signature = SignatureBuilder::ml_dsa_65()
        .with_secret_key(keypair.secret_key_vec())?
        .with_message(message)
        .sign()
        .await?;
    
    // Verify signature
    let verification = SignatureBuilder::ml_dsa_65()
        .with_public_key(keypair.public_key_vec())?
        .with_message(message)
        .with_signature(signature.signature())
        .verify()
        .await?;
    
    assert!(verification.is_valid());
    Ok(())
}
```

## 🔐 Supported Algorithms

### Key Encapsulation Mechanisms (FIPS 203)

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Shared Secret |
|-----------|----------------|------------|------------|------------|---------------|
| **ML-KEM-512** | 1 (128-bit) | 800 bytes | 1632 bytes | 768 bytes | 32 bytes |
| **ML-KEM-768** | 3 (192-bit) | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes |
| **ML-KEM-1024** | 5 (256-bit) | 1568 bytes | 3168 bytes | 1568 bytes | 32 bytes |

### Digital Signatures (FIPS 204)

| Algorithm | Security Level | Public Key | Secret Key | Signature |
|-----------|----------------|------------|------------|-----------|
| **ML-DSA-44** | 2 (128-bit) | 1312 bytes | 2560 bytes | ~2420 bytes |
| **ML-DSA-65** | 3 (192-bit) | 1952 bytes | 4032 bytes | ~3293 bytes |
| **ML-DSA-87** | 5 (256-bit) | 2592 bytes | 4896 bytes | ~4595 bytes |
| **FALCON-512** | 1 (128-bit) | 897 bytes | 1281 bytes | ~666 bytes |
| **FALCON-1024** | 5 (256-bit) | 1793 bytes | 2305 bytes | ~1280 bytes |

### Hash-Based Signatures (SPHINCS+)

| Variant | Security Level | Fast/Small | Public Key | Secret Key | Signature |
|---------|----------------|------------|------------|------------|-----------|
| **sha256-128f-simple** | 1 (128-bit) | Fast | 32 bytes | 64 bytes | ~17KB |
| **sha256-128s-simple** | 1 (128-bit) | Small | 32 bytes | 64 bytes | ~7KB |
| **sha256-192f-simple** | 3 (192-bit) | Fast | 48 bytes | 96 bytes | ~35KB |
| **sha256-192s-simple** | 3 (192-bit) | Small | 48 bytes | 96 bytes | ~16KB |
| **sha256-256f-simple** | 5 (256-bit) | Fast | 64 bytes | 128 bytes | ~49KB |
| **sha256-256s-simple** | 5 (256-bit) | Small | 64 bytes | 128 bytes | ~29KB |

## 🔑 Key Encapsulation Mechanisms (KEM)

KEMs enable secure key exchange between parties without prior shared secrets.

### Basic Usage

```rust
use cryypt::prelude::*;

// Choose security level
let keypair = KemBuilder::ml_kem_768().generate().await?;  // 192-bit security

// Extract keys for separate operations
let public_key = keypair.public_key_vec();
let secret_key = keypair.secret_key_vec();

// Alice: Create shared secret with Bob's public key
let encapsulation = KemBuilder::ml_kem_768()
    .with_public_key(public_key)?
    .encapsulate()
    .await?;

// Alice sends ciphertext to Bob
let ciphertext = encapsulation.ciphertext_vec();

// Bob: Recover shared secret using his secret key
let decapsulation = KemBuilder::ml_kem_768()
    .with_secret_key(secret_key)?
    .with_ciphertext(ciphertext)
    .decapsulate()
    .await?;

// Both parties now have the same 32-byte shared secret
let shared_secret = decapsulation.shared_secret();
```

### Security Level Selection

```rust
// High performance (128-bit security)
let kem_512 = KemBuilder::ml_kem_512();

// Balanced (192-bit security) - RECOMMENDED
let kem_768 = KemBuilder::ml_kem_768();

// Maximum security (256-bit security)
let kem_1024 = KemBuilder::ml_kem_1024();

// Dynamic selection
let kem = KemBuilder::ml_kem(768)?;  // Same as ml_kem_768()
```

### Working with Shared Secrets

```rust
let encapsulation = KemBuilder::ml_kem_768()
    .with_public_key(public_key)?
    .encapsulate()
    .await?;

let shared_secret = encapsulation.shared_secret();

// Access raw bytes
let secret_bytes: &[u8] = shared_secret.as_bytes();

// Encode for transmission/storage
let hex_secret = shared_secret.to_hex();
let b64_secret = shared_secret.to_base64();

// Reconstruct from encoded data
let from_hex = SharedSecret::from_hex(KemAlgorithm::MlKem768, &hex_secret)?;
let from_b64 = SharedSecret::from_base64(KemAlgorithm::MlKem768, &b64_secret)?;
```

## ✍️ Digital Signatures

Digital signatures provide authentication, integrity, and non-repudiation.

### ML-DSA (Lattice-based)

```rust
use cryypt::prelude::*;

// Generate key pair
let keypair = SignatureBuilder::ml_dsa_65().generate().await?;

let document = b"Contract: Transfer of 1000 BTC to Alice";

// Sign document
let signature = SignatureBuilder::ml_dsa_65()
    .with_secret_key(keypair.secret_key_vec())?
    .with_message(document)
    .sign()
    .await?;

// Verify signature
let verification = SignatureBuilder::ml_dsa_65()
    .with_public_key(keypair.public_key_vec())?
    .with_message(document)
    .with_signature(signature.signature())
    .verify()
    .await?;

if verification.is_valid() {
    println!("✅ Signature is valid");
} else {
    println!("❌ Signature is invalid");
}
```

### FALCON (Compact Signatures)

FALCON produces much smaller signatures than ML-DSA, ideal for bandwidth-constrained environments.

```rust
// Compact signatures with FALCON
let keypair = SignatureBuilder::falcon_512().generate().await?;

let signature = SignatureBuilder::falcon_512()
    .with_secret_key(keypair.secret_key_vec())?
    .with_message(b"Small signature needed")
    .sign()
    .await?;

println!("Signature size: {} bytes", signature.signature_size()); // ~666 bytes
```

### SPHINCS+ (Hash-based)

SPHINCS+ offers the highest confidence in long-term security but produces large signatures.

```rust
// Hash-based signatures (quantum-secure)
let keypair = SignatureBuilder::sphincs_plus("sha256-128f-simple")?.generate().await?;

let signature = SignatureBuilder::sphincs_plus("sha256-128f-simple")?
    .with_secret_key(keypair.secret_key_vec())?
    .with_message(b"Maximum security signature")
    .sign()
    .await?;

// Large but extremely secure signature
println!("Signature size: {} bytes", signature.signature_size()); // ~17KB
```

### Multiple Message Formats

```rust
let keypair = SignatureBuilder::ml_dsa_44().generate().await?;
let sk = keypair.secret_key_vec();

// Raw bytes
let sig1 = SignatureBuilder::ml_dsa_44()
    .with_secret_key(sk.clone())?
    .with_message(b"Raw byte message")
    .sign().await?;

// Text string
let sig2 = SignatureBuilder::ml_dsa_44()
    .with_secret_key(sk.clone())?
    .with_message_text("Unicode text: 你好世界 🌍")
    .sign().await?;

// Hex-encoded data
let sig3 = SignatureBuilder::ml_dsa_44()
    .with_secret_key(sk.clone())?
    .with_message_hex("deadbeef")?
    .sign().await?;

// Base64-encoded data
let sig4 = SignatureBuilder::ml_dsa_44()
    .with_secret_key(sk)?
    .with_message_base64("SGVsbG8gV29ybGQ=")?  // "Hello World"
    .sign().await?;
```

## 🔐 Hybrid Encryption Patterns

Combine post-quantum KEMs with symmetric encryption for protecting large data.

### Basic Hybrid Encryption

```rust
use cryypt::prelude::*;

async fn hybrid_encrypt(
    public_key: Vec<u8>, 
    plaintext: &[u8]
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // 1. Encapsulate random shared secret
    let encapsulation = KemBuilder::ml_kem_768()
        .with_public_key(public_key)?
        .encapsulate()
        .await?;
    
    // 2. Use shared secret as AES key
    let aes_ciphertext = Cipher::aes()
        .with_key(Key::from_bytes(encapsulation.shared_secret().as_bytes().to_vec()))
        .with_data(plaintext)
        .encrypt()
        .await?;
    
    // Return: (KEM ciphertext, AES ciphertext)
    Ok((encapsulation.ciphertext_vec(), aes_ciphertext.to_bytes()))
}

async fn hybrid_decrypt(
    secret_key: Vec<u8>,
    kem_ciphertext: Vec<u8>,
    aes_ciphertext: Vec<u8>
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 1. Decapsulate shared secret
    let decapsulation = KemBuilder::ml_kem_768()
        .with_secret_key(secret_key)?
        .with_ciphertext(kem_ciphertext)
        .decapsulate()
        .await?;
    
    // 2. Decrypt using recovered shared secret
    let plaintext = Cipher::aes()
        .with_key(Key::from_bytes(decapsulation.shared_secret().as_bytes().to_vec()))
        .with_ciphertext(aes_ciphertext)
        .decrypt()
        .await?;
    
    Ok(plaintext)
}
```

### Authenticated Hybrid Encryption

```rust
async fn signed_hybrid_encrypt(
    recipient_kem_pk: Vec<u8>,
    sender_sig_sk: Vec<u8>,
    plaintext: &[u8]
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // 1. Encrypt with hybrid encryption
    let (kem_ct, aes_ct) = hybrid_encrypt(recipient_kem_pk, plaintext).await?;
    
    // 2. Sign the ciphertext for authentication
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&kem_ct);
    signed_data.extend_from_slice(&aes_ct);
    
    let signature = SignatureBuilder::ml_dsa_65()
        .with_secret_key(sender_sig_sk)?
        .with_message(&signed_data)
        .sign()
        .await?;
    
    Ok((kem_ct, aes_ct, signature.signature_vec()))
}
```

## 💾 Key Management

### File Storage

```rust
use cryypt::prelude::*;
use tokio::fs;

// Generate and save keys
let kem_keypair = KemBuilder::ml_kem_768().generate().await?;
let sig_keypair = SignatureBuilder::ml_dsa_65().generate().await?;

// Save as binary files
fs::write("kem_public.key", kem_keypair.public_key()).await?;
fs::write("kem_secret.key", kem_keypair.secret_key()).await?;

// Save as hex files
fs::write("sig_public.hex", hex::encode(sig_keypair.public_key())).await?;
fs::write("sig_secret.hex", hex::encode(sig_keypair.secret_key())).await?;

// Load keys from files
let kem_pk = fs::read("kem_public.key").await?;
let kem_sk = fs::read("kem_secret.key").await?;

let sig_pk_hex = fs::read_to_string("sig_public.hex").await?;
let sig_sk_hex = fs::read_to_string("sig_secret.hex").await?;

// Use loaded keys
let encapsulation = KemBuilder::ml_kem_768()
    .with_public_key(kem_pk)?
    .encapsulate()
    .await?;

let signature = SignatureBuilder::ml_dsa_65()
    .with_secret_key_hex(&sig_sk_hex)?
    .with_message(b"Message signed with loaded key")
    .sign()
    .await?;
```

### Key Encoding Formats

```rust
let keypair = KemBuilder::ml_kem_512().generate().await?;

// Binary (most compact)
let pk_bytes = keypair.public_key_vec();
let sk_bytes = keypair.secret_key_vec();

// Hexadecimal (human readable)
let pk_hex = hex::encode(keypair.public_key());
let sk_hex = hex::encode(keypair.secret_key());

// Base64 (web/JSON friendly)
use base64::Engine;
let engine = base64::engine::general_purpose::STANDARD;
let pk_b64 = engine.encode(keypair.public_key());
let sk_b64 = engine.encode(keypair.secret_key());

// Load from different formats
let from_hex = KemBuilder::ml_kem_512().with_public_key_hex(&pk_hex)?;
let from_b64 = KemBuilder::ml_kem_512().with_public_key_base64(&pk_b64)?;
let from_bytes = KemBuilder::ml_kem_512().with_public_key(pk_bytes)?;
```

## ⚠️ Error Handling

### Common Error Types

```rust
use cryypt::{CryptError, Result};

match kem_operation().await {
    Ok(result) => println!("Success!"),
    Err(CryptError::InvalidKeySize { expected, actual }) => {
        eprintln!("Wrong key size: expected {}, got {}", expected, actual);
    }
    Err(CryptError::UnsupportedAlgorithm(msg)) => {
        eprintln!("Unsupported algorithm: {}", msg);
    }
    Err(CryptError::InvalidKey(msg)) => {
        eprintln!("Invalid key format: {}", msg);
    }
    Err(CryptError::AuthenticationFailed(msg)) => {
        eprintln!("Signature verification failed: {}", msg);
    }
    Err(CryptError::Io(io_err)) => {
        eprintln!("File I/O error: {}", io_err);
    }
    Err(e) => eprintln!("Other error: {}", e),
}
```

### Graceful Error Recovery

```rust
async fn robust_key_loading(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Try multiple formats
    if let Ok(data) = tokio::fs::read(path).await {
        return Ok(data);
    }
    
    if let Ok(hex_data) = tokio::fs::read_to_string(path).await {
        if let Ok(bytes) = hex::decode(&hex_data) {
            return Ok(bytes);
        }
    }
    
    Err("Could not load key in any supported format".into())
}
```

## ⚡ Performance Considerations

### Algorithm Selection Guidelines

**For Maximum Performance:**
- KEM: ML-KEM-512 (128-bit security)
- Signatures: FALCON-512 (small signatures, fast)

**For Balanced Performance/Security:**
- KEM: ML-KEM-768 (192-bit security) **← RECOMMENDED**
- Signatures: ML-DSA-65 (192-bit security) **← RECOMMENDED**

**For Maximum Security:**
- KEM: ML-KEM-1024 (256-bit security)
- Signatures: ML-DSA-87 or FALCON-1024 (256-bit security)

**For Long-term Archival:**
- Signatures: SPHINCS+ (hash-based, extremely secure)

### Performance Benchmarks

Approximate performance on modern hardware:

| Operation | ML-KEM-768 | ML-DSA-65 | FALCON-512 |
|-----------|------------|-----------|-------------|
| Key Generation | ~1ms | ~2ms | ~50ms |
| Encaps/Sign | ~1ms | ~3ms | ~15ms |
| Decaps/Verify | ~1ms | ~1ms | ~0.5ms |

### Optimization Tips

```rust
// Pre-generate keys when possible
let keypair = SignatureBuilder::ml_dsa_65().generate().await?;
let pk = keypair.public_key_vec(); // Extract once
let sk = keypair.secret_key_vec(); // Extract once

// Reuse keys for multiple operations
for message in messages {
    let signature = SignatureBuilder::ml_dsa_65()
        .with_secret_key(sk.clone())? // Reuse extracted key
        .with_message(message)
        .sign()
        .await?;
}
```

## 🛡️ Security Guidelines

### Key Management Best Practices

1. **Generate keys securely**: Always use the library's key generation functions
2. **Protect secret keys**: Never log, transmit, or store secret keys in plaintext
3. **Use appropriate key sizes**: Match security level to your threat model
4. **Rotate keys regularly**: Implement key rotation for long-term security
5. **Validate inputs**: Always check key sizes and formats before use

### Secure Implementation Patterns

```rust
// ✅ GOOD: Extract keys once, reuse safely
let keypair = KemBuilder::ml_kem_768().generate().await?;
let pk = keypair.public_key_vec();
let sk = keypair.secret_key_vec();

// Use keys...
drop(sk); // Explicit cleanup (automatic with zeroize)

// ✅ GOOD: Validate inputs
if public_key.len() != 1184 {
    return Err(CryptError::InvalidKeySize { 
        expected: 1184, 
        actual: public_key.len() 
    });
}

// ❌ BAD: Don't hardcode keys
// const SECRET_KEY: &[u8] = b"hardcoded_secret"; // Never do this!

// ❌ BAD: Don't ignore verification results
let verification = signature_verification.await?;
// assert!(verification.is_valid()); // Always check!
```

### Side-Channel Resistance

This library implements several side-channel protections:

- **Constant-time operations**: Secret-dependent operations use constant-time algorithms
- **Memory zeroization**: Secret keys are automatically zeroed when dropped
- **Secure random generation**: Uses cryptographically secure random number generators

## 📋 Algorithm Specifications

### ML-KEM (FIPS 203) - Key Encapsulation

Based on the **CRYSTALS-Kyber** algorithm, standardized in NIST FIPS 203.

- **Security Model**: IND-CCA2 secure under the Module-LWE assumption
- **Quantum Security**: Secure against Shor's algorithm and Grover's algorithm
- **Use Cases**: Key exchange, hybrid encryption, secure communication

### ML-DSA (FIPS 204) - Digital Signatures

Based on the **CRYSTALS-Dilithium** algorithm, standardized in NIST FIPS 204.

- **Security Model**: EUF-CMA secure under the Module-LWE assumption  
- **Quantum Security**: Secure against quantum signature forgery attacks
- **Use Cases**: Digital signatures, authentication, non-repudiation

### FALCON - Compact Signatures

Based on **NTRU lattices** with signature compression.

- **Security Model**: EUF-CMA secure under the NTRU assumption
- **Advantage**: Smallest signature sizes among lattice schemes
- **Use Cases**: Bandwidth-constrained environments, blockchain, IoT

### SPHINCS+ - Hash-Based Signatures

Based on **Merkle trees** and one-time signatures.

- **Security Model**: EUF-CMA secure under standard hash function assumptions
- **Advantage**: Highest confidence in long-term security (no number theory)
- **Use Cases**: Long-term archival, maximum security scenarios

## 🔄 Migration Guide

### From Classical Cryptography

```rust
// Classical ECDSA (insecure against quantum)
// let keypair = ecdsa::SigningKey::random(&mut rng);
// let signature = keypair.sign(message);

// Post-quantum ML-DSA (quantum-secure)
let keypair = SignatureBuilder::ml_dsa_65().generate().await?;
let signature = SignatureBuilder::ml_dsa_65()
    .with_secret_key(keypair.secret_key_vec())?
    .with_message(message)
    .sign()
    .await?;
```

### From RSA/DH Key Exchange

```rust
// Classical Diffie-Hellman (insecure against quantum)
// let shared_secret = alice_private * bob_public;

// Post-quantum ML-KEM (quantum-secure)
let encapsulation = KemBuilder::ml_kem_768()
    .with_public_key(bob_public_key)?
    .encapsulate()
    .await?;

let shared_secret = encapsulation.shared_secret();
```

### Choosing Security Levels

| Classical Security | Post-Quantum Equivalent | Recommended PQ Algorithm |
|-------------------|-------------------------|-------------------------|
| RSA-2048, P-256 | 128-bit quantum | ML-KEM-512, ML-DSA-44 |
| RSA-3072, P-384 | 192-bit quantum | **ML-KEM-768, ML-DSA-65** |
| RSA-4096, P-521 | 256-bit quantum | ML-KEM-1024, ML-DSA-87 |

## 🔗 See Also

- **Examples**: `examples/pqcrypto_comprehensive.rs` - Complete usage examples
- **Tests**: `tests/pqcrypto_*` - Comprehensive test suite
- **NIST Standards**: 
  - [FIPS 203 (ML-KEM)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
  - [FIPS 204 (ML-DSA)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- **Algorithm Documentation**:
  - [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)
  - [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)
  - [FALCON](https://falcon-sign.info/)
  - [SPHINCS+](https://sphincs.org/)

---

**⚠️ Important Security Notice**: Post-quantum cryptography is essential for protecting against future quantum computer threats. While current classical cryptography remains secure against classical computers, quantum computers running Shor's algorithm could break RSA, ECDSA, and Diffie-Hellman. Start migrating to post-quantum algorithms now to ensure long-term security.

**🏛️ Standards Compliance**: This implementation follows NIST FIPS 203 and FIPS 204 standards and uses officially recommended parameter sets. All algorithms have undergone extensive cryptanalysis and are considered ready for production use.