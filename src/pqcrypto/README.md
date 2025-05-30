# Post-Quantum Cryptography Module

This module provides implementations of NIST-standardized post-quantum cryptographic algorithms that are resistant to attacks by quantum computers.

## Overview

Post-quantum cryptography (PQC) addresses the threat that large-scale quantum computers pose to current public-key cryptography. This module implements:

- **Key Encapsulation Mechanisms (KEMs)**: For secure key exchange
- **Digital Signature Algorithms**: For authentication and non-repudiation

All implementations are based on the NIST post-quantum cryptography standards finalized in 2024.

## Supported Algorithms

### Key Encapsulation Mechanisms (KEMs)

#### ML-KEM (Module-Lattice-based KEM)
- **ML-KEM-512**: NIST security level 1 (~128-bit security)
- **ML-KEM-768**: NIST security level 3 (~192-bit security)
- **ML-KEM-1024**: NIST security level 5 (~256-bit security)

Formerly known as CRYSTALS-Kyber, ML-KEM is based on the hardness of the Module Learning With Errors (MLWE) problem.

### Digital Signature Algorithms

#### ML-DSA (Module-Lattice-based Digital Signature Algorithm)
- **ML-DSA-44**: NIST security level 2
- **ML-DSA-65**: NIST security level 3
- **ML-DSA-87**: NIST security level 5

Formerly known as CRYSTALS-Dilithium, ML-DSA provides fast signing and verification.

#### FALCON
- **FALCON-512**: NIST security level 1
- **FALCON-1024**: NIST security level 5

Based on NTRU lattices, FALCON offers compact signatures and fast operations.

#### SPHINCS+
- Multiple variants with different speed/size trade-offs
- Hash-based signatures providing long-term security
- Stateless design (no state management required)

## Quick Start

### Key Encapsulation (KEM)

```rust
use cryypt::prelude::*;

// Generate a key pair
let keypair = KemBuilder::ml_kem_768()
    .generate()
    .await?;

// Alice encapsulates a shared secret using Bob's public key
let encapsulation = KemBuilder::ml_kem_768()
    .with_public_key(bob_public_key)?
    .encapsulate()
    .await?;

// Bob decapsulates to get the same shared secret
let decapsulation = keypair
    .with_ciphertext(encapsulation.ciphertext())
    .decapsulate()
    .await?;

// Both parties now have the same shared secret
assert_eq!(
    encapsulation.shared_secret().as_bytes(),
    decapsulation.shared_secret().as_bytes()
);
```

### Digital Signatures

```rust
use cryypt::prelude::*;

// Generate a signing key pair
let keypair = SignatureBuilder::ml_dsa_65()
    .generate()
    .await?;

// Sign a message
let signature = keypair
    .with_message(b"Important document")
    .sign()
    .await?;

// Verify the signature
let verification = SignatureBuilder::ml_dsa_65()
    .with_public_key(public_key)?
    .with_message(b"Important document")
    .with_signature(signature.signature())
    .verify()
    .await?;

assert!(verification.is_valid());
```

## Advanced Usage

### Hybrid Encryption

Combine post-quantum KEM with symmetric encryption for large data:

```rust
// Encapsulate to get a shared secret
let encapsulation = KemBuilder::ml_kem_768()
    .with_public_key(recipient_public_key)?
    .encapsulate()
    .await?;

// Use the shared secret as an AES key
let ciphertext = Cipher::aes()
    .with_key(
        Key::from_bytes(encapsulation.shared_secret().as_bytes())
            .with_namespace("hybrid-pq")
    )
    .with_data(large_data)
    .encrypt()
    .await?;

// Send both the KEM ciphertext and AES ciphertext to the recipient
```

### Key Serialization

Keys can be serialized in various formats:

```rust
// Hex encoding
let public_key_hex = hex::encode(&public_key);
let loaded = KemBuilder::ml_kem_768()
    .with_public_key_hex(&public_key_hex)?;

// Base64 encoding
let public_key_b64 = base64::encode(&public_key);
let loaded = KemBuilder::ml_kem_768()
    .with_public_key_base64(&public_key_b64)?;

// File storage
tokio::fs::write("public.key", &public_key).await?;
let loaded = KemBuilder::ml_kem_768()
    .with_public_key_file("public.key")
    .await?;
```

### Message Formats

Signatures support various message input formats:

```rust
// Text messages
let sig = keypair.with_message_text("Hello, world!").sign().await?;

// Hex-encoded data
let sig = keypair.with_message_hex("deadbeef").sign().await?;

// Base64-encoded data
let sig = keypair.with_message_base64("SGVsbG8=").sign().await?;

// From file
let sig = keypair.with_message_file("document.pdf").await?.sign().await?;
```

## Security Levels

NIST defines five security levels for post-quantum algorithms:

1. **Level 1**: At least as hard to break as AES-128
2. **Level 2**: At least as hard to break as SHA-256
3. **Level 3**: At least as hard to break as AES-192
4. **Level 4**: At least as hard to break as SHA-384
5. **Level 5**: At least as hard to break as AES-256

## Performance Characteristics

### Key and Data Sizes

| Algorithm | Public Key | Secret Key | Ciphertext/Signature |
|-----------|------------|------------|---------------------|
| ML-KEM-512 | 800 B | 1,632 B | 768 B |
| ML-KEM-768 | 1,184 B | 2,400 B | 1,088 B |
| ML-KEM-1024 | 1,568 B | 3,168 B | 1,568 B |
| ML-DSA-44 | 1,312 B | 2,528 B | 2,420 B |
| ML-DSA-65 | 1,952 B | 4,000 B | 3,293 B |
| ML-DSA-87 | 2,592 B | 4,864 B | 4,595 B |
| FALCON-512 | 897 B | 1,281 B | 666 B |
| FALCON-1024 | 1,793 B | 2,305 B | 1,280 B |

### Speed Characteristics

- **ML-KEM**: Fast key generation, encapsulation, and decapsulation
- **ML-DSA**: Moderate speed for all operations
- **FALCON**: Very fast signing and verification, compact signatures
- **SPHINCS+**: Slower but provides hash-based security

## Best Practices

### 1. Algorithm Selection

- **For general use**: ML-KEM-768 and ML-DSA-65 (balanced security/performance)
- **For high security**: ML-KEM-1024 and ML-DSA-87
- **For constrained environments**: FALCON (smaller signatures)
- **For long-term security**: SPHINCS+ (hash-based)

### 2. Hybrid Approaches

Consider using post-quantum algorithms alongside classical algorithms during the transition period:

```rust
// Hybrid key exchange: ML-KEM + X25519
// Hybrid signatures: ML-DSA + Ed25519
```

### 3. Key Management

- Store keys securely using the same practices as classical cryptography
- Consider key rotation schedules appropriate for your security requirements
- Use hardware security modules (HSMs) when available

### 4. Migration Strategy

1. **Inventory**: Identify all uses of public-key cryptography
2. **Prioritize**: Focus on long-lived keys and sensitive data
3. **Test**: Thoroughly test post-quantum implementations
4. **Deploy**: Use hybrid modes initially, then transition fully

## Error Handling

The module provides detailed error information:

```rust
match KemBuilder::ml_kem_768().with_public_key(invalid_key) {
    Ok(_) => { /* success */ }
    Err(CryptError::InvalidKeySize { expected, actual }) => {
        println!("Wrong key size: expected {} bytes, got {}", expected, actual);
    }
    Err(e) => println!("Other error: {}", e),
}
```

## Compliance

This implementation follows:
- NIST FIPS 203 (ML-KEM)
- NIST FIPS 204 (ML-DSA)
- NIST FIPS 205 (SLH-DSA/SPHINCS+)
- NIST standards for FALCON (forthcoming)

## Security Considerations

1. **Quantum Resistance**: These algorithms are designed to resist attacks by both classical and quantum computers
2. **Side-Channel Resistance**: Implementations aim to be constant-time where possible
3. **Randomness**: Ensure high-quality randomness for key generation
4. **Key Sizes**: Be aware of larger key and signature sizes compared to classical algorithms

## Examples

See the `tests/pqcrypto_examples.rs` file for comprehensive examples including:
- Basic key exchange
- Hybrid encryption
- Document signing
- Performance comparisons
- Error handling

## Future Work

- Hardware acceleration support
- Additional parameter sets
- Threshold signatures
- Integration with key management systems