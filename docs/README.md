# Cryptographic Algorithm Specifications

This directory contains the official specifications for all cryptographic algorithms used in the `cyrup-crypt` library.

## Classical Cryptography

### AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)
- **File**: `NIST-SP-800-38D-AES-GCM.pdf`
- **Standard**: NIST Special Publication 800-38D
- **Description**: Specifies the Galois/Counter Mode (GCM) algorithm for confidentiality and authentication. Used for AES-256-GCM implementation.

### ChaCha20-Poly1305
- **File**: `RFC-8439-ChaCha20-Poly1305.pdf`
- **Standard**: IETF RFC 8439
- **Description**: Specifies ChaCha20 stream cipher and Poly1305 authenticator. An IETF variant of Bernstein's ChaCha20-Poly1305 AEAD construction.

### SHA-3 (Secure Hash Algorithm 3)
- **File**: `NIST-FIPS-202-SHA3.pdf`
- **Standard**: NIST FIPS 202
- **Description**: Specifies the SHA-3 family of hash functions based on Keccak. Used for SHA3-512 in HMAC construction.

### HMAC (Hash-based Message Authentication Code)
- **File**: `NIST-FIPS-198-1-HMAC.pdf`
- **Standard**: NIST FIPS 198-1
- **Description**: Specifies the HMAC algorithm for message authentication using cryptographic hash functions.

### Argon2
- **File**: `Argon2-Specification.pdf`
- **Standard**: Password Hashing Competition Winner
- **Description**: Memory-hard key derivation function, winner of the Password Hashing Competition. Used for key stretching.

### BLAKE3
- **File**: `BLAKE3-Specification.pdf`
- **Standard**: BLAKE3 Team Specification
- **Description**: Cryptographic hash function based on Bao tree mode. Faster than SHA-256/SHA-3 with similar security.

## Post-Quantum Cryptography

### ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- **File**: `NIST-FIPS-203-ML-KEM-Kyber.pdf`
- **Standard**: NIST FIPS 203
- **Description**: Kyber-based key encapsulation mechanism for post-quantum key exchange. Provides IND-CCA2 security.

### ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- **File**: `NIST-FIPS-204-ML-DSA-Dilithium.pdf`
- **Standard**: NIST FIPS 204
- **Description**: Dilithium-based digital signature algorithm for post-quantum signatures. Provides EUF-CMA security.

### SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
- **File**: `NIST-FIPS-205-SLH-DSA-SPHINCS+.pdf`
- **Standard**: NIST FIPS 205
- **Description**: SPHINCS+ hash-based signature scheme. Provides quantum-resistant signatures without relying on lattice assumptions.

## Implementation Notes

All implementations in `cyrup-crypt` follow these specifications exactly, with additional considerations for:

1. **Constant-time operations** to prevent timing side-channels
2. **Memory zeroization** using the `zeroize` crate
3. **Hardware acceleration** where available (AES-NI, etc.)
4. **Formal verification** for critical paths
5. **FIPS compliance** where applicable

## Security Levels

- **Classical**: 256-bit security level (AES-256, ChaCha20-256)
- **Post-Quantum**: NIST Level 3 (192-bit classical security equivalent) as default
  - Level 1: 128-bit security (AES-128 equivalent)
  - Level 3: 192-bit security (AES-192 equivalent)
  - Level 5: 256-bit security (AES-256 equivalent)