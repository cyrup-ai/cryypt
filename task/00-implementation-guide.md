# RSA-Based Session Authentication - Implementation Guide

## Overview
Replace passphrase-only authentication with RSA key-based session authentication for better security and usability.

## Architecture

### Current (Broken)
```
┌─────────────┐
│   Passphrase │
└──────┬──────┘
       ├──> Argon2 ──> encryption_key (in-memory, lost between processes)
       └──> Argon2 ──> jwt_key (in-memory, lost between processes)
                        └──> HS256 JWT signing
```
**Problem:** Each CLI command is a new process. In-memory keys are lost. JWT validation impossible.

### New (Fixed)
```
┌─────────────┐
│  Passphrase  │ (only on first setup)
└──────┬───────┘
       ↓
┌─────────────────┐
│  ~/.ssh/cryypt  │  RSA-2048/4096 Private Key
│     .rsa        │  (persisted to filesystem)
└────────┬────────┘
         ├──> HKDF-SHA256 ──> encryption_key (derived on demand)
         │
         └──> RS256 JWT signing
              ├──> Private key: Sign JWT
              └──> Public key: Verify JWT (stored in database)

Database stores:
  - RSA key path
  - RSA public key
  - JWT tokens with expiration
```

## Key Storage Locations

### Filesystem (~/.ssh/cryypt.rsa)
- **RSA private key** (PKCS1 DER format)
- Generated once from passphrase
- Used for all subsequent operations
- Never stored in database

### Database (.db file)
- **RSA key path** (string)
- **RSA public key** (DER bytes, base64-encoded)
- **JWT tokens** (with exp timestamps)
- **Encrypted values** (user data)

### OS Keychain (unchanged)
- **PQCrypto keypairs** for outer armor (.db ↔ .vault)

## Implementation Mapping

### cryypt_key Package

#### RSA Key Generation
Location: `/Volumes/samsung_t9/cryypt/packages/key/src/api/algorithm_builders/rsa_builder.rs`

```rust
use cryypt_key::Key;

// Generate RSA keypair
let keypair = Key::rsa()
    .with_size(2048)
    .on_result(|result| result.unwrap_or_default())
    .generate()
    .await;

// Format: [4 bytes private_len][private_key_der][4 bytes public_len][public_key_der]
```

#### Parsing RSA Keypair
Need to create utility to parse the combined format:
```rust
fn parse_rsa_keypair(keypair_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut offset = 0;
    
    // Read private key length
    let private_len = u32::from_le_bytes([
        keypair_bytes[0], keypair_bytes[1], keypair_bytes[2], keypair_bytes[3]
    ]) as usize;
    offset += 4;
    
    // Read private key
    let private_key = keypair_bytes[offset..offset + private_len].to_vec();
    offset += private_len;
    
    // Read public key length
    let public_len = u32::from_le_bytes([
        keypair_bytes[offset], keypair_bytes[offset + 1], 
        keypair_bytes[offset + 2], keypair_bytes[offset + 3]
    ]) as usize;
    offset += 4;
    
    // Read public key
    let public_key = keypair_bytes[offset..offset + public_len].to_vec();
    
    Ok((private_key, public_key))
}
```

### cryypt_jwt Package

#### RS256 JWT Signing
Location: `/Volumes/samsung_t9/cryypt/packages/jwt/src/api/builder.rs`

```rust
use cryypt_jwt::Jwt;

// Sign JWT with RSA private key
let token = Jwt::builder()
    .with_algorithm("RS256")
    .with_private_key(&private_key_der)  // PKCS1 DER format
    .sign(claims)
    .await?;

// Verify JWT with RSA public key
let claims = Jwt::builder()
    .with_algorithm("RS256")
    .with_public_key(&public_key_der)   // PKCS1 DER format
    .verify(token)
    .await?;
```

### Encryption Key Derivation

#### HKDF-SHA256 from RSA Key Material
```rust
use hkdf::Hkdf;
use sha2::Sha256;

fn derive_aes_key_from_rsa(private_key_der: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, private_key_der);
    let mut okm = [0u8; 32];
    hk.expand(b"cryypt-vault-aes-key-v1", &mut okm)
        .map_err(|_| VaultError::KeyDerivation("HKDF expansion failed".to_string()))?;
    Ok(okm)
}
```

## User Workflows

### Initial Setup
```bash
# Generate RSA key from passphrase, save to ~/.ssh/cryypt.rsa
vault new --passphrase "mypassphrase"

# Key created: ~/.ssh/cryypt.rsa
# Database stores: key path, public key
```

### Session-Based Usage
```bash
# Login once per session
vault login --passphrase "mypassphrase"
# Output: JWT token (1 hour expiration)

export VAULT_JWT="<token>"

# All operations without passphrase
vault put key1 "value1"
vault get key1
vault list

# After 1 hour, JWT expires
vault put key2 "value2"  # Error: JWT expired

# Login again
vault login --passphrase "mypassphrase"
export VAULT_JWT="<new-token>"
```

### Custom Key Path
```bash
# Use custom key location
vault new --passphrase "mypass" --key ~/work/vault.rsa

# Login with custom key
vault login --passphrase "mypass"
# Key path remembered in database
```

## Security Properties

### Database Compromise
- ❌ No RSA private key (in filesystem)
- ❌ No encryption key (derived from RSA key)
- ✅ Has RSA public key (can't forge JWTs)
- ✅ Has JWT tokens (time-limited, validates with public key)
- ✅ Has encrypted values (useless without encryption key)

### Filesystem Compromise
- ✅ Has RSA private key
- ❌ No database (encrypted values elsewhere)
- Attacker needs both filesystem + database

### JWT Expiration
- JWT expires after N hours
- Expired JWT rejected
- Must login again to get new JWT
- Fresh JWT = fresh session authorization

## Task Execution Order

1. **Task 01:** RSA key management infrastructure
2. **Task 02:** JWT authentication with RS256
3. **Task 03:** Encryption key derivation from RSA
4. **Task 04:** Database schema updates
5. **Task 05:** CLI integration

## Testing Strategy

### Unit Tests
- RSA key generation from passphrase
- RSA keypair parsing
- HKDF encryption key derivation
- JWT signing/verification with RS256

### Integration Tests
- Complete vault lifecycle with RSA keys
- Session persistence across process boundaries
- JWT expiration handling
- Key rotation scenarios

### E2E Tests
Update `/Volumes/samsung_t9/cryypt/packages/vault/test_all_cli_commands_e2e.sh`:
```bash
# Create vault
vault new --passphrase "testpass"

# Login to get JWT
JWT=$(vault login --passphrase "testpass" --json | jq -r .jwt_token)
export VAULT_JWT="$JWT"

# Operations without passphrase
vault put key1 "value1"
vault get key1
vault list

# Logout
vault logout

# Subsequent operations should fail
vault get key1  # Error: No valid JWT
```

## Migration Notes

### Existing Vaults
- Old vaults use passphrase-only authentication
- On first operation after upgrade:
  1. Prompt for passphrase
  2. Generate RSA key from passphrase
  3. Save to ~/.ssh/cryypt.rsa
  4. Update database schema
  5. Continue with new authentication

### Backwards Compatibility
- Support --passphrase for operations (legacy mode)
- Gradually migrate users to JWT-based workflow
- Document migration in release notes

## Performance Considerations

### RSA Operations
- Key generation: ~100ms (done once per vault)
- JWT signing: ~5ms per token
- JWT verification: ~2ms per token
- Acceptable for CLI usage

### HKDF Key Derivation
- ~1μs (microsecond)
- Negligible overhead

### Overall
- First login: 100ms (RSA key generation)
- Subsequent logins: 5ms (JWT signing)
- Operations: 2ms (JWT verification)
- Much faster than Argon2 passphrase derivation per operation
