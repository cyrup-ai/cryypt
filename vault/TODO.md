# Updated TODO.md - Production Crypto Stack Integration

## Core Implementation Tasks

### 1. Add Required Crypto Dependencies to vault/src/db/vault_store/backend.rs
- Import cryypt_cipher with on_result! patterns from README.md
- Import cryypt_pqcrypto for key management  
- Import cryypt_jwt for session token handling
- DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required.

### 2. Act as an Objective QA Rust Expert and rate the quality of the crypto dependencies integration on a scale of 1-10. Provide specific feedback on import correctness and library usage.

### 3. Implement JWT Session Management in vault/src/db/vault_store/mod.rs
- Add session_token field to LocalVaultProvider struct
- Generate JWT token on successful unlock using cryypt_jwt
- Validate JWT token in check_unlocked() method
- Handle token expiration and refresh logic
- DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required.

### 4. Act as an Objective QA Rust Expert and rate the quality of the JWT session implementation on a scale of 1-10. Provide specific feedback on token security and session handling.

### 5. Implement PQCrypto Key Derivation in vault/src/db/vault_store/backend.rs
- Add derive_encryption_key method using cryypt_pqcrypto
- Use passphrase + salt to derive symmetric encryption key
- Store derived key securely in memory during unlocked session
- Clear key material on lock operation
- DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required.

### 6. Act as an Objective QA Rust Expert and rate the quality of the PQCrypto key derivation on a scale of 1-10. Provide specific feedback on key security and memory handling.

### 7. Implement Cipher Encryption Methods in vault/src/db/vault_store/backend.rs
- Add encrypt_data method using cryypt_cipher with on_result! pattern
- Add decrypt_data method using cryypt_cipher with on_result! pattern  
- Use derived key from PQCrypto for encryption operations
- Handle encryption/decryption errors properly
- DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required.

### 8. Act as an Objective QA Rust Expert and rate the quality of the cipher encryption methods on a scale of 1-10. Provide specific feedback on encryption implementation and error handling.

### 9. Update All Data Storage Operations in vault/src/db/vault_store/backend.rs
- Replace base64 encoding with encrypt_data() in put_impl
- Replace base64 encoding with encrypt_data() in put_with_namespace
- Update all storage operations to use cipher encryption
- Ensure consistent encryption across all data paths
- DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required.

### 10. Act as an Objective QA Rust Expert and rate the quality of the data storage encryption updates on a scale of 1-10. Provide specific feedback on encryption consistency and implementation completeness.

### 11. Update All Data Retrieval Operations in vault/src/db/vault_store/backend.rs  
- Replace base64 decoding with decrypt_data() in get_impl
- Replace base64 decoding with decrypt_data() in find_impl
- Replace base64 decoding with decrypt_data() in get_by_namespace
- Update all retrieval operations to use cipher decryption
- DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required.

### 12. Act as an Objective QA Rust Expert and rate the quality of the data retrieval decryption updates on a scale of 1-10. Provide specific feedback on decryption consistency and error handling.

### 13. Implement Secure Passphrase Storage in vault/src/db/vault_store/backend.rs
- Add store_passphrase_hash method using Argon2 from VaultConfig
- Store hashed passphrase in dedicated vault_auth table
- Add load_passphrase_hash method for verification
- Use PQCrypto for additional passphrase protection
- DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required.

### 14. Act as an Objective QA Rust Expert and rate the quality of the passphrase storage implementation on a scale of 1-10. Provide specific feedback on hash security and storage protection.

### 15. Update unlock_impl with Full Crypto Integration in vault/src/db/vault_store/backend.rs
- Load stored passphrase hash from SurrealDB
- Verify passphrase using Argon2 + PQCrypto
- Derive encryption key using PQCrypto on successful verification
- Generate JWT session token using cryypt_jwt
- Store session token and derived key in provider state
- DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required.

### 16. Act as an Objective QA Rust Expert and rate the quality of the unlock implementation on a scale of 1-10. Provide specific feedback on authentication security and crypto integration.