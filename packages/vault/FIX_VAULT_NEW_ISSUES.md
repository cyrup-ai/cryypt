# TODO - Fix Vault New Command Issues

## Critical Security Fix

### 1. Remove passphrase exposure from output
**File:** `packages/vault/src/tui/cli/new_vault.rs`  
**Location:** Line 420  
**Issue:** Passphrase is printed in plain text in success message  
**Current code:**
```rust
println!("      vault --vault-path {} login --passphrase \"{}\"", base_path.display(), passphrase);
```

**Fix Required:**
Replace the actual passphrase with a placeholder in the output message.

**Change to:**
```rust
println!("      vault --vault-path {} login --passphrase <your-passphrase>", base_path.display());
```

**Constraints:** DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required. Do not modify or rewrite any portion of the app outside scope.

### 2. QA Review - Passphrase exposure fix
**Act as an Objective Rust Expert QA reviewer:**
- Verify passphrase is no longer printed in output
- Verify the example command still makes sense to users
- Verify both JSON and non-JSON output modes are secure
- Check if passphrase appears anywhere else in output
- Verify no other sensitive data is exposed
- Rate security fix quality 1-10 with detailed reasoning

---

## Documentation Fixes

### 3. Fix module documentation
**File:** `packages/vault/src/tui/cli/new_vault.rs`  
**Location:** Lines 1-4  
**Issue:** Says "Vaults are created in locked (.vault) format" but actually creates .db directories  

**Current documentation:**
```rust
//! Vault initialization and creation
//!
//! This module handles the creation of new encrypted vaults with PQCrypto protection.
//! Vaults are created in locked (.vault) format and stored in the system keychain.
```

**Fix Required:**
Update to accurately describe what the module does.

**Change to:**
```rust
//! Vault initialization and creation
//!
//! This module handles the creation of new encrypted vaults with PQCrypto protection.
//! Vaults are created as SurrealDB directories (.db) with Argon2id encryption.
//! PQCrypto keypairs are generated and stored in the system keychain for optional file-level encryption.
```

**Constraints:** DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required. Do not modify or rewrite any portion of the app outside scope.

### 4. QA Review - Module documentation fix
**Act as an Objective Rust Expert QA reviewer:**
- Verify documentation accurately describes module behavior
- Verify no misleading statements remain
- Verify technical accuracy of encryption methods mentioned
- Verify clarity for developers reading the code
- Rate documentation quality 1-10 with detailed reasoning

---

### 5. Fix function documentation
**File:** `packages/vault/src/tui/cli/new_vault.rs`  
**Location:** Lines 109-141  
**Issue:** Documentation claims vault is locked to .vault format and .db is cleaned up, but this doesn't happen  

**Current documentation:**
```rust
/// Create a new encrypted vault with PQCrypto protection
///
/// This is the main entry point for vault creation. It performs the complete
/// initialization workflow:
///
/// 1. Determines vault path (custom or XDG default)
/// 2. Validates vault doesn't already exist
/// 3. Creates parent directories
/// 4. Collects passphrase (interactive or from CLI)
/// 5. Ensures PQCrypto keypair exists in keychain
/// 6. Creates and initializes temporary .db file
/// 7. Locks vault to encrypted .vault format
/// 8. Cleans up temporary .db file
```

**Fix Required:**
Update steps 6-8 to match actual implementation.

**Change to:**
```rust
/// Create a new encrypted vault with PQCrypto protection
///
/// This is the main entry point for vault creation. It performs the complete
/// initialization workflow:
///
/// 1. Determines vault path (custom or XDG default)
/// 2. Validates vault doesn't already exist
/// 3. Creates parent directories
/// 4. Collects passphrase (interactive or from CLI)
/// 5. Ensures PQCrypto keypair exists in keychain
/// 6. Creates and initializes vault database (.db directory)
/// 7. Unlocks vault with passphrase to initialize encryption
/// 8. Locks vault to persist to disk
```

**Constraints:** DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required. Do not modify or rewrite any portion of the app outside scope.

### 6. QA Review - Function documentation fix
**Act as an Objective Rust Expert QA reviewer:**
- Verify documentation matches actual function implementation
- Verify all 8 steps accurately describe what happens
- Verify no misleading claims remain
- Verify developers can understand the workflow
- Rate documentation quality 1-10 with detailed reasoning

---

### 7. Fix Commands enum documentation
**File:** `packages/vault/src/tui/cli/commands.rs`  
**Location:** Lines 44-66  
**Issue:** Multiple incorrect claims about .vault format, unlocking requirement, etc.  

**Current documentation:**
```rust
/// Create a new encrypted vault with PQCrypto protection
///
/// This command initializes a new vault at the specified path (or default XDG location)
/// and encrypts it using post-quantum cryptography. The vault is created in locked
/// (.vault) format and must be unlocked before use.
///
/// Default path: $XDG_CONFIG_HOME/cryypt/cryypt.vault (or ~/.config/cryypt/cryypt.vault)
///
/// The command will:
/// 1. Generate or reuse PQCrypto keypair in system keychain
/// 2. Create all parent directories safely
/// 3. Initialize an encrypted vault database
/// 4. Lock the vault with PQCrypto armor
///
/// After creation, unlock the vault with:
///   vault unlock    - Decrypt .vault to .db
///   vault login     - Unlock and generate JWT token
///
/// Example usage:
///   vault new
///   vault new --vault-path /my/vault
///   vault new --passphrase "my-secret-pass"
```

**Fix Required:**
Rewrite to accurately describe what the command does.

**Change to:**
```rust
/// Create a new encrypted vault with PQCrypto protection
///
/// This command initializes a new vault at the specified path (or default XDG location)
/// with Argon2id encryption and PQCrypto keypair generation. The vault is created as
/// a SurrealDB database directory (.db) and is immediately ready for use.
///
/// Default path: $XDG_CONFIG_HOME/cryypt/cryypt.db (or ~/.config/cryypt/cryypt.db)
///
/// The command will:
/// 1. Generate or reuse PQCrypto keypair in system keychain
/// 2. Create all parent directories safely
/// 3. Initialize an encrypted vault database with Argon2id key derivation
/// 4. Persist the vault to disk
///
/// After creation, use the vault immediately:
///   vault --vault-path <path> put mykey "myvalue" --passphrase <pass>
///   vault --vault-path <path> login --passphrase <pass>
///
/// Optional: Encrypt vault file with PQCrypto armor:
///   vault --vault-path <path> lock
///
/// Example usage:
///   vault new
///   vault new --vault-path /my/vault
///   vault new --passphrase "my-secret-pass"
```

**Constraints:** DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required. Do not modify or rewrite any portion of the app outside scope.

### 8. QA Review - Commands enum documentation fix
**Act as an Objective Rust Expert QA reviewer:**
- Verify documentation accurately describes command behavior
- Verify default path is correct (.db not .vault)
- Verify workflow steps match implementation
- Verify examples are accurate and helpful
- Verify no misleading statements remain
- Rate documentation quality 1-10 with detailed reasoning

---

## Build and Verification

### 9. Rebuild and verify no compilation errors
**Command:** `cargo build --package cryypt_vault --release`  
**Details:**
- Verify clean build with no errors
- Verify no new warnings introduced
- Verify documentation changes don't break anything

**Constraints:** DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required. Do not modify or rewrite any portion of the app outside scope.

### 10. QA Review - Build verification
**Act as an Objective Rust Expert QA reviewer:**
- Verify cargo build succeeds
- Verify zero compilation errors
- Verify zero new warnings
- Rate build quality 1-10 with detailed reasoning

---

### 11. Run clippy and verify no warnings
**Command:** `cargo clippy --package cryypt_vault -- -D warnings`  
**Details:**
- Verify clippy passes with zero warnings
- Verify no new issues introduced

**Constraints:** DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required. Do not modify or rewrite any portion of the app outside scope.

### 12. QA Review - Clippy verification
**Act as an Objective Rust Expert QA reviewer:**
- Verify clippy passes with zero warnings
- Verify code follows Rust best practices
- Rate code quality 1-10 with detailed reasoning

---

### 13. Manual testing - Verify passphrase not exposed
**Test Steps:**
1. Run `vault new --passphrase "test123"`
2. Verify passphrase does NOT appear in output
3. Run `vault --json new --passphrase "test123"`
4. Verify passphrase does NOT appear in JSON output
5. Verify example commands in output are still helpful

**Constraints:** DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required. Do not modify or rewrite any portion of the app outside scope.

### 14. QA Review - Security verification
**Act as an Objective Rust Expert QA reviewer:**
- Verify passphrase is never displayed in any output mode
- Verify no other sensitive data is exposed
- Verify output is still helpful to users
- Rate security quality 1-10 with detailed reasoning

---

### 15. Manual testing - Verify documentation accuracy
**Test Steps:**
1. Read the updated documentation
2. Run `vault new` and verify behavior matches docs
3. Verify created vault is .db directory, not .vault file
4. Verify vault is immediately usable without unlock
5. Verify all documented steps actually happen

**Constraints:** DO NOT MOCK, FABRICATE, FAKE or SIMULATE ANY OPERATION or DATA. Make ONLY THE MINIMAL, SURGICAL CHANGES required. Do not modify or rewrite any portion of the app outside scope.

### 16. QA Review - Documentation accuracy verification
**Act as an Objective Rust Expert QA reviewer:**
- Verify documentation matches actual behavior
- Verify no misleading statements remain
- Verify examples work as documented
- Rate documentation accuracy 1-10 with detailed reasoning

---

## Success Criteria

- ✅ Passphrase is never displayed in output (CRITICAL SECURITY)
- ✅ Module documentation accurately describes behavior
- ✅ Function documentation matches implementation
- ✅ Commands enum documentation is accurate
- ✅ Clean build with zero warnings
- ✅ All manual tests pass
- ✅ No security vulnerabilities
- ✅ Production-ready code quality

## Architecture Notes

**Security Model:**
- Passphrases must NEVER be displayed in output
- Sensitive data must be protected at all times
- User guidance should use placeholders, not actual secrets

**Documentation Standards:**
- Documentation must accurately describe implementation
- No misleading or incorrect claims
- Examples must be accurate and tested
- Technical details must be precise

**Code Quality:**
- Zero unwrap() or expect() in source code
- Comprehensive error handling
- Clear, accurate documentation
- Production-ready security practices
