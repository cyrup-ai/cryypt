# Implement Complete Password Management Interface

## Description
Replace placeholder password interface that returns fake data with complete encrypted password storage backend.

## Violation Details
- **File**: `vault/src/tui/pass_interface.rs:32-65`
- **Impact**: Password management functionality completely non-functional
- **Issue**: All operations return fake data instead of real password storage

## Success Criteria
- [ ] Replace fake `list()` with real encrypted password storage query
- [ ] Replace fake `get()` with actual password retrieval and decryption
- [ ] Replace fake `search()` with real encrypted password database search
- [ ] Replace no-op `insert()` with actual encrypted password storage
- [ ] Implement `update()` and `delete()` operations
- [ ] Add password metadata (creation time, last modified, usage count)
- [ ] Implement secure password generation utilities

## Technical Requirements
- Use vault document storage for password entries
- Implement AES-GCM encryption for password content
- Store password metadata separately from encrypted content
- Implement secure search without full decryption
- Add password strength validation
- Support password categories and tagging
- Follow async patterns with proper error handling

## Dependencies
- **Prerequisites**:
  - 2_vault_backend/0_implement_document_operations.md
  - 2_vault_backend/1_implement_ttl_metadata.md (for password expiry)
  - 2_vault_backend/2_implement_config_system.md
- **Blocks**: TUI password management functionality

## Password Storage Schema
```rust
struct PasswordEntry {
    id: String,
    name: String,           // Site/service name
    username: Option<String>,
    encrypted_password: Vec<u8>,
    metadata: PasswordMetadata,
    tags: Vec<String>,
    created_at: SystemTime,
    updated_at: SystemTime,
    last_accessed: Option<SystemTime>,
}

struct PasswordMetadata {
    strength_score: u8,
    expiry_date: Option<SystemTime>,
    category: String,
    notes: Option<String>,
}
```

## Operations to Implement
1. **list()**: Query password entries with metadata (no decryption)
2. **get(name)**: Retrieve and decrypt specific password
3. **search(query)**: Search password names and metadata
4. **insert(name, password)**: Store encrypted password with validation
5. **update(name, password)**: Update existing password entry
6. **delete(name)**: Securely delete password entry
7. **generate_password(criteria)**: Generate secure passwords

## Security Requirements
- All passwords encrypted with unique per-entry keys
- Password keys derived from vault master key
- Secure deletion with key destruction
- Access audit logging for password operations
- Password strength validation and reporting

## Testing Strategy
- Unit tests for each password operation
- Integration tests with vault backend
- Security tests for encryption/decryption
- Performance tests with large password databases
- Usability tests for search and retrieval

## Risk Assessment
- **High Risk**: Password interface is primary user functionality
- **Mitigation**: Comprehensive security review and testing
- **Validation**: End-to-end password management workflow testing