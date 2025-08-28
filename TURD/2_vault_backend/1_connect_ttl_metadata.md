# Connect Interface to Production TTL System

## Description
Wire the placeholder TTL operations to the existing production TTL system in `vault/src/db/vault_store/cache.rs` and related TTL infrastructure.

## Current State Analysis
- **Production Implementation**: `vault/src/db/vault_store/cache.rs` contains complete TTL system with expiration checking, timestamp management, `CacheEntry::is_expired()`
- **Additional TTL Code**: TTL functionality exists in `vault/src/core/vault.rs`, `cipher/src/cipher/nonce.rs`, `quic/src/keys.rs`
- **Placeholder Interface**: `vault/src/db/vault_store/backend/operations/crud.rs:154-170` has placeholder `set_expiry()`, `remove_expiry()` methods
- **Issue**: Interface methods return `Ok(())` without connecting to production TTL system

## Success Criteria
- [ ] Connect `set_expiry()` to production TTL metadata storage
- [ ] Connect `remove_expiry()` to production TTL cleanup
- [ ] Wire TTL checking into all read operations using existing `is_expired()` logic
- [ ] Ensure TTL operations use existing `CacheEntry` and timestamp infrastructure
- [ ] Integrate with production cache TTL configuration

## Technical Implementation
Connect placeholder operations to production TTL system:

```rust
// Current placeholder:
pub async fn set_expiry(&self, _key: &str, _expiry: SystemTime) -> VaultResult<()> {
    Ok(()) // Placeholder
}

// Connect to production:
pub async fn set_expiry(&self, key: &str, expiry: SystemTime) -> VaultResult<()> {
    use crate::db::vault_store::cache::CacheEntry;
    
    // Calculate TTL seconds from current time
    let now = SystemTime::now();
    let ttl_seconds = expiry.duration_since(now)?.as_secs();
    
    // Update cache entry with TTL using existing infrastructure
    if let Some(entry) = self.cache.get(key) {
        // Use production TTL system
        let updated_entry = CacheEntry::new(entry.encrypted_value.clone(), ttl_seconds);
        self.cache.insert(key.to_string(), updated_entry);
    }
    
    Ok(())
}
```

## Dependencies
- **Prerequisites**: 
  - 0_core_foundation/0_fix_common_infrastructure.md
  - 2_vault_backend/0_connect_document_operations.md
- **Blocks**: 3_vault_interface/1_connect_ttl_operations.md

## Files to Modify
- `vault/src/db/vault_store/backend/operations/crud.rs:154-170` - Connect placeholders to production
- Ensure integration with existing `CacheConfig` TTL settings
- Wire TTL checking into read operations

## Existing Production Code to Leverage
- `CacheEntry::is_expired()` - Production expiration checking
- `CacheEntry::new(encrypted_value, ttl_seconds)` - TTL-aware cache entry creation
- `current_timestamp()` helper function - Timestamp utilities
- `CacheConfig::ttl_seconds` - TTL configuration
- TTL infrastructure in vault core, cipher nonce management, QUIC keys

## Integration Points
- Cache layer already has comprehensive TTL support
- Nonce management already has TTL for replay protection
- QUIC keys already have TTL for key rotation
- Need to connect CRUD operations to this existing infrastructure

## Testing Strategy
- Verify TTL operations integrate with existing cache system
- Test expiration checking uses production `is_expired()` logic
- Ensure TTL configuration is consistent across systems
- Validate TTL metadata persists correctly

## Risk Assessment
- **Low Risk**: Connecting to existing comprehensive TTL infrastructure
- **Validation**: Production TTL systems already operational in cache, nonce, and QUIC layers