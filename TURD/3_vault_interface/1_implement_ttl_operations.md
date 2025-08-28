# Implement TTL Operations Interface

## Description
Replace temporary TTL operations that ignore expiration with proper TTL-aware vault operations.

## Violation Details
- **File**: `vault/src/api/ttl_operations.rs:47-60`
- **Impact**: TTL security feature bypassed in user operations
- **Issue**: TTL operations return values without checking expiration because metadata storage not implemented

## Success Criteria
- [ ] Replace temporary TTL-unaware get operations
- [ ] Implement proper expiration checking in all read operations
- [ ] Add TTL-aware query operations
- [ ] Implement TTL status reporting
- [ ] Add automatic expiry warnings for near-expired entries
- [ ] Implement TTL batch operations
- [ ] Ensure consistent TTL behavior across all interfaces

## Technical Requirements
- Integrate with TTL metadata storage system
- Check expiry on all read operations before returning data
- Return appropriate errors for expired entries
- Implement TTL status queries (time remaining, expired status)
- Add TTL extension operations
- Follow async patterns with proper error handling
- Integrate with vault configuration system

## Dependencies
- **Prerequisites**: 
  - 2_vault_backend/1_implement_ttl_metadata.md (requires TTL metadata system)
  - 2_vault_backend/0_implement_document_operations.md
- **Blocks**: Complete vault TTL functionality

## TTL Operations to Implement
1. **get_with_ttl()**: Get value with TTL validation
2. **set_with_ttl()**: Store value with TTL
3. **extend_ttl()**: Extend TTL for existing entry
4. **get_ttl_status()**: Query TTL information
5. **list_expiring()**: List entries expiring soon
6. **cleanup_expired()**: Manual cleanup of expired entries

## TTL-Aware Query Integration
```rust
pub async fn get_with_ttl_check(&self, key: &str) -> VaultResult<Option<String>> {
    // Check TTL first
    if let Some(expiry) = self.get_ttl_expiry(key).await? {
        if expiry < SystemTime::now() {
            // Entry expired - return None and optionally cleanup
            self.cleanup_expired_entry(key).await?;
            return Ok(None);
        }
    }
    
    // TTL valid or no TTL - proceed with normal get
    self.vault.get(key).await
}
```

## Error Handling
- **ExpiredEntry**: Entry exists but has expired
- **TTLNotSet**: Operation requires TTL but none set
- **InvalidTTL**: TTL value is invalid or in the past
- **TTLMetadataError**: TTL metadata corruption or unavailability

## Testing Strategy
- Unit tests for each TTL operation
- Time-based testing with controlled clocks
- Integration tests with document storage
- Edge case testing (clock adjustments, expired entries)
- Performance testing for TTL checks

## Risk Assessment
- **Medium Risk**: TTL operations affect data availability
- **Mitigation**: Comprehensive time handling and testing
- **Validation**: End-to-end TTL workflow verification