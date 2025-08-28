# Implement TTL Metadata Storage System

## Description
Implement complete TTL (Time-To-Live) metadata storage in SurrealDB with expiry tracking and automatic cleanup.

## Violation Details
- **Files**: 
  - `vault/src/db/vault_store/backend/operations/crud.rs:154-170`
  - `vault/src/api/ttl_operations.rs:47-60`
- **Impact**: Critical security feature non-functional
- **Issue**: TTL operations return success without implementing metadata storage or expiry checking

## Success Criteria
- [ ] Design TTL metadata schema in SurrealDB
- [ ] Implement `set_expiry()` with actual metadata storage
- [ ] Implement `remove_expiry()` with metadata deletion
- [ ] Add expiry checking to all read operations
- [ ] Implement automatic cleanup of expired entries
- [ ] Add TTL monitoring and reporting
- [ ] Ensure atomic TTL operations

## Technical Requirements
- Design SurrealDB schema for TTL metadata
- Implement TTL metadata CRUD operations
- Add expiry validation to all vault read operations
- Create background cleanup service for expired entries
- Implement TTL-aware query operations
- Use proper time handling (UTC, monotonic clocks)
- Follow async patterns with channels

## Dependencies
- **Prerequisites**:
  - 0_core_foundation/0_fix_common_infrastructure.md
  - 2_vault_backend/0_implement_document_operations.md
- **Blocks**: 
  - 3_vault_interface/1_implement_ttl_operations.md
  - 3_vault_interface/2_implement_vault_reencryption.md

## Database Schema Design
```sql
-- TTL metadata table
CREATE TABLE ttl_metadata (
    key_id STRING,
    expires_at DATETIME,
    created_at DATETIME,
    updated_at DATETIME
);

-- Indexes for efficient expiry queries
CREATE INDEX idx_expires_at ON ttl_metadata(expires_at);
CREATE INDEX idx_key_id ON ttl_metadata(key_id);
```

## Implementation Tasks
1. **TTL Metadata CRUD**:
   - Create TTL entry with expiry time
   - Update TTL expiry time
   - Delete TTL metadata
   - Query TTL status

2. **Expiry Integration**:
   - Check expiry on all read operations
   - Return appropriate errors for expired entries
   - Update TTL access timestamps if needed

3. **Cleanup Service**:
   - Background task for expired entry cleanup
   - Configurable cleanup intervals
   - Metrics for cleanup operations
   - Graceful cleanup with rate limiting

## Testing Strategy
- Unit tests for TTL metadata operations
- Integration tests with document storage
- Time-based testing with controlled clocks
- Performance tests for cleanup operations
- Edge case testing (clock adjustments, etc.)

## Risk Assessment
- **Medium Risk**: TTL is security feature but not foundation-critical
- **Mitigation**: Thorough testing with time handling
- **Validation**: End-to-end TTL lifecycle testing