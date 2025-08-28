# Connect Interface to Production Document Storage

## Description
Wire the placeholder document operations interface to the existing production `DocumentDao` implementation in `vault/src/db/document.rs`.

## Current State Analysis
- **Production Implementation**: `vault/src/db/document.rs` contains complete `DocumentDao` with SurrealDB integration, full CRUD operations, metadata handling
- **Placeholder Interface**: `vault/src/db/dao/documents/core.rs:226` has placeholder document operations
- **Issue**: Interface layer not connected to production document storage system

## Success Criteria
- [ ] Connect placeholder document operations to production `DocumentDao`
- [ ] Wire CRUD operations to use `DocumentDao::save()`, `find_by_key()`, `delete_by_key()`, etc.
- [ ] Ensure proper error handling integration with production system
- [ ] Maintain existing async patterns and SurrealDB integration
- [ ] Verify document encryption works with existing production methods

## Technical Implementation
Connect interface operations to production `DocumentDao`:

```rust
// Current placeholder - needs connection to production
impl DocumentOperations {
    pub async fn create_document(&self, key: &str, content: &str) -> VaultResult<()> {
        use crate::db::document::{Document, DocumentDao};
        
        let doc = Document {
            id: None,
            key: key.to_string(),
            content: content.to_string(),
            metadata: serde_json::Value::Null,
            created_at: None,
            updated_at: None,
            tags: vec![],
        };
        
        let dao = DocumentDao::new(self.db.clone());
        dao.save(doc).await?;
        Ok(())
    }
}
```

## Dependencies  
- **Prerequisites**:
  - 0_core_foundation/0_fix_common_infrastructure.md
  - SurrealDB connection already established
- **Blocks**: 3_vault_interface/* tasks depend on document operations

## Files to Modify
- `vault/src/db/dao/documents/core.rs:226` - Connect to production `DocumentDao`
- Verify imports and database connection are properly shared
- Ensure error handling is consistent

## Existing Production Code to Leverage
- `DocumentDao::new()` - Database connection setup
- `DocumentDao::save()` - Document creation/update with timestamps
- `DocumentDao::find_by_key()` - Document retrieval
- `DocumentDao::delete_by_key()` - Secure document deletion
- `DocumentDao::list_all()` - Document listing
- `DocumentDao::find_by_pattern()` - Document search functionality
- Complete `Document` struct with metadata, tags, timestamps

## Testing Strategy
- Verify document CRUD operations work through interface
- Test document metadata and timestamp handling
- Ensure SurrealDB integration remains functional
- Validate error propagation from production to interface

## Risk Assessment
- **Low Risk**: Connecting to existing tested production implementation
- **Validation**: Production document system already has comprehensive SurrealDB integration