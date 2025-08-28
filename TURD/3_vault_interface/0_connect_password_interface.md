# Connect Password Interface to Production Storage

## Description  
Wire the placeholder password interface methods to the existing production document storage and TUI password management systems.

## Current State Analysis
- **Production Implementation**: `vault/src/tui/tabs/pass.rs` contains complete password TUI with listing, viewing, searching, content loading
- **Production Document System**: `vault/src/db/document.rs` has full `DocumentDao` for encrypted document storage  
- **Production Password Types**: `vault/src/tui/types.rs` has password state management
- **Placeholder Interface**: `vault/src/tui/pass_interface.rs:32-65` returns fake data instead of connecting to production systems
- **Issue**: Interface methods return hardcoded fake data rather than using production storage

## Success Criteria
- [ ] Connect `list()` to production document storage for password entries
- [ ] Connect `get()` to production encrypted document retrieval and decryption
- [ ] Connect `search()` to production `DocumentDao::find_by_pattern()`
- [ ] Connect `insert()` to production encrypted document storage via `DocumentDao::save()`
- [ ] Ensure password entries use proper encryption from production cipher systems
- [ ] Integrate with existing TUI password management workflow

## Technical Implementation
Connect placeholder methods to production systems:

```rust
// Current placeholder:
pub fn list(&self) -> VaultResult<Vec<String>> {
    Ok(vec!["example.com".to_string(), "github.com".to_string(), "gitlab.com".to_string()])
}

// Connect to production:
pub async fn list(&self) -> VaultResult<Vec<String>> {
    use crate::db::document::DocumentDao;
    
    let dao = DocumentDao::new(self.db.clone());
    let docs = dao.list_all().await?;
    
    // Filter for password documents and extract keys
    let passwords = docs.into_iter()
        .filter(|doc| doc.tags.contains(&"password".to_string()))
        .map(|doc| doc.key)
        .collect();
        
    Ok(passwords)
}

pub async fn get(&self, name: &str) -> VaultResult<String> {
    use crate::db::document::DocumentDao;
    
    let dao = DocumentDao::new(self.db.clone());
    if let Some(doc) = dao.find_by_key(name.to_string()).await? {
        // Use production decryption from cipher system
        let decrypted = self.decrypt_password_content(&doc.content)?;
        Ok(decrypted)
    } else {
        Err(VaultError::NotFound(format!("Password {} not found", name)))
    }
}
```

## Dependencies
- **Prerequisites**: 
  - 2_vault_backend/0_connect_document_operations.md (document storage)
  - 1_crypto_foundation/* (for encryption/decryption)
- **Blocks**: Complete TUI password management functionality

## Files to Modify
- `vault/src/tui/pass_interface.rs:32-65` - Replace all fake data with production calls
- Ensure integration with `DocumentDao` for storage
- Connect to production cipher system for password encryption/decryption

## Existing Production Code to Leverage
- `DocumentDao` - Complete encrypted document storage system
- `vault/src/tui/tabs/pass.rs` - Full TUI implementation that already calls this interface
- `vault/src/tui/types.rs` - Password state management
- Production cipher systems for password encryption/decryption
- Document tagging system for password categorization

## Integration Strategy
1. **Storage Layer**: Use `DocumentDao` with "password" tag for password documents
2. **Encryption Layer**: Use production cipher system for password content encryption
3. **Search Layer**: Leverage `DocumentDao::find_by_pattern()` for password search
4. **Metadata Layer**: Use document metadata for password properties (creation time, etc.)

## Testing Strategy
- Verify password CRUD operations work through TUI
- Test password encryption/decryption with production cipher system
- Ensure search functionality works with document storage
- Validate integration with existing TUI workflow

## Risk Assessment  
- **Low Risk**: Connecting to existing tested production implementations
- **Validation**: TUI already expects this interface to work - just need to connect the wiring