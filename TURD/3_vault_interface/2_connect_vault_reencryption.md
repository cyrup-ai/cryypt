# Connect Interface to Production Re-encryption Systems

## Description
Wire the placeholder vault re-encryption method to existing production key derivation and document re-encryption capabilities.

## Current State Analysis
- **Production Key Derivation**: `key/src/api/key_generator/derive/` contains complete key derivation with `specialized.rs`, `core.rs`, `config.rs`
- **Production Document System**: `vault/src/db/document.rs` has `DocumentDao` for document operations
- **Production Cipher System**: Cipher crate has complete AES-GCM, ChaCha20-Poly1305 encryption/decryption
- **Production Passphrase Handling**: `vault/src/db/vault_store/backend/passphrase.rs`, `auth/passphrase.rs` contain passphrase management
- **Placeholder Interface**: `vault/src/db/vault_store/backend/operations/crud.rs:170` returns `Ok(())` without re-encryption
- **Issue**: Method doesn't connect to production re-encryption capabilities

## Success Criteria  
- [ ] Connect `re_encrypt_with_new_passphrase()` to production key derivation system
- [ ] Use production `DocumentDao` to stream through all vault documents
- [ ] Integrate with production cipher system for decrypt-with-old/encrypt-with-new pattern
- [ ] Use production passphrase validation from auth system
- [ ] Ensure atomic operations using existing transaction capabilities
- [ ] Integrate with production backup systems if available

## Technical Implementation
Connect to production systems:

```rust
// Current placeholder:
pub async fn re_encrypt_with_new_passphrase(
    &self,
    _old_passphrase: &str, 
    _new_passphrase: &str,
) -> VaultResult<()> {
    Ok(()) // Placeholder
}

// Connect to production:
pub async fn re_encrypt_with_new_passphrase(
    &self,
    old_passphrase: &str,
    new_passphrase: &str,
) -> VaultResult<()> {
    use crate::db::document::DocumentDao;
    use crate::db::vault_store::backend::passphrase::PassphraseManager;
    use key::api::key_generator::derive::specialized::derive_key_from_password;
    
    // Validate passphrases using production validation
    let passphrase_mgr = PassphraseManager::new();
    passphrase_mgr.validate_passphrase(new_passphrase)?;
    
    // Derive keys using production key derivation
    let old_key = derive_key_from_password(old_passphrase, "vault", 32)?;
    let new_key = derive_key_from_password(new_passphrase, "vault", 32)?;
    
    // Use production DocumentDao to process all vault documents
    let dao = DocumentDao::new(self.db.clone());
    let documents = dao.list_all().await?;
    
    for mut doc in documents {
        // Decrypt with old key, encrypt with new key using production cipher
        let decrypted = self.decrypt_document_content(&doc.content, &old_key)?;
        let re_encrypted = self.encrypt_document_content(&decrypted, &new_key)?;
        
        doc.content = re_encrypted;
        doc.updated_at = Some(chrono::Utc::now());
        
        // Save using production DocumentDao
        dao.save(doc).await?;
    }
    
    Ok(())
}
```

## Dependencies
- **Prerequisites**:
  - 2_vault_backend/0_connect_document_operations.md (document operations)
  - 1_crypto_foundation/* (key derivation and encryption)
  - 2_vault_backend/2_implement_config_system.md (for backup configuration)
- **Blocks**: Complete vault security lifecycle management

## Files to Modify
- `vault/src/db/vault_store/backend/operations/crud.rs:170` - Connect to production systems
- Integrate with existing passphrase management infrastructure
- Use production key derivation and cipher systems

## Existing Production Code to Leverage  
- `key/src/api/key_generator/derive/specialized.rs` - Password-based key derivation
- `key/src/api/key_generator/derive/core.rs` - Core key derivation functionality
- `DocumentDao::list_all()`, `save()` - Document streaming and updates
- `vault/src/db/vault_store/backend/passphrase.rs` - Passphrase management
- `vault/src/db/vault_store/backend/auth/passphrase.rs` - Passphrase authentication
- Production cipher systems for encryption/decryption operations
- Document timestamp management in `DocumentDao`

## Re-encryption Strategy
1. **Validation**: Use production passphrase validation
2. **Key Derivation**: Use production password-based key derivation
3. **Document Processing**: Stream through documents using production `DocumentDao`  
4. **Encryption**: Use production cipher system for decrypt/encrypt operations
5. **Persistence**: Use production document save with timestamp updates
6. **Error Handling**: Leverage production error types and recovery

## Testing Strategy
- Verify re-encryption with production key derivation
- Test document streaming and processing
- Ensure cipher integration for decrypt/encrypt operations
- Validate passphrase management integration
- Test atomic operations and error recovery

## Risk Assessment
- **Medium Risk**: Complex operation but using existing production components
- **Mitigation**: Each component already tested individually in production
- **Validation**: Integration testing with small vault datasets first