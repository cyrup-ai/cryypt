# Implement Vault Re-encryption with New Passphrase

## Description
Replace placeholder vault re-encryption operation with secure passphrase transition functionality.

## Violation Details
- **File**: `vault/src/db/vault_store/backend/operations/crud.rs:170`
- **Impact**: Critical security operation non-functional
- **Issue**: `re_encrypt_with_new_passphrase()` returns Ok(()) without re-encrypting vault data

## Success Criteria
- [ ] Implement secure vault re-encryption process
- [ ] Support atomic passphrase transition (rollback on failure)
- [ ] Re-encrypt all vault documents with new key derivation
- [ ] Update TTL metadata encryption if applicable
- [ ] Implement progress reporting for large vaults
- [ ] Ensure old passphrase invalidation
- [ ] Add backup creation before re-encryption

## Technical Requirements
- Derive new encryption keys from new passphrase
- Re-encrypt all stored documents atomically
- Handle large vaults with streaming re-encryption
- Implement rollback mechanism for failed re-encryption
- Create vault backup before starting process
- Validate new passphrase strength requirements
- Follow async patterns with progress reporting
- Ensure secure cleanup of old key material

## Dependencies
- **Prerequisites**:
  - 2_vault_backend/0_implement_document_operations.md
  - 2_vault_backend/1_implement_ttl_metadata.md  
  - 2_vault_backend/2_implement_config_system.md
  - 0_core_foundation/* (for key derivation)
- **Blocks**: Complete vault security lifecycle management

## Re-encryption Process
1. **Validation Phase**:
   - Validate new passphrase strength
   - Verify current passphrase
   - Check vault integrity

2. **Preparation Phase**:
   - Create vault backup
   - Derive new encryption keys
   - Initialize progress tracking

3. **Re-encryption Phase**:
   - Stream through all vault entries
   - Decrypt with old key, encrypt with new key
   - Update entry atomically
   - Report progress

4. **Finalization Phase**:
   - Validate all entries re-encrypted
   - Secure cleanup of old keys
   - Update vault metadata
   - Remove backup on success

## Atomic Re-encryption Strategy
```rust
pub async fn re_encrypt_with_new_passphrase(
    &self,
    old_passphrase: &str,
    new_passphrase: &str,
    progress_callback: Option<Box<dyn Fn(f32)>>
) -> VaultResult<()> {
    // 1. Create transaction/backup point
    let backup = self.create_backup().await?;
    
    // 2. Derive new keys
    let new_keys = self.derive_keys(new_passphrase).await?;
    
    // 3. Re-encrypt all entries
    let mut progress = 0.0;
    let total_entries = self.count_entries().await?;
    
    for entry in self.stream_all_entries().await? {
        let decrypted = self.decrypt_entry(&entry, old_passphrase).await?;
        let re_encrypted = self.encrypt_entry(&decrypted, &new_keys).await?;
        self.update_entry_atomic(&entry.id, re_encrypted).await?;
        
        progress += 1.0 / total_entries as f32;
        if let Some(callback) = &progress_callback {
            callback(progress);
        }
    }
    
    // 4. Cleanup and finalize
    self.cleanup_old_keys().await?;
    self.remove_backup(backup).await?;
    
    Ok(())
}
```

## Error Handling and Recovery
- **PassphraseValidationFailed**: New passphrase doesn't meet requirements
- **ReEncryptionFailed**: Re-encryption process failed, rollback triggered
- **BackupCreationFailed**: Cannot create backup, operation aborted
- **KeyDerivationFailed**: Cannot derive new keys from passphrase

## Testing Strategy
- Unit tests for each phase of re-encryption
- Integration tests with various vault sizes
- Failure scenario testing with rollback verification
- Performance testing with large vaults
- Security testing for key material handling

## Risk Assessment
- **Critical Risk**: Re-encryption failure could corrupt entire vault
- **Mitigation**: Atomic operations with backup and rollback
- **Validation**: Comprehensive testing with vault integrity verification