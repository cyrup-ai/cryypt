# Remove Backup Files with TODO Comments

## Description
Remove backup/unused files that contain TODO comments and are not part of the production codebase.

## Violation Details
- **File**: `pqcrypto/src/api/signature_builder/mod_backup.rs:178`
- **Impact**: Code clutter and potential confusion
- **Issue**: TODO comment in backup/unused file

## Success Criteria
- [ ] Identify all backup files in the codebase
- [ ] Verify backup files are not referenced by production code
- [ ] Remove backup files or complete their TODO implementations
- [ ] Update any import statements that reference removed files
- [ ] Clean up any related test files
- [ ] Ensure cargo check passes after removal

## Technical Requirements
- Search for files with "_backup", "_old", or similar naming patterns
- Verify files are not imported or used by production code
- Check for any related documentation that references removed files
- Ensure removal doesn't break existing functionality
- Update any build scripts or configuration that might reference files

## Dependencies
- **Prerequisites**: None (independent cleanup task)
- **Blocks**: None (this is a cleanup task)

## Files to Investigate
- `pqcrypto/src/api/signature_builder/mod_backup.rs` - Confirmed backup file
- Search for other files with backup naming patterns
- Check for other unused/experimental files

## Cleanup Process
1. **Discovery Phase**:
   - Search for backup files across the codebase
   - Identify unused experimental files
   - Check git history for abandoned feature branches

2. **Verification Phase**:
   - Verify files are not imported anywhere
   - Check for references in documentation
   - Ensure no tests depend on backup files

3. **Removal Phase**:
   - Remove identified backup files
   - Clean up any related imports
   - Update module declarations

4. **Validation Phase**:
   - Run cargo check to ensure no broken imports
   - Run tests to ensure functionality preserved
   - Verify documentation still accurate

## Testing Strategy
- Compile entire workspace after file removal
- Run all tests to ensure no missing dependencies
- Check for any broken documentation links
- Validate that cargo clippy passes

## Risk Assessment
- **Low Risk**: Backup files should not be in production use
- **Mitigation**: Careful verification before removal
- **Rollback**: Git history preserves removed files if needed

## Alternative: Complete TODO Implementation
If backup files contain valuable incomplete work:
- Evaluate TODO comments for implementation value
- Complete implementations if they add production value
- Move completed implementations to main files
- Remove backup designation and integrate properly