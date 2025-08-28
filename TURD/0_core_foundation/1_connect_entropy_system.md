# Connect Interface to Production Entropy System

## Description
Wire the placeholder entropy quality verification interface to the existing production `EntropySource` implementation in `key/src/entropy.rs`.

## Current State Analysis
- **Production Implementation**: `key/src/entropy.rs` contains complete `EntropySource` with NIST SP 800-90B methodology, quality verification, Shannon entropy estimation
- **Placeholder Interface**: `key/src/api/key_generator/entropy.rs:103` has placeholder `verify_entropy_quality()` method
- **Issue**: Interface method not connected to production implementation

## Success Criteria
- [ ] Connect `EntropyProvider::verify_entropy_quality()` to `EntropySource::verify_min_entropy()`  
- [ ] Ensure interface uses production entropy quality thresholds
- [ ] Wire interface to use production `EntropySource::estimate_entropy()` method
- [ ] Maintain existing async patterns and error handling
- [ ] Verify all entropy generation uses production quality validation

## Technical Implementation
Replace placeholder method in `key/src/api/key_generator/entropy.rs`:

```rust
// Current placeholder:
fn verify_entropy_quality(&self, _bytes: &[u8]) {
    // Implementation placeholder for entropy quality testing
}

// Connect to production:
fn verify_entropy_quality(&self, bytes: &[u8]) -> bool {
    use crate::entropy::EntropySource;
    let mut source = EntropySource::new().expect("Failed to initialize entropy source");
    
    // Use production entropy estimation
    let entropy = source.estimate_entropy(bytes);
    entropy >= 7.8 // Use same threshold as production MIN_ENTROPY_THRESHOLD
}
```

## Dependencies
- **Prerequisites**: 0_fix_common_infrastructure.md (for error handling)
- **Blocks**: 1_crypto_foundation/* tasks (entropy quality validation needed)

## Files to Modify
- `key/src/api/key_generator/entropy.rs:103` - Connect placeholder to production
- Verify imports and error handling are consistent
- Ensure `EntropyProvider` uses `EntropySource` internally

## Existing Production Code to Leverage
- `EntropySource::new()` - Quality-verified entropy initialization
- `EntropySource::verify_min_entropy()` - NIST methodology implementation  
- `EntropySource::estimate_entropy()` - Shannon entropy calculation
- `MIN_ENTROPY_THRESHOLD` constant - Production quality threshold

## Testing Strategy
- Verify interface now uses production quality validation
- Test that low-quality entropy is properly rejected
- Ensure existing entropy generation still works
- Validate error handling integration

## Risk Assessment
- **Low Risk**: Connecting to existing tested production implementation
- **Validation**: Production entropy system already has comprehensive quality validation