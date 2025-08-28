# Connect Interface to Production Entropy Quality System

## Description
Wire the placeholder entropy quality verification in the interface layer to the existing production entropy quality system in `key/src/entropy.rs`.

## Current State Analysis  
- **Production Implementation**: `key/src/entropy.rs` contains complete entropy quality system with `verify_min_entropy()`, `estimate_entropy()`, NIST SP 800-90B methodology
- **Placeholder Interface**: `key/src/api/key_generator/entropy.rs:103` has placeholder `verify_entropy_quality()` method
- **Issue**: Interface method has empty implementation instead of connecting to production entropy validation

## Success Criteria
- [ ] Connect `EntropyProvider::verify_entropy_quality()` to production `EntropySource::estimate_entropy()`
- [ ] Use production entropy quality thresholds from `MIN_ENTROPY_THRESHOLD`
- [ ] Integrate with production NIST SP 800-90B methodology
- [ ] Ensure quality validation occurs in key generation workflows
- [ ] Maintain existing async patterns and error propagation

## Technical Implementation
Replace placeholder with connection to production system:

```rust  
// Current placeholder:
fn verify_entropy_quality(&self, _bytes: &[u8]) {
    // Implementation placeholder for entropy quality testing
    // Could include tests like:
    // - Frequency analysis
    // - Run tests  
    // - Chi-square tests
    // - Entropy estimation
}

// Connect to production:
fn verify_entropy_quality(&self, bytes: &[u8]) -> bool {
    use crate::entropy::{EntropySource, MIN_ENTROPY_THRESHOLD};
    
    // Use production entropy source for quality validation
    let mut entropy_source = match EntropySource::new() {
        Ok(source) => source,
        Err(_) => return false, // Failed to initialize quality validation
    };
    
    // Use production entropy estimation with NIST methodology
    let estimated_entropy = entropy_source.estimate_entropy(bytes);
    
    // Apply production quality threshold
    estimated_entropy >= MIN_ENTROPY_THRESHOLD
}
```

## Dependencies
- **Prerequisites**: 
  - 0_core_foundation/0_fix_common_infrastructure.md
  - 0_core_foundation/1_connect_entropy_system.md
- **Blocks**: All key generation operations that should use quality validation

## Files to Modify
- `key/src/api/key_generator/entropy.rs:103` - Connect placeholder to production
- Ensure `EntropyProvider` integrates quality validation into key generation workflows
- Update any callers to handle boolean return value for quality checks

## Existing Production Code to Leverage
- `EntropySource::estimate_entropy()` - Shannon entropy calculation with production algorithms  
- `EntropySource::verify_min_entropy()` - NIST SP 800-90B methodology implementation
- `MIN_ENTROPY_THRESHOLD` - Production-tested quality threshold (7.8 bits per byte)
- `EntropySource::new()` - Quality-verified entropy source initialization

## Integration Points
- Connect quality validation to `EntropyProvider::fill_bytes()` 
- Ensure key generation workflows use quality-validated entropy
- Integrate with existing entropy configuration (`EntropyConfig::test_entropy_quality`)

## Quality Validation Strategy
1. **Statistical Analysis**: Use production Shannon entropy estimation
2. **Threshold Enforcement**: Apply production `MIN_ENTROPY_THRESHOLD`  
3. **Integration**: Wire into key generation workflows
4. **Error Handling**: Proper error propagation for quality failures

## Testing Strategy
- Verify quality validation rejects low-entropy input
- Test integration with key generation workflows
- Ensure production entropy thresholds are properly applied
- Validate error handling for quality validation failures

## Risk Assessment
- **Very Low Risk**: Connecting to existing tested production entropy system
- **Validation**: Production entropy system already has comprehensive NIST-based validation