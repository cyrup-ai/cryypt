# Implement Core Entropy System

## Description
Replace placeholder core entropy system with production-grade entropy collection and validation.

## Violation Details
- **File**: `key/src/entropy.rs:80`
- **Impact**: Security critical - compromised key generation affects all cryptographic operations
- **Issue**: Core entropy system has placeholder implementation

## Success Criteria
- [ ] Implement production-grade entropy collection from OS sources
- [ ] Implement entropy pooling with proper mixing
- [ ] Implement entropy quality validation and monitoring
- [ ] Support cross-platform entropy sources (macOS/Windows/Linux)
- [ ] Integrate with existing key generation systems
- [ ] Pass security-focused entropy validation tests
- [ ] Maintain async compliance (channel-based patterns)

## Technical Requirements
- Use OS entropy sources: `/dev/urandom` (Unix), `CryptGenRandom` (Windows), `SecRandomCopyBytes` (macOS)
- Implement entropy pooling with cryptographic mixing (e.g., HMAC-based extraction)
- Add entropy health monitoring and fallback strategies
- Implement proper entropy accumulation and estimation
- Follow "True async with channels" architecture - no `spawn_blocking`
- Ensure constant-time operations where applicable
- Use `zeroize` for sensitive entropy data

## Dependencies
- **Prerequisites**: 0_fix_common_infrastructure.md (for error handling)
- **Blocks**: 1_crypto_foundation/* tasks (all key operations depend on entropy)

## Files to Investigate
- `key/src/entropy.rs:80` - Main placeholder location
- `key/src/api/key_generator/entropy.rs` - Related entropy validation
- Platform-specific entropy source implementations
- Integration points with key generation systems

## Security Considerations
- Entropy must never be logged or exposed
- Implement proper entropy source validation  
- Ensure fallback strategies for entropy source failures
- Use cryptographically secure entropy mixing
- Validate entropy quality continuously

## Testing Strategy
- Unit tests for entropy collection from each platform
- Statistical tests for entropy quality (chi-square, frequency analysis)
- Integration tests with key generation systems
- Stress tests for entropy pool depletion/recovery
- Security-focused property testing

## Risk Assessment
- **Critical Risk**: Poor entropy affects all cryptographic security
- **Mitigation**: Implement with extensive testing and multiple entropy sources
- **Validation**: Statistical analysis of generated entropy quality