# Fix Error Recovery Logic

## Description
Replace overly permissive error retry logic with proper error categorization and retry policies.

## Violation Details
- **File**: `vault/src/api/error_recovery.rs:56`
- **Impact**: Improper error handling affects vault reliability
- **Issue**: `is_retryable()` returns `true` for all errors without proper analysis

## Success Criteria
- [ ] Implement proper error categorization system
- [ ] Create retry policies based on error types
- [ ] Distinguish between retryable and permanent failures
- [ ] Implement exponential backoff for retryable errors
- [ ] Add retry attempt limits
- [ ] Implement circuit breaker pattern for recurring failures
- [ ] Add comprehensive error logging and metrics

## Technical Requirements
- Categorize errors into retryable vs permanent
- Implement different retry strategies per error type
- Add exponential backoff with jitter
- Implement circuit breaker for cascading failures
- Create error recovery metrics and monitoring
- Use proper error handling from common infrastructure
- Follow async patterns for retry operations

## Dependencies
- **Prerequisites**: 
  - 0_core_foundation/0_fix_common_infrastructure.md
  - 2_vault_backend/2_implement_config_system.md (for retry configuration)
- **Blocks**: Reliable vault error handling

## Error Categories
1. **Network Errors** (Retryable):
   - Connection timeouts
   - Temporary network failures
   - DNS resolution failures
   - Rate limiting responses

2. **Database Errors** (Mixed):
   - Connection pool exhausted (retryable)
   - Database temporarily unavailable (retryable)
   - Constraint violations (permanent)
   - Data corruption (permanent)

3. **Authentication Errors** (Permanent):
   - Invalid credentials
   - Expired tokens
   - Permission denied

4. **Validation Errors** (Permanent):
   - Invalid input data
   - Schema validation failures
   - Business rule violations

5. **System Errors** (Mixed):
   - Out of memory (retryable after delay)
   - Disk full (retryable after cleanup)
   - Permission denied (permanent)

## Error Recovery Implementation
```rust
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
    backoff_multiplier: f64,
    jitter: bool,
}

impl ErrorRecovery {
    pub fn is_retryable(&self, error: &VaultError) -> bool {
        match error {
            VaultError::Network(_) => true,
            VaultError::Database(db_err) => self.is_db_error_retryable(db_err),
            VaultError::Authentication(_) => false,
            VaultError::Validation(_) => false,
            VaultError::System(sys_err) => self.is_system_error_retryable(sys_err),
            _ => false,
        }
    }
    
    pub async fn retry_with_policy<T, F, Fut>(
        &self,
        operation: F,
        policy: &RetryPolicy
    ) -> Result<T, VaultError> 
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, VaultError>>,
    {
        // Implementation with exponential backoff and circuit breaker
    }
}
```

## Circuit Breaker Integration
- Track failure rates per operation type
- Open circuit after threshold failures
- Half-open circuit for test requests
- Close circuit after successful operations

## Testing Strategy
- Unit tests for error categorization
- Integration tests with simulated failures
- Load testing for circuit breaker behavior
- Retry policy validation with different error types

## Risk Assessment
- **Medium Risk**: Poor error recovery affects vault reliability
- **Mitigation**: Comprehensive error categorization and testing
- **Validation**: Error recovery behavior verification under load