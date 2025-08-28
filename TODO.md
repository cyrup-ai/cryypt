# CRYYPT WORKSPACE PRODUCTION QUALITY TODO

## OBJECTIVE: ACHIEVE ABSOLUTE ZERO ERRORS AND ZERO WARNINGS ACROSS ENTIRE WORKSPACE

### Previously Completed (RSA v0.10.0-rc.4 Upgrade Foundation)
- ✅ RSA crate upgrade from v0.9.8 to v0.10.0-rc.4
- ✅ All dependency version conflicts resolved
- ✅ Basic compilation errors fixed (cargo check --workspace passes)
- ✅ Runtime warnings in key crate fixed
- ✅ Initial clippy errors in common/async_task crates fixed
- ✅ Transform macro redundant field name issues partially addressed

## CURRENT PHASE: SYSTEMATIC CLIPPY ERROR ELIMINATION (104 TOTAL ERRORS)

**Architecture Context**: Modular cryptographic workspace with sophisticated immutable builder patterns, type-state enforcement, result handlers with `.on_result()` and `.on_chunk()` patterns, feature-gated algorithms, and streaming support.

---

## PHASE 1: HASHING CRATE CLIPPY COMPLIANCE (14 errors)

### Fix Redundant Field Names Errors
- [ ] **File**: `hashing/src/api/blake3_builder.rs:40`
  - **Issue**: `clippy::redundant_field_names` - `handler: transform_on_result!(handler)` is redundant
  - **Fix**: Replace with `handler` (since transform_on_result! macro is identity function)
  - **Architecture Note**: Maintains Blake3WithHandler struct builder pattern integrity
  - **Constraint**: Zero allocation, no unsafe, preserve ergonomic API

- [ ] **File**: `hashing/src/api/blake3_builder.rs:50` 
  - **Issue**: `clippy::redundant_field_names` - `handler: transform_on_chunk!(handler)` is redundant
  - **Fix**: Replace with `handler` in Blake3WithChunkHandler struct
  - **Architecture Note**: Preserves chunk-based streaming functionality
  - **Constraint**: Maintain blazing-fast performance for large data processing

### Add Missing Default Implementations
- [ ] **File**: `hashing/src/api/blake2b_builder.rs:37`
  - **Issue**: `clippy::new_without_default` - Blake2bBuilder lacks Default implementation
  - **Fix**: Add `impl Default for Blake2bBuilder { fn default() -> Self { Self::new() } }`
  - **Architecture Note**: Enables ergonomic initialization patterns while preserving builder state transitions
  - **Performance**: Zero allocation default construction

- [ ] **File**: `hashing/src/api/blake3_builder.rs:27`
  - **Issue**: `clippy::new_without_default` - Blake3Builder lacks Default implementation  
  - **Fix**: Add Default trait implementation calling new()
  - **Architecture Note**: Consistent with other hash algorithm builders
  - **Constraint**: No locking, no unsafe operations

- [ ] **File**: `hashing/src/api/sha256_builder.rs:37`
  - **Issue**: `clippy::new_without_default` - Sha256Builder lacks Default
  - **Fix**: Implement Default trait
  - **Architecture Note**: Maintains SHA-256 builder pattern consistency
  - **Performance**: Inlined default construction for hot paths

- [ ] **File**: `hashing/src/api/sha3_builder.rs:25`
  - **Issue**: `clippy::new_without_default` - Sha3_256Builder lacks Default
  - **Fix**: Implement Default trait
  - **Architecture Note**: SHA-3 variant builder consistency
  - **Optimization**: Zero overhead initialization

- [ ] **File**: `hashing/src/api/sha3_builder.rs:172`
  - **Issue**: `clippy::new_without_default` - Sha3_384Builder lacks Default
  - **Fix**: Implement Default trait
  - **Architecture Note**: Mid-level SHA-3 security variant support
  - **Constraint**: Elegant ergonomic code patterns

- [ ] **File**: `hashing/src/api/sha3_builder.rs:232`
  - **Issue**: `clippy::new_without_default` - Sha3_512Builder lacks Default  
  - **Fix**: Implement Default trait
  - **Architecture Note**: High-security SHA-3 variant consistency
  - **Performance**: Optimized for minimal allocation overhead

- [ ] **File**: `hashing/src/api/hash/algorithms/blake2b.rs:35`
  - **Issue**: `clippy::new_without_default` - Duplicate Blake2bBuilder in algorithms module
  - **Fix**: Implement Default trait
  - **Architecture Note**: Algorithm-specific module consistency
  - **Design**: Maintains modular hash algorithm organization

- [ ] **File**: `hashing/src/api/hash/algorithms/sha256.rs:44`
  - **Issue**: `clippy::new_without_default` - Algorithm-specific Sha256Builder
  - **Fix**: Implement Default trait  
  - **Architecture Note**: Preserves algorithm modularity design
  - **Constraint**: No unchecked operations, full error handling

### Fix Manual Division Ceiling and Other Issues
- [ ] **File**: `hashing/src/api/blake3_builder.rs:88`
  - **Issue**: `clippy::manual_div_ceil` - Manual ceiling division implementation
  - **Current**: `(data.len() + chunk_size - 1) / chunk_size`
  - **Fix**: Replace with `data.len().div_ceil(chunk_size)`
  - **Architecture Note**: Streaming hash computation optimization
  - **Performance**: Utilizes latest Rust stdlib optimizations for ceiling division
  - **Constraint**: Blazing-fast performance for large data chunks

- [ ] **File**: `key/src/api/key_retriever/store.rs:92`
  - **Issue**: `clippy::empty_line_after_doc_comments` - Formatting issue
  - **Fix**: Remove empty line after doc comment before function definition
  - **Architecture Note**: Key retrieval documentation consistency
  - **Style**: Maintains professional code formatting standards

---

## PHASE 2: JWT CRATE CLIPPY COMPLIANCE (35 errors)

### Fix Redundant Field Names in JWT Builders
- [ ] **File**: `jwt/src/api/algorithm_builders/hs256_builder.rs:82`
  - **Issue**: `clippy::redundant_field_names` - HMAC-SHA256 builder redundancy
  - **Fix**: Replace `handler: transform_on_result!(handler)` with `handler`
  - **Architecture Note**: JWT HMAC signing builder pattern preservation
  - **Constraint**: Cryptographically secure, zero allocation where possible

- [ ] **File**: `jwt/src/api/algorithm_builders/hs256_builder.rs:94` 
  - **Issue**: `clippy::redundant_field_names` - Chunk handler redundancy
  - **Fix**: Replace `handler: transform_on_chunk!(handler)` with `handler`
  - **Architecture Note**: Batch JWT processing capability maintenance
  - **Performance**: Optimized for high-throughput JWT operations

- [ ] **File**: `jwt/src/api/algorithm_builders/rs256_builder.rs:82`
  - **Issue**: `clippy::redundant_field_names` - RSA-SHA256 builder redundancy
  - **Fix**: Replace with `handler`
  - **Architecture Note**: RSA JWT signing with v0.10.0-rc.4 compatibility
  - **Security**: Maintains RSA cryptographic integrity

- [ ] **File**: `jwt/src/api/algorithm_builders/rs256_builder.rs:94`
  - **Issue**: `clippy::redundant_field_names` - RSA chunk handler redundancy  
  - **Fix**: Replace with `handler`
  - **Architecture Note**: Batch RSA JWT processing support
  - **Performance**: Optimized RSA operations with latest crate version

### Add Missing Default Implementations for JWT
- [ ] **File**: `jwt/src/api/algorithm_builders/hs256_builder.rs:48`
  - **Issue**: `clippy::new_without_default` - HsJwtBuilder lacks Default
  - **Fix**: Implement Default trait calling new()
  - **Architecture Note**: HMAC JWT builder ergonomic initialization
  - **Security**: Secure default initialization patterns

- [ ] **File**: `jwt/src/api/algorithm_builders/rs256_builder.rs:48`
  - **Issue**: `clippy::new_without_default` - RsJwtBuilder lacks Default
  - **Fix**: Implement Default trait calling new()
  - **Architecture Note**: RSA JWT builder initialization consistency
  - **Performance**: Zero overhead default construction

- [ ] **File**: `jwt/src/api/builders.rs:87`
  - **Issue**: `clippy::new_without_default` - JwtBuilder lacks Default
  - **Fix**: Implement Default trait calling new()
  - **Architecture Note**: Main JWT builder entry point consistency
  - **Design**: Maintains builder pattern fluent interface

### Fix JWT Collapsible If Statements
- [ ] **File**: `jwt/src/api/algorithms/utils.rs:65`
  - **Issue**: `clippy::collapsible_if` - JWT ID validation nested ifs
  - **Current**: `if let Some(jti) = obj.get("jti") { if !jti.is_string() { ... } }`
  - **Fix**: Combine with `if let Some(jti) = obj.get("jti") && !jti.is_string() { ... }`
  - **Architecture Note**: JWT claims validation optimization
  - **Performance**: Reduced branching for token validation hot path

- [ ] **File**: `jwt/src/api/algorithms/utils.rs:74`
  - **Issue**: `clippy::collapsible_if` - Issuer validation nested ifs
  - **Fix**: Combine nested if with && pattern for iss validation
  - **Architecture Note**: JWT issuer claim validation streamlining
  - **Security**: Maintains validation logic integrity

- [ ] **File**: `jwt/src/api/algorithms/utils.rs:83`
  - **Issue**: `clippy::collapsible_if` - Subject validation nested ifs
  - **Fix**: Combine with && pattern for sub validation
  - **Architecture Note**: JWT subject claim validation consistency
  - **Performance**: Optimized validation path

### Fix JWT API Method Names and Type Issues
- [ ] **File**: `jwt/src/api/builder.rs:26`
  - **Issue**: `clippy::new_ret_no_self` - Method named new() should return Self
  - **Current**: `pub fn new() -> JwtBuilder`
  - **Fix**: Either rename method or change return type to Self
  - **Architecture Note**: Builder pattern consistency with Rust conventions
  - **Design Decision**: Maintain API compatibility while fixing lint

- [ ] **File**: `jwt/src/api/builder.rs:58`
  - **Issue**: `clippy::new_ret_no_self` - Another new() method issue
  - **Fix**: Align with builder pattern conventions
  - **Architecture Note**: Secondary builder entry point consistency

- [ ] **File**: `jwt/src/api/builders.rs:16` and `jwt/src/api/builders.rs:38`
  - **Issue**: `clippy::new_ret_no_self` - Multiple new() method issues
  - **Fix**: Ensure all new() methods return appropriate Self types
  - **Architecture Note**: Comprehensive builder pattern compliance

### Fix JWT Type Complexity and Optimization Issues
- [ ] **File**: `jwt/src/api/claims/validator.rs:14`
  - **Issue**: `clippy::type_complexity` - Complex function pointer type
  - **Current**: `Vec<Box<dyn Fn(&Value) -> Result<(), JwtError> + Send + Sync>>`
  - **Fix**: Create type alias: `type CustomValidator = Box<dyn Fn(&Value) -> Result<(), JwtError> + Send + Sync>;`
  - **Architecture Note**: JWT claims validation system type clarification
  - **Performance**: No runtime overhead, improved code readability

- [ ] **File**: `jwt/src/api/claims/validator.rs:118`
  - **Issue**: `clippy::unnecessary_map_or` - Can be simplified
  - **Current**: `.any(|aud| aud.as_str().map_or(false, |s| s == expected_aud))`
  - **Fix**: `.any(|aud| aud.as_str().is_some_and(|s| s == expected_aud))`
  - **Architecture Note**: JWT audience validation optimization
  - **Performance**: More idiomatic and potentially faster validation

### Fix JWT Useless Conversions and Borrowing Issues
- [ ] **File**: `jwt/src/api/operations.rs:62`, `jwt/src/api/operations.rs:75`, `jwt/src/api/operations.rs:111`, `jwt/src/api/operations.rs:156`
  - **Issue**: `clippy::useless_conversion` - Unnecessary .into() calls
  - **Fix**: Remove `.into()` where error types are already correct
  - **Architecture Note**: JWT operation error handling streamlining
  - **Performance**: Eliminates unnecessary conversions

- [ ] **Files**: Multiple crypto files with `clippy::needless_borrow`
  - **Issue**: Unnecessary & references in function calls
  - **Fix**: Remove & where not needed (e.g., `std::str::from_utf8(&private_key)` → `std::str::from_utf8(private_key)`)
  - **Architecture Note**: Cryptographic operations optimization
  - **Performance**: Reduces unnecessary reference indirection

---

## PHASE 3: KEY CRATE CLIPPY COMPLIANCE (23 errors)

### Fix Redundant Field Names in Key Builders
- [ ] **File**: `key/src/api/algorithm_builders/aes_builder.rs:51`
  - **Issue**: `clippy::redundant_field_names` - AES key builder redundancy
  - **Fix**: Replace `handler: transform_on_result!(handler)` with `handler`
  - **Architecture Note**: AES key generation builder pattern maintenance
  - **Security**: Preserves AES cryptographic key generation integrity

- [ ] **File**: `key/src/api/algorithm_builders/aes_builder.rs:62`
  - **Issue**: `clippy::redundant_field_names` - AES chunk handler redundancy
  - **Fix**: Replace with `handler`
  - **Architecture Note**: Batch AES key generation support
  - **Performance**: Optimized for high-volume key generation scenarios

- [ ] **File**: `key/src/api/algorithm_builders/rsa_builder.rs:56`
  - **Issue**: `clippy::redundant_field_names` - RSA key builder redundancy
  - **Fix**: Replace with `handler` 
  - **Architecture Note**: RSA key generation with v0.10.0-rc.4 integration
  - **Security**: Maintains RSA cryptographic integrity with latest crate

- [ ] **File**: `key/src/api/algorithm_builders/rsa_builder.rs:67`
  - **Issue**: `clippy::redundant_field_names` - RSA chunk handler redundancy
  - **Fix**: Replace with `handler`
  - **Architecture Note**: Batch RSA key generation capability
  - **Performance**: Optimized RSA key generation throughput

### Add Missing Default Implementations for Key Builders
- [ ] **File**: `key/src/api/algorithm_builders/aes_builder.rs:35`
  - **Issue**: `clippy::new_without_default` - AesKeyBuilder lacks Default
  - **Fix**: Implement Default trait calling new()
  - **Architecture Note**: AES key builder ergonomic initialization
  - **Security**: Secure default initialization for AES key generation

- [ ] **File**: `key/src/api/algorithm_builders/rsa_builder.rs:35`
  - **Issue**: `clippy::new_without_default` - RsaKeyBuilder lacks Default  
  - **Fix**: Implement Default trait calling new()
  - **Architecture Note**: RSA key builder initialization consistency
  - **Performance**: Zero overhead RSA builder initialization

### Fix Should Implement Trait Issues  
- [ ] **File**: `key/src/api/key_generator/derive/core.rs:29`
  - **Issue**: `clippy::should_implement_trait` - custom default() method should be Default trait
  - **Current**: `pub fn default() -> Self { Self::new(KdfConfig::default()) }`
  - **Fix**: Replace with proper `impl Default for DeriveBuilder`
  - **Architecture Note**: Key derivation function builder consistency
  - **Design**: Aligns with Rust trait conventions

- [ ] **File**: `key/src/api/key_generator/entropy.rs:71`
  - **Issue**: `clippy::should_implement_trait` - custom default() method
  - **Fix**: Implement proper Default trait instead of custom default()
  - **Architecture Note**: Entropy generation configuration defaults
  - **Security**: Maintains secure entropy defaults

### Fix Needless Borrows and Other Key Issues
- [ ] **Files**: `key/src/api/key_generator/derive/core.rs:97,104,115,126` and `key/src/api/key_generator/derive/specialized.rs:147,155,166,173`
  - **Issue**: `clippy::needless_borrows_for_generic_args` - Unnecessary & in format! calls
  - **Fix**: Remove & from `&format!(...)` calls
  - **Architecture Note**: Key derivation error handling optimization
  - **Performance**: Eliminates unnecessary borrowing in error paths

- [ ] **File**: `key/src/api/key_retriever/handler_execution.rs:29`
  - **Issue**: `clippy::manual_unwrap_or_default` - Manual match can be simplified
  - **Current**: `match storage_result { Ok(bytes) => bytes, Err(_) => Vec::new() }`
  - **Fix**: `storage_result.unwrap_or_default()`
  - **Architecture Note**: Key retrieval error handling simplification
  - **Performance**: More idiomatic error handling

- [ ] **File**: `key/src/store/file_store/core.rs:41`
  - **Issue**: `clippy::collapsible_str_replace` - Consecutive string replacements
  - **Current**: `namespace.replace('/', "_").replace(':', "_")`
  - **Fix**: `namespace.replace(['/', ':'], "_")`
  - **Architecture Note**: File-based key storage path sanitization
  - **Performance**: Single pass string replacement optimization

---

## PHASE 4: PQCRYPTO CRATE CLIPPY COMPLIANCE (16 errors)

### Fix Manual Async Functions
- [ ] **File**: `pqcrypto/src/api/kem_builder/keypair.rs:19`
  - **Issue**: `clippy::manual_async_fn` - Function returning Future should be async fn
  - **Current**: `fn generate(self) -> impl Future<Output = Result<Self::Output>> + Send`
  - **Fix**: Convert to `async fn generate(self) -> Result<Self::Output>`
  - **Architecture Note**: Post-quantum KEM keypair generation async interface
  - **Performance**: Cleaner async implementation with better compiler optimizations

- [ ] **File**: `pqcrypto/src/api/signature_builder/falcon.rs:35`
  - **Issue**: `clippy::manual_async_fn` - Falcon signature keypair generation  
  - **Fix**: Convert to proper async fn
  - **Architecture Note**: FALCON post-quantum signature scheme integration
  - **Security**: Maintains FALCON cryptographic properties

- [ ] **Files**: `pqcrypto/src/api/signature_builder/ml_dsa/key_management.rs:17` and `pqcrypto/src/api/signature_builder/sphincs/keypair.rs:17`
  - **Issue**: `clippy::manual_async_fn` - ML-DSA and SPHINCS+ async functions
  - **Fix**: Convert to proper async fn syntax
  - **Architecture Note**: Post-quantum signature scheme async consistency
  - **Performance**: Optimized async execution for PQ crypto operations

### Fix Option As Ref Deref Issues
- [ ] **Files**: Multiple files with `.as_ref().map(|k| k.as_slice())` patterns
  - **Issue**: `clippy::option_as_ref_deref` - Can use .as_deref() instead
  - **Fix**: Replace with `.as_deref()` for cleaner code
  - **Architecture Note**: Post-quantum cryptographic key access optimization
  - **Performance**: More efficient Option handling

### Add Missing Default Implementations for PQCrypto
- [ ] **File**: `pqcrypto/src/api/kyber_builder.rs:44`
  - **Issue**: `clippy::new_without_default` - KyberBuilder lacks Default
  - **Fix**: Implement Default trait
  - **Architecture Note**: Kyber KEM algorithm builder consistency
  - **Security**: Secure default initialization for post-quantum KEM

- [ ] **File**: `pqcrypto/src/api/dilithium_builder.rs:45`
  - **Issue**: `clippy::new_without_default` - DilithiumBuilder lacks Default
  - **Fix**: Implement Default trait  
  - **Architecture Note**: Dilithium signature algorithm builder consistency
  - **Performance**: Zero overhead PQ signature builder initialization

- [ ] **File**: `pqcrypto/src/api/pqcrypto_master_builder.rs:9`
  - **Issue**: `clippy::new_without_default` - PqCryptoMasterBuilder lacks Default
  - **Fix**: Implement Default trait
  - **Architecture Note**: Master post-quantum crypto builder initialization
  - **Design**: Unified PQ crypto interface ergonomics

### Fix PQCrypto Miscellaneous Issues
- [ ] **File**: `pqcrypto/src/api/states.rs:85`
  - **Issue**: `clippy::non_canonical_clone_impl` - Clone should use copy for Copy types
  - **Current**: `fn clone(&self) -> Self { Self::new() }`
  - **Fix**: `fn clone(&self) -> Self { *self }`
  - **Architecture Note**: Post-quantum crypto state management optimization
  - **Performance**: Efficient Copy-based cloning for simple state types

---

## PHASE 5: COMPRESSION CRATE CLIPPY COMPLIANCE (16 errors)

### Add Missing Default Implementations for Compression
- [ ] **File**: `compression/src/api/bzip2_builder/stream/decompressor.rs:15`
  - **Issue**: `clippy::new_without_default` - Bzip2Decompressor lacks Default
  - **Fix**: Implement Default trait
  - **Architecture Note**: Bzip2 streaming decompression initialization
  - **Performance**: Optimized buffer allocation for streaming operations

- [ ] **File**: `compression/src/api/bzip2_builder/mod.rs:46`
  - **Issue**: `clippy::new_without_default` - Bzip2Builder<NoLevel> lacks Default
  - **Fix**: Implement Default trait
  - **Architecture Note**: Bzip2 compression builder with type-state pattern
  - **Design**: Maintains compression level type safety

- [ ] **Files**: Multiple compression builders lacking Default implementations
  - **Fix**: Add Default implementations for all compression algorithm builders
  - **Architecture Note**: Consistent compression algorithm initialization patterns
  - **Performance**: Zero allocation default initialization where possible

### Fix Type Complexity Issues in Compression
- [ ] **File**: `compression/src/api/gzip_builder/mod.rs:27`
  - **Issue**: `clippy::type_complexity` - Complex chunk handler function pointer
  - **Current**: `Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>`
  - **Fix**: Create type alias: `type ChunkHandler = Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>;`
  - **Architecture Note**: Gzip compression streaming handler type clarification
  - **Performance**: No runtime overhead, improved maintainability

- [ ] **File**: `compression/src/api/zip_builder.rs:21,22`
  - **Issue**: `clippy::type_complexity` - Complex ZIP handler types  
  - **Fix**: Create appropriate type aliases for ZIP compression handlers
  - **Architecture Note**: ZIP archive compression with multiple file support
  - **Design**: Cleaner type definitions for complex ZIP operations

### Fix Unnecessary Casts and Division Issues
- [ ] **File**: `compression/src/api/bzip2_builder/stream/factory.rs:10`
  - **Issue**: `clippy::unnecessary_cast` - Casting u32 to u32
  - **Current**: `level.unwrap_or(6) as u32`
  - **Fix**: `level.unwrap_or(6)`
  - **Architecture Note**: Bzip2 compression level handling optimization
  - **Performance**: Eliminates unnecessary type conversion

- [ ] **File**: `compression/src/api/gzip_builder/stream/compressor.rs:99`
  - **Issue**: `clippy::unnecessary_cast` - Similar u32 cast issue
  - **Fix**: Remove redundant cast
  - **Architecture Note**: Gzip compression level consistency
  - **Performance**: Streamlined compression configuration

- [ ] **Files**: `compression/src/api/zstd_builder/streaming_compress.rs:24,63`
  - **Issue**: `clippy::manual_div_ceil` - Manual ceiling division
  - **Current**: `(data.len() + chunk_size - 1) / chunk_size`
  - **Fix**: `data.len().div_ceil(chunk_size)`
  - **Architecture Note**: Zstd streaming compression chunk calculation
  - **Performance**: Optimized division using stdlib implementation

---

## PHASE 6: FINAL VERIFICATION AND VALIDATION

### Comprehensive Workspace Verification
- [ ] **Command**: `cargo clippy --workspace -- -D warnings`
  - **Requirement**: Must return completely empty output (zero clippy errors)
  - **Architecture Validation**: Ensures all builder patterns maintain integrity
  - **Performance Check**: Validates no performance regressions introduced
  - **Constraint**: Absolute zero tolerance for any warnings or errors

- [ ] **Command**: `cargo check --workspace`
  - **Requirement**: Zero compilation errors across entire workspace
  - **Dependency Validation**: Confirms RSA v0.10.0-rc.4 integration success
  - **API Compatibility**: Ensures all fixes maintain API contract
  - **Security**: Validates cryptographic integrity preserved

- [ ] **Command**: `cargo test --workspace --no-run`
  - **Requirement**: All tests compile without errors
  - **Test Coverage**: Ensures test suite remains intact
  - **Integration Testing**: Validates examples and integration points
  - **Constraint**: No expect() or unwrap() in test compilation

### Functional Validation
- [ ] **Example**: `cargo run --package cryypt --example cipher_api`
  - **Validation**: RSA encryption/decryption with v0.10.0-rc.4 works correctly
  - **Architecture Test**: Builder pattern functionality preserved
  - **Performance Check**: No regression in cryptographic operations
  - **Security Validation**: Cryptographic correctness maintained

- [ ] **Example**: `cargo run --package cryypt --example key_api`
  - **Validation**: RSA key generation with new crate version functions
  - **Integration Test**: Key generation builder patterns work correctly
  - **Security Check**: Key generation maintains cryptographic strength
  - **Performance**: Key generation performance not degraded

- [ ] **Example**: `cargo run --package cryypt --example jwt_api`
  - **Validation**: JWT operations with RSA keys function correctly
  - **Integration Test**: JWT signing and verification with RSA v0.10.0-rc.4
  - **Security Validation**: JWT cryptographic operations maintained
  - **API Test**: JWT builder patterns remain functional

### Final Success Confirmation
- [ ] **Comprehensive Final Check**
  - **Commands**: Both `cargo check --workspace` and `cargo clippy --workspace -- -D warnings`
  - **Success Criteria**: Absolute zero errors, zero warnings, zero output
  - **Architecture Validation**: All builder patterns functional
  - **Performance Confirmation**: No regressions introduced
  - **Security Assurance**: All cryptographic operations intact
  - **Production Readiness**: Code meets production quality standards

---

## CONSTRAINTS AND STANDARDS APPLIED TO ALL TASKS

### Code Quality Requirements
- **Never use**: `unwrap()` or `expect()` in src/* or examples/*
- **Use expect()**: Only in ./tests/* directory
- **No unsafe code**: Maintain `#![forbid(unsafe_code)]` compliance
- **No unchecked operations**: All operations must be checked and handled
- **No locking**: Maintain lock-free architecture where possible
- **Zero allocation**: Optimize for minimal allocation overhead
- **Blazing-fast**: Maintain performance characteristics
- **Elegant ergonomic code**: Clean, maintainable, professional quality

### Architecture Preservation Requirements
- **Builder Pattern Integrity**: All builder patterns must remain functional
- **Type-State Safety**: Maintain compile-time API safety
- **Streaming Support**: Preserve streaming capabilities for large data
- **Feature Gates**: Maintain feature flag architecture
- **Error Handling**: Comprehensive error handling with proper types
- **Cryptographic Security**: All cryptographic operations must remain secure
- **API Compatibility**: No breaking changes to public APIs
- **Performance**: No regressions in cryptographic operation performance

### Implementation Standards
- **Complete Implementation**: No stubs, no TODOs, no "future enhancements"
- **Full Error Handling**: All error paths must be properly handled
- **Documentation**: Maintain existing documentation standards
- **Testing Compatibility**: All fixes must be compatible with existing tests
- **Production Quality**: All code must meet production deployment standards
- **Security First**: Security considerations must be preserved in all changes
- **Performance Optimized**: All hot paths must be optimized for performance
- **Memory Safe**: All operations must be memory safe without unsafe code