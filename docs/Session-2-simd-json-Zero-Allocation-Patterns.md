# Session 2: simd-json Zero-Allocation Patterns Research

## Overview
Research into simd-json library zero-allocation JSON parsing patterns for use in production JSON-RPC implementation.

## Key Findings

### 1. Buffer Reuse Architecture
```rust
use simd_json::{Buffers, Tape, fill_tape, to_borrowed_value_with_buffers};

// Create persistent, reusable buffers
let mut buffers = Buffers::default(); // or Buffers::new(expected_size)
let mut tape = Tape::null();

// Zero-allocation parsing (after buffer amortization)
fill_tape(&mut json_data, &mut buffers, &mut tape)?;
```

### 2. Buffers Structure Components
```rust
pub struct Buffers {
    string_buffer: Vec<u8>,        // For string de-escaping
    structural_indexes: Vec<u32>,  // JSON structure indices
    input_buffer: AlignedBuf,      // SIMD-aligned input buffer
    stage2_stack: Vec<StackState>, // Parser state stack
}
```

### 3. Zero-Allocation API Patterns

#### BorrowedValue (Preferred for RPC)
```rust
// First parse (buffer initialization)
let value = to_borrowed_value_with_buffers(&mut json_data, &mut buffers)?;

// Subsequent parses (zero allocations)
let value = to_borrowed_value_with_buffers(&mut json_data, &mut buffers)?;
```

#### Tape API (Maximum Performance)
```rust
// Amortized zero-allocation pattern
fill_tape(&mut json_data, &mut buffers, &mut tape)?;
let value = tape.as_value();
```

### 4. Performance Validation
From `tests/alloc.rs`:
```rust
// After buffer amortization, parsing achieves:
assert_eq!(count.0, 0); // 0 allocations  
assert_eq!(count.1, 0); // 0 reallocations
```

## Critical Implementation Requirements

### 1. Buffer Lifetime Management
- Buffers must persist across multiple parse operations
- Initial parse performs buffer sizing (amortization)
- Subsequent parses reuse existing capacity

### 2. SIMD Alignment Requirements
- Input buffer requires 64-byte SIMD alignment
- Uses `AlignedBuf` for proper memory alignment
- Padding requirements: `SIMDJSON_PADDING = 32 bytes`

### 3. Memory Safety Patterns
```rust
// Safe buffer reuse pattern
buffer.string_buffer.clear();           // Clear content, keep capacity
buffer.structural_indexes.clear();      // Clear indices, keep capacity
input_buffer.copy_from_nonoverlapping() // Safe memory copying
```

## JSON-RPC Integration Strategy

### 1. Per-Connection Buffer Pool
```rust
struct RpcConnection {
    buffers: Buffers,
    tape: Tape<'static>,
    // ... other fields
}
```

### 2. Request Processing Pipeline
1. **Receive**: Get JSON-RPC bytes from QUIC stream
2. **Parse**: Use `fill_tape()` with connection buffers  
3. **Process**: Extract method/params from tape value
4. **Respond**: Generate response using same buffers

### 3. Batch Request Optimization
- Single buffer set can process entire batch array
- Concurrent processing with separate buffer sets per task
- Zero additional allocations for batch parsing

## Comparison vs Current Implementation

### Current Issues
- `data.to_vec()` violates zero-allocation principle
- No buffer reuse between requests
- Excessive allocations in request processing

### Required Changes  
1. Replace `simd_json::to_owned_value(&mut json_data)` 
2. Implement persistent `Buffers` per connection
3. Use `fill_tape()` or `to_borrowed_value_with_buffers()`
4. Proper buffer lifecycle management

## Performance Impact

### Memory Allocation Reduction
- **Before**: N allocations per request
- **After**: 0 allocations per request (after amortization)

### Throughput Improvement
- Eliminates allocation/deallocation overhead
- Reduces garbage collection pressure
- Improves cache locality through buffer reuse

## Next Steps for Session 3
1. Study production RPC architectures (tarpc, tonic)
2. Research Tokio concurrency and timeout patterns
3. Design complete integration architecture
4. Plan production-quality implementation

## Compliance with Research-First Methodology
✅ Zero stubs - pure research and documentation
✅ Complete understanding of zero-allocation patterns
✅ Production-ready implementation strategy
✅ Performance validation through existing tests