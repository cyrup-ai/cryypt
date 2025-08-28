# Fix All Cargo Errors and Warnings - TODO List

## Overview
36 total issues identified (1 warning + 35 clippy errors). All must be fixed to achieve 0 errors and 0 warnings.

## Tasks

### 1. Fix unused import warning in quic crate
**File**: `quic/src/protocols/file_transfer/receiver.rs:8`
**Issue**: Remove unused import `std::future::Future`
**Status**: completed

### 2. QA Review - unused import fix
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10 (complete failure through significant improvement). Provide specific feedback on any issues or truly great work (objectively without bragging).
**Status**: pending

### 3. Fix int_plus_one warning in spinner state
**File**: `src/components/spinner/state.rs:100`
**Issue**: Change `advance >= self.frame_index + 1` to `advance > self.frame_index`
**Status**: pending

### 4. QA Review - int_plus_one fix
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 5. Fix manual_is_multiple_of warnings in spinner state (3 instances)
**File**: `src/components/spinner/state.rs:119,122,125`
**Issues**: 
- `self.frame_index % 2 == 0` -> `self.frame_index.is_multiple_of(2)`
- `self.frame_index % 4 != 0` -> `!self.frame_index.is_multiple_of(4)`
- `self.frame_index % 8 != 0` -> `!self.frame_index.is_multiple_of(8)`
**Status**: pending

### 6. QA Review - manual_is_multiple_of fixes
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 7. Fix unwrap_or_default warning in spinner controller
**File**: `src/components/spinner/controller.rs:204`
**Issue**: Change `.or_insert_with(Vec::new)` to `.or_default()`
**Status**: pending

### 8. QA Review - unwrap_or_default fix
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 9. Fix manual_flatten warnings in executor (2 instances)
**File**: `src/concurrent/executor.rs:146,378`
**Issues**: Replace manual if-let patterns with iterator `.flatten()`
**Status**: pending

### 10. QA Review - manual_flatten fixes
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 11. Fix needless_lifetimes warning in executor
**File**: `src/concurrent/executor.rs:374`
**Issue**: Remove explicit lifetimes that can be elided in `build_timer_select` function
**Status**: pending

### 12. QA Review - needless_lifetimes fix
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 13. Fix io_other_error warning in threaded module
**File**: `src/concurrent/threaded.rs:51`
**Issue**: Use `io::Error::other("I/O error")` instead of `io::Error::new(io::ErrorKind::Other, "I/O error")`
**Status**: pending

### 14. QA Review - io_other_error fix (threaded)
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 15. Fix unnecessary_map_or warnings in bandwidth_graph (2 instances)
**File**: `src/display/components/bandwidth_graph.rs:494,512`
**Issue**: Use `.is_some_and(|e| e.running())` instead of `.map_or(false, |e| e.running())`
**Status**: pending

### 16. QA Review - unnecessary_map_or fixes (bandwidth_graph)
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 17. Fix nonminimal_bool warning in ui module
**File**: `src/display/ui.rs:522-523`
**Issue**: Simplify boolean expression: `(opts.connections && opts.processes) || (opts.connections && opts.addresses)` to `(opts.addresses || opts.processes) && opts.connections`
**Status**: pending

### 18. QA Review - nonminimal_bool fix
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 19. Fix missing_safety_doc warning in ui_components_ticker
**File**: `src/display/ui_components_ticker.rs:22`
**Issue**: Add `# Safety` section to unsafe function documentation
**Status**: pending

### 20. QA Review - missing_safety_doc fix
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 21. Fix unnecessary_map_or warning in ui_components_ticker
**File**: `src/display/ui_components_ticker.rs:49`
**Issue**: Use `.is_some_and()` instead of `.map_or(false, ...)`
**Status**: pending

### 22. QA Review - unnecessary_map_or fix (ui_components_ticker)
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 23. Fix clone_on_copy warnings in ui_state (2 instances)
**File**: `src/display/ui_state.rs:168,195`
**Issues**: Use dereference `*connection` and `*local_socket` instead of `.clone()`
**Status**: pending

### 24. QA Review - clone_on_copy fixes
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 25. Fix should_implement_trait warning in sniffer
**File**: `src/network/sniffer.rs:123`
**Issue**: Method `next` can be confused for Iterator::next. Consider implementing Iterator trait or rename method.
**Status**: pending

### 26. QA Review - should_implement_trait fix
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 27. Fix io_other_error warning in sniffer
**File**: `src/network/sniffer.rs:177`
**Issue**: Use `io::Error::other("Interface not available")` instead of manual construction
**Status**: pending

### 28. QA Review - io_other_error fix (sniffer)
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 29. Fix new_without_default warning in network types
**File**: `src/network/type.rs:175`
**Issue**: Add `Default` implementation for `Utilization` struct
**Status**: pending

### 30. QA Review - new_without_default fix
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 31. Fix needless_borrow warnings in spinners (6 instances)
**File**: `src/spinners.rs:859,863,867,871,875,879`
**Issues**: Remove unnecessary references (`&DEFAULT_*` -> `DEFAULT_*`)
**Status**: pending

### 32. QA Review - needless_borrow fixes
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 33. Fix io_other_error warnings in tui (9 instances)
**File**: `src/tui.rs:34,40,63,78,86,90,114,123,126,135`
**Issue**: Use `io::Error::other(e.to_string())` instead of `io::Error::new(io::ErrorKind::Other, e.to_string())`
**Status**: pending

### 34. QA Review - io_other_error fixes (tui)
**Task**: Act as an Objective Rust Expert and rate the quality of the fix on a scale of 1-10. Provide specific feedback.
**Status**: pending

### 35. Final cargo check verification
**Task**: Run `cargo check --workspace` to verify 0 errors
**Status**: pending

### 36. QA Review - final verification
**Task**: Act as an Objective Rust Expert and rate the overall quality of all fixes on a scale of 1-10. Provide summary assessment.
**Status**: pending

### 37. Final cargo clippy verification
**Task**: Run `cargo clippy --workspace -- -D warnings` to verify 0 warnings
**Status**: pending

### 38. QA Review - final clippy verification
**Task**: Act as an Objective Rust Expert and confirm all clippy warnings are resolved and rate the final code quality.
**Status**: pending

## Success Criteria
- 0 errors from `cargo check --workspace`
- 0 warnings from `cargo clippy --workspace -- -D warnings`
- All code is production-ready quality
- All fixes maintain existing functionality