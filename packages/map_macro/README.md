# map_macro

A Rust crate providing ergonomic macros for initializing `hashbrown::HashMap` and `hashbrown::HashSet` instances in version 0.1.0. It supports inferred and explicitly typed variants, with closure-based macros for deferred initialization.

## Features

- Create `HashMap` and `HashSet` with concise, expressive syntax.
- Support for inferred and explicitly typed keys/values, including trait objects (e.g., `&dyn Debug`).
- Closure-based macros returning `impl FnOnce` for methods requiring deferred map creation.
- Compatible with `hashbrown 0.14.5` and `no_std` environments (with optional `std` feature).

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
map_macro = "0.1.0"
hashbrown = "0.14.5"
```