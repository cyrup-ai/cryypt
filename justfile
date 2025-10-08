# Cryypt Development Justfile
# https://github.com/casey/just

# Default recipe - show available commands
default:
    @just --list

# Run the vault binary
run *args:
    cargo run --package cryypt_vault --bin cryypt {{args}}

# Run vault in release mode
run-release *args:
    cargo run --package cryypt_vault --bin cryypt --release {{args}}

# Build all workspace crates
build:
    cargo build

# Build in release mode
build-release:
    cargo build --release

# Run all tests with all features
test:
    cargo test --all-features

# Run tests for specific crates
test-cipher:
    cargo test --package cryypt_cipher

test-compression:
    cargo test --package cryypt_compression

test-hashing:
    cargo test --package cryypt_hashing

test-key:
    cargo test --package cryypt_key

test-vault:
    cargo test --package cryypt_vault

test-jwt:
    cargo test --package cryypt_jwt

test-pqcrypto:
    cargo test --package cryypt_pqcrypto

test-quic:
    cargo test --package cryypt_quic

# Run tests including doctests
test-all-including-docs:
    cargo test

# Run only library and integration tests (skip doctests)
test-no-docs:
    cargo test --lib --tests

# Run tests with coverage
test-coverage:
    cargo test --all-features

# Format all code
fmt:
    cargo fmt

# Check code without building
check:
    cargo check --message-format short --quiet

# Run clippy linter
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Run full quality check pipeline
quality: fmt check lint test

# Clean build artifacts
clean:
    cargo clean

# Update dependencies
update:
    cargo update

# Show workspace tree
tree:
    cargo tree

# Show workspace members
members:
    @echo "Workspace members:"
    @cargo metadata --format-version 1 | jq -r '.workspace_members[]' | sed 's/.*#/  - /'

# Run nextest (if available)
nextest:
    cargo nextest run

# Build documentation
docs:
    cargo doc --no-deps --open

# Run security audit
audit:
    cargo audit

# Install the cryypt binary
install:
    cargo install --path packages/vault --bin cryypt

# Benchmark performance
bench:
    cargo bench

# Run the unified cryypt library examples (if available)
example name:
    cargo run --package cryypt --example {{name}}

# Development helpers
dev-setup:
    @echo "Setting up development environment..."
    cargo install cargo-nextest cargo-audit cargo-expand
    @echo "Development tools installed!"

# Show crate sizes
sizes:
    cargo tree --format "{p} {f}" | grep -E "\(|\)" | sort