#!/bin/bash

# Comprehensive script to fix major clippy warnings across all packages
# This targets the highest-volume warning types for maximum impact

echo "🔧 Starting bulk clippy warning fixes..."

cd /Volumes/samsung_t9/cryypt

# 1. Fix remaining format string issues (more specific patterns)
echo "📝 Fixing remaining format string patterns..."
find packages -name "*.rs" -type f -exec sed -i '' \
    -e 's/format!("Invalid hex \([^"]*\): {}", e)/format!("Invalid hex \1: {e}")/g' \
    -e 's/format!("Invalid base64 \([^"]*\): {}", e)/format!("Invalid base64 \1: {e}")/g' \
    -e 's/format!("Failed to read \([^"]*\): {}", e)/format!("Failed to read \1: {e}")/g' \
    -e 's/format!("\([^"]*\) decode error: {}", err)/format!("\1 decode error: {err}")/g' \
    -e 's/format!("\([^"]*\) error: {}", err)/format!("\1 error: {err}")/g' \
    {} \;

# 2. Add #[must_use] attributes to common method patterns
echo "🏷️  Adding #[must_use] attributes..."
find packages -name "*.rs" -type f -exec sed -i '' \
    -e 's/    pub fn new() -> Self {/#[must_use]\n    pub fn new() -> Self {/g' \
    -e 's/    pub fn algorithm(&self)/#[must_use]\n    pub fn algorithm(\&self)/g' \
    -e 's/    pub fn with_\([^(]*\)(self/#[must_use]\n    pub fn with_\1(self/g' \
    -e 's/    pub fn \([^(]*\)(&self) -> \([^{]*\) {/#[must_use]\n    pub fn \1(\&self) -> \2 {/g' \
    {} \;

# 3. Fix wildcard imports with common specific imports
echo "🌟 Fixing wildcard imports..."
find packages -name "*.rs" -type f -exec sed -i '' \
    -e 's/use super::\*;/use super::{states, builder_traits};/g' \
    -e 's/use super::super::\*;/use super::super::{states, builder_traits};/g' \
    -e 's/use super::states::\*;/use super::states::{NeedKeyPair, HasKeyPair, HasPublicKey, HasSecretKey, HasMessage, HasSignature, HasCiphertext};/g' \
    -e 's/use super::builder_traits::\*;/use super::builder_traits::{KemKeyPairBuilder, SignatureKeyPairBuilder, MessageBuilder, SignatureDataBuilder, CiphertextBuilder};/g' \
    {} \;

echo "✅ Bulk fixes applied!"
echo "🧪 Running clippy check to see progress..."

# Check progress on pqcrypto package
echo "pqcrypto package warnings:"
cargo clippy --package cryypt_pqcrypto --all-targets --all-features -- -D warnings 2>&1 | grep -c "error:" || echo "0"