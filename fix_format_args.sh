#!/bin/bash

# Script to fix uninlined_format_args warnings across the entire codebase
# This fixes patterns like format!("text: {}", var) to format!("text: {var}")

echo "Fixing uninlined format args across all packages..."

# Find all Rust files and apply the transformation
find packages -name "*.rs" -type f | while read -r file; do
    echo "Processing: $file"
    
    # Fix various common format patterns
    sed -i '' \
        -e 's/format!("\([^"]*\): {}", \([^)]*\))/format!("\1: {\2}")/g' \
        -e 's/format!("\([^"]*\) {}", \([^)]*\))/format!("\1 {\2}")/g' \
        -e 's/format!("{}", \([^)]*\))/format!("{\1}")/g' \
        -e 's/format!("\([^"]*\): {}", e)/format!("\1: {e}")/g' \
        -e 's/format!("\([^"]*\) error: {}", e)/format!("\1 error: {e}")/g' \
        -e 's/format!("\([^"]*\) failed: {}", e)/format!("\1 failed: {e}")/g' \
        "$file"
done

echo "Format args fix complete!"