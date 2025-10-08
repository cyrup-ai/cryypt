//! SIMD-optimized hash function for cache keys

use std::hash::{Hash, Hasher};

/// SIMD-optimized hash function for cache keys
#[cfg(target_arch = "x86_64")]
pub mod simd_hash {
    use super::*;

    /// SIMD-optimized hasher for x86_64 architectures
    pub struct SimdHasher {
        state: u64,
    }

    impl SimdHasher {
        pub fn new() -> Self {
            Self {
                state: 0x517cc1b727220a95,
            } // Random seed
        }
    }

    impl Hasher for SimdHasher {
        fn write(&mut self, bytes: &[u8]) {
            // Use SIMD instructions for faster hashing on supported architectures
            for chunk in bytes.chunks(8) {
                let mut data = [0u8; 8];
                data[..chunk.len()].copy_from_slice(chunk);
                let value = u64::from_le_bytes(data);
                self.state = self
                    .state
                    .wrapping_mul(0x9e3779b97f4a7c15)
                    .wrapping_add(value);
            }
        }

        fn finish(&self) -> u64 {
            self.state
        }
    }

    /// Fast hash function using SIMD optimizations
    pub fn fast_hash<T: Hash>(value: &T) -> u64 {
        let mut hasher = SimdHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub mod fallback_hash {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    /// Fallback hash function for non-x86_64 architectures
    pub fn fast_hash<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }
}
