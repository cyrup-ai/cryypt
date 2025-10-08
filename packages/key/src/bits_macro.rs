//! Bit size macro for type-safe bit operations

/// Type-safe bit size representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitSize {
    /// The number of bits
    pub bits: u32,
}

impl BitSize {
    /// Convert to bytes
    #[must_use]
    pub fn to_bytes(&self) -> usize {
        (self.bits / 8) as usize
    }
}

/// Extension trait for bit conversion
pub trait Bits {
    /// Convert to `BitSize`
    fn bits(self) -> BitSize;
}

impl Bits for u32 {
    fn bits(self) -> BitSize {
        BitSize { bits: self }
    }
}

impl Bits for usize {
    fn bits(self) -> BitSize {
        // For bit sizes, we expect reasonable values that fit in u32
        // If the value is too large, we clamp it to u32::MAX
        let bits = u32::try_from(self).unwrap_or(u32::MAX);
        BitSize { bits }
    }
}

impl Bits for i32 {
    fn bits(self) -> BitSize {
        // For bit sizes, negative values don't make sense, so we clamp to 0
        // Positive values are converted safely
        let bits = if self < 0 {
            0
        } else {
            u32::try_from(self).unwrap_or(0)
        };
        BitSize { bits }
    }
}
