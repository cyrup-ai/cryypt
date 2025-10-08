//! Macro for semantic bit sizes

/// Trait to convert numeric values to bits
pub trait Bits {
    /// Convert this value to a `BitSize` representing the number of bits
    fn bits(self) -> BitSize;
}

/// Represents a size in bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitSize {
    /// The number of bits
    pub bits: usize,
}

impl BitSize {
    /// Convert to bytes
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bits / 8
    }
}

impl Bits for i32 {
    fn bits(self) -> BitSize {
        BitSize {
            bits: usize::try_from(self.max(0)).unwrap_or(0),
        }
    }
}

impl Bits for u32 {
    fn bits(self) -> BitSize {
        BitSize {
            bits: self as usize,
        }
    }
}

impl Bits for usize {
    fn bits(self) -> BitSize {
        BitSize { bits: self }
    }
}

// Support for integer literals
impl Bits for i64 {
    fn bits(self) -> BitSize {
        BitSize {
            bits: usize::try_from(self.max(0)).unwrap_or(0),
        }
    }
}

impl Bits for u64 {
    fn bits(self) -> BitSize {
        BitSize {
            bits: usize::try_from(self).unwrap_or(usize::MAX),
        }
    }
}

// Convenience constants
impl BitSize {
    /// 128 bits (16 bytes)
    pub const BITS_128: BitSize = BitSize { bits: 128 };
    /// 192 bits (24 bytes)
    pub const BITS_192: BitSize = BitSize { bits: 192 };
    /// 256 bits (32 bytes)
    pub const BITS_256: BitSize = BitSize { bits: 256 };
    /// 384 bits (48 bytes)
    pub const BITS_384: BitSize = BitSize { bits: 384 };
    /// 512 bits (64 bytes)
    pub const BITS_512: BitSize = BitSize { bits: 512 };
}
