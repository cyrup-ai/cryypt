//! Macro for semantic bit sizes

/// Trait to convert numeric values to bits
pub trait Bits {
    fn bits(self) -> BitSize;
}

/// Represents a size in bits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitSize {
    pub bits: usize,
}

impl BitSize {
    /// Convert to bytes
    pub fn bytes(&self) -> usize {
        self.bits / 8
    }
}

impl Bits for i32 {
    fn bits(self) -> BitSize {
        BitSize { bits: self as usize }
    }
}

impl Bits for u32 {
    fn bits(self) -> BitSize {
        BitSize { bits: self as usize }
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
        BitSize { bits: self as usize }
    }
}

impl Bits for u64 {
    fn bits(self) -> BitSize {
        BitSize { bits: self as usize }
    }
}

// Convenience constants
impl BitSize {
    pub const BITS_128: BitSize = BitSize { bits: 128 };
    pub const BITS_192: BitSize = BitSize { bits: 192 };
    pub const BITS_256: BitSize = BitSize { bits: 256 };
    pub const BITS_384: BitSize = BitSize { bits: 384 };
    pub const BITS_512: BitSize = BitSize { bits: 512 };
}