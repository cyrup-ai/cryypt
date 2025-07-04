//! Bit size macro for type-safe bit operations

/// Type-safe bit size representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitSize {
    /// The number of bits
    pub bits: u32,
}

impl BitSize {
    /// Convert to bytes
    pub fn to_bytes(&self) -> usize {
        (self.bits / 8) as usize
    }
}

/// Extension trait for bit conversion
pub trait Bits {
    /// Convert to BitSize
    fn bits(self) -> BitSize;
}

impl Bits for u32 {
    fn bits(self) -> BitSize {
        BitSize { bits: self }
    }
}

impl Bits for usize {
    fn bits(self) -> BitSize {
        BitSize { bits: self as u32 }
    }
}

impl Bits for i32 {
    fn bits(self) -> BitSize {
        BitSize { bits: self as u32 }
    }
}
