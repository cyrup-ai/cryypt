//! Hashing-specific on_chunk! macro implementation (internal use only)

// Internal macro - not exported, only used within the crate
macro_rules! hash_on_chunk_impl {
    // Standard README pattern for stream processing
    (|$chunk:ident| { Ok => $chunk_ident:ident, Err($err:ident) => return }) => {
        |$chunk: $crate::Result<Vec<u8>>| -> Option<Vec<u8>> {
            match $chunk {
                Ok($chunk_ident) => Some($chunk_ident),
                Err(_) => None,
            }
        }
    };
    // Custom handler with error logging
    (|$chunk:ident| { Ok => $chunk_ident:ident, Err($err:ident) => { $($err_body:tt)* } }) => {
        |$chunk: $crate::Result<Vec<u8>>| -> Option<Vec<u8>> {
            match $chunk {
                Ok($chunk_ident) => Some($chunk_ident),
                Err($err) => {
                    $($err_body)*
                    None
                }
            }
        }
    };
}

// Users should use the on_chunk method on builders, not call macros directly
pub(crate) use hash_on_chunk_impl;