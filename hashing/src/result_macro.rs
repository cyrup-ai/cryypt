//! Hashing-specific on_result! macro implementation (internal use only)

// Internal macro - not exported, only used within the crate
macro_rules! hash_on_result_impl {
    // Standard README pattern - identity function for Result
    (|$result:ident| { Ok => Ok($ok_result:ident), Err($err:ident) => Err($err_ident:ident) }) => {
        |$result: $crate::Result<Vec<u8>>| -> $crate::Result<Vec<u8>> {
            match $result {
                Ok($ok_result) => Ok($ok_result),
                Err($err) => Err($err),
            }
        }
    };
    // Custom handler pattern (for flexibility)
    (|$result:ident| { Ok => $ok_expr:expr, Err($err:ident) => $err_expr:expr }) => {
        |$result: $crate::Result<Vec<u8>>| -> $crate::Result<Vec<u8>> {
            match $result {
                Ok($result) => $ok_expr,
                Err($err) => $err_expr,
            }
        }
    };
}

// Users should use the on_result method on builders, not call macros directly
pub(crate) use hash_on_result_impl;