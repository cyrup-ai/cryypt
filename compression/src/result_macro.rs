//! Compression-specific on_result! macro implementation

/// Macro for handling Result types in compression operations
///
/// This macro enables the README.md pattern:
/// ```rust,no_run
/// # use cryypt_compression::*;
/// # async fn example() -> Result<()> {
/// # let data = b"test data";
/// // Compress::zstd()
/// //     .on_result!(|result| {
/// //         Ok => Ok(result),
/// //         Err(e) => Err(e)
/// //     })
/// //     .compress(data)
/// //     .await?
/// # Ok(())
/// # }
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! __compression_on_result_impl {
    // Standard README pattern - identity function for Result
    (|$result:ident| { Ok => Ok($ok_result:ident), Err($err:ident) => Err($err_ident:ident) }) => {
        |$result: $crate::Result<$crate::CompressionResult>| -> $crate::Result<$crate::CompressionResult> {
            match $result {
                Ok($ok_result) => Ok($ok_result),
                Err($err) => Err($err),
            }
        }
    };
    // Custom handler pattern (for flexibility)
    (|$result:ident| { Ok => $ok_expr:expr, Err($err:ident) => $err_expr:expr }) => {
        |$result: $crate::Result<$crate::CompressionResult>| -> $crate::Result<$crate::CompressionResult> {
            match $result {
                Ok($result) => $ok_expr,
                Err($err) => $err_expr,
            }
        }
    };
}

/// Public macro that users call for compression operations
#[macro_export]
macro_rules! compression_on_result {
    ($($tt:tt)*) => {
        $crate::__compression_on_result_impl!($($tt)*)
    };
}