//! Cipher-specific on_result! macro implementation

/// Macro for handling Result types in cipher operations
///
/// This macro enables the README.md pattern:
/// ```rust,no_run
/// # use cryypt_cipher::*;
/// # async fn example() -> Result<()> {
/// # let key = vec![0u8; 32];
/// # let data = b"test data";
/// // key.aes()
/// //     .on_result!(|result| {
/// //         Ok => Ok(result),
/// //         Err(e) => Err(e)
/// //     })
/// //     .encrypt(data)
/// //     .await?
/// # Ok(())
/// # }
/// ```
#[doc(hidden)]
macro_rules! __cipher_on_result_impl {
    // Standard README pattern - just return the cipher for method chaining
    (|$result:ident| { Ok => Ok($ok_result:ident), Err($err:ident) => Err($err_ident:ident) }) => {
        |cipher| cipher
    };
    // Custom handler pattern (for flexibility)
    (|$result:ident| { Ok => $ok_expr:expr, Err($err:ident) => $err_expr:expr }) => {
        |$result| match $result {
            Ok($result) => $ok_expr,
            Err($err) => $err_expr,
        }
    };
}

/// Internal macro for cipher operations - NOT PUBLIC API
macro_rules! cipher_on_result {
    ($($tt:tt)*) => {
        on_result($crate::__cipher_on_result_impl!($($tt)*))
    };
}