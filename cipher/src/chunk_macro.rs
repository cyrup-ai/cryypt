//! Macro for handling stream chunk results

/// Macro for handling stream chunk results in cipher operations
///
/// This macro enables the README.md streaming pattern:
/// ```rust,no_run
/// # use cryypt_cipher::*;
/// # async fn example() {
/// // cipher.on_chunk(on_chunk!(|chunk| {
/// //     Ok => chunk,     // Returns unwrapped bytes
/// //     Err(e) => {      // Can log and skip/return
/// //         log::error!("Error: {}", e);
/// //     }
/// // }))
/// # }
/// ```
#[macro_export]
macro_rules! on_chunk {
    // Standard pattern: Ok => chunk, Err(e) => { ... return; }
    (|$chunk:ident| {
        Ok => $ok_expr:expr,
        Err($err:ident) => {
            $($err_body:tt)*
        }
    }) => {
        |$chunk: Result<Vec<u8>, $crate::CryptError>| -> Option<Vec<u8>> {
            match $chunk {
                Ok($chunk) => Some($ok_expr),
                Err($err) => {
                    $($err_body)*
                    None
                }
            }
        }
    };
    // Alternative pattern with custom error handling
    (|$chunk:ident| {
        Ok => $ok_expr:expr,
        Err($err:ident) => $err_expr:expr
    }) => {
        |$chunk: Result<Vec<u8>, $crate::CryptError>| -> Option<Vec<u8>> {
            match $chunk {
                Ok($chunk) => Some($ok_expr),
                Err($err) => $err_expr
            }
        }
    };
}