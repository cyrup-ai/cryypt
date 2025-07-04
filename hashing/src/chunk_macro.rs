//! Macro for handling stream chunk results in hashing operations

/// Macro for handling stream chunk results in hashing operations
///
/// This macro enables the README.md streaming pattern:
/// ```rust,no_run
/// # use cryypt_hashing::*;
/// # async fn example() {
/// // let mut hash_stream = Hash::sha256()
/// //     .on_chunk!(|chunk| {
/// //         Ok => chunk,
/// //         Err(e) => {
/// //             log::error!("Hash chunk error: {}", e);
/// //             return;
/// //         }
/// //     })
/// //     .compute_stream(file_stream);
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
        |$chunk: Result<Vec<u8>, $crate::HashError>| -> Option<Vec<u8>> {
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
        |$chunk: Result<Vec<u8>, $crate::HashError>| -> Option<Vec<u8>> {
            match $chunk {
                Ok($chunk) => Some($ok_expr),
                Err($err) => $err_expr
            }
        }
    };
}