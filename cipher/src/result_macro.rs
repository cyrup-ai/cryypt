//! Cipher-specific on_result macro implementation for clean syntax

/// Macro to enable clean on_result syntax as shown in README.md
/// 
/// This transforms:
/// ```rust
/// .on_result(|result| {
///     Ok => result,
///     Err(e) => Vec::new()
/// })
/// ```
/// 
/// Into a proper closure that works with the AesWithKeyAndHandler pattern
#[macro_export]
macro_rules! on_result {
    (|$result:ident| {
        Ok => $ok_expr:expr,
        Err($err:ident) => $err_block:block
    }) => {
        |$result: crate::Result<Vec<u8>>| -> Vec<u8> {
            match $result {
                Ok($result) => $ok_expr,
                Err($err) => $err_block,
            }
        }
    };
}