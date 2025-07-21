//! ⚠️  CRATE PRIVATE CIPHER MACROS - NEVER EXPOSE TO USERS ⚠️ 
//!
//! Cipher-specific on_result macro implementation for clean syntax
//! 🚨 CRITICAL: THIS MACRO IS CRATE PRIVATE ONLY 🚨
//! USERS NEVER IMPORT OR SEE THIS MACRO

/// ⚠️  CRATE PRIVATE ONLY ⚠️  Macro to enable clean on_result syntax as shown in README.md
/// 🚨 NEVER MAKE THIS PUBLIC 🚨
/// 
/// This transforms users' sexy syntax:
/// ```rust,ignore
/// use cryypt::Cryypt;
/// 
/// async fn example() {
///     let data = b"hello world";
///     let key = b"my-secret-key-32-bytes-long!!!!";
///     
///     let encrypted = Cryypt::cipher()
///         .aes()
///         .with_key(key)
///         .on_result(|result| {
///             Ok => result,
///             Err(e) => Vec::new()
///         })
///         .encrypt(data)
///         .await;
/// }
/// ```
/// 
/// Into a proper closure that works with the AesWithKeyAndHandler pattern
/// USERS NEVER IMPORT THIS - IT WORKS VIA INTERNAL TRANSFORMATION
#[doc(hidden)]
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