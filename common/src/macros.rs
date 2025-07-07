//! Handler macros for the special on_result, on_chunk, on_error syntax
//!
//! These macros enable the README.md patterns with special syntax
//! INTERNAL ONLY - NEVER PUBLIC

/// Internal macro for on_result pattern with special Ok => / Err(e) => syntax
/// NEVER PUBLIC - This is internal implementation detail
#[doc(hidden)]
#[macro_export]
macro_rules! __cryypt_on_result_impl {
    (|$result:ident| {
        Ok => $ok_expr:expr,
        Err($err:ident) => $err_block:block
    }) => {
        |$result| match $result {
            Ok($result) => $ok_expr,
            Err($err) => $err_block,
        }
    };
}

/// Internal macro for on_chunk pattern with special Ok => / Err(e) => syntax
/// NEVER PUBLIC - This is internal implementation detail
#[doc(hidden)]
#[macro_export]
macro_rules! __cryypt_on_chunk_impl {
    (|$chunk:ident| {
        Ok => $ok_expr:expr,
        Err($err:ident) => {
            $($err_stmt:stmt;)*
            return
        }
    }) => {
        |$chunk| match $chunk {
            Ok($chunk) => Some($ok_expr),
            Err($err) => {
                $($err_stmt;)*
                None
            }
        }
    };
}

/// Internal macro for on_error pattern
/// NEVER PUBLIC - This is internal implementation detail
#[doc(hidden)]
#[macro_export]
macro_rules! __cryypt_on_error_impl {
    (|$err:ident| $body:block) => {
        |$err| $body
    };
}