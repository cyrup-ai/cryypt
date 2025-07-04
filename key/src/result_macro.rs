//! Error handling macro for fluent builders

/// Trait for builders that can produce keys with on_result! macro
pub trait KeyProducer {
    async fn produce_key(self) -> Result<crate::api::ActualKey, crate::KeyError>;
}

/// Macro for handling Result types in fluent builders
///
/// This macro enables the README.md pattern:
/// ```rust
/// builder
///     .on_result!(|result| {
///         Ok => Ok(result),
///         Err(e) => Err(e)
///     })
///     .await?
/// ```
#[macro_export]
macro_rules! on_result {
    // Standard README pattern for identity handler
    (|$result:ident| { Ok => Ok($ok_result:ident), Err($err:ident) => Err($err_ident:ident) }) => {
        on_result()
    };
    // Custom handler pattern (for flexibility)
    (|$result:ident| { Ok => $ok_expr:expr, Err($err:ident) => $err_expr:expr }) => {
        |$result| match $result {
            Ok($result) => $ok_expr,
            Err($err) => $err_expr,
        }
    };
}

// Re-export handled at lib.rs level
