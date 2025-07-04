//! Hashing-specific on_result! macro implementation

/// Macro for handling Result types in hashing operations
///
/// This macro enables the README.md pattern:
/// ```rust,no_run
/// # use cryypt_hashing::*;
/// # async fn example() {
/// # let data = b"test data";
/// // let hash = Hash::sha256()
/// //     .on_result!(|result| {
/// //         result.unwrap_or_else(|e| panic!("Hash error: {}", e))
/// //     })
/// //     .compute(data)
/// //     .await;
/// # }
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! __hash_on_result_impl {
    // New pattern - accepts a closure that unwraps Result<HashResult> to HashResult
    ($handler:expr) => {
        $handler
    };
}

/// Public macro that users call for hashing operations
#[macro_export]
macro_rules! hash_on_result {
    ($($tt:tt)*) => {
        $crate::__hash_on_result_impl!($($tt)*)
    };
}