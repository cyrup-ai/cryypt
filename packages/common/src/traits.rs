//! Common traits used across the cryypt ecosystem

/// Trait to prevent Result types in async operations - README.md compliance
/// This ensures that `AsyncTask` and `AsyncStream` return unwrapped values, not Result
#[marker]
pub trait NotResult {}

// Implement for specific types we want to allow
impl NotResult for bool {}
impl NotResult for () {}
impl<T> NotResult for Vec<T> {}
impl NotResult for String {}
impl<T> NotResult for Option<T> {}
impl NotResult for u8 {}
impl NotResult for u16 {}
impl NotResult for u32 {}
impl NotResult for u64 {}
impl NotResult for u128 {}
impl NotResult for usize {}
impl NotResult for i8 {}
impl NotResult for i16 {}
impl NotResult for i32 {}
impl NotResult for i64 {}
impl NotResult for i128 {}
impl NotResult for isize {}
impl NotResult for f32 {}
impl NotResult for f64 {}
impl NotResult for &str {}
impl<T> NotResult for &[T] {}
impl<T> NotResult for Box<T> {}
impl<T> NotResult for std::sync::Arc<T> {}
impl<T> NotResult for std::rc::Rc<T> {}

// Common JSON types for JWT and other serialization
impl NotResult for serde_json::Value {}

// Tuple implementations for QUIC streams
impl<T, U> NotResult for (T, U)
where
    T: NotResult,
    U: NotResult,
{
}

// Explicitly exclude Result types
impl<T, E> !NotResult for Result<T, E> {}

// === Async Result Traits ===
// These traits ensure that async operations return unwrapped values, not Results
// The user controls error handling through on_result/on_chunk/on_error

use std::future::Future;

/// Async result for operations that return bool (like exists checks)
pub trait AsyncExistsResult: Future + Send
where
    Self::Output: NotResult,
{
}
impl<T> AsyncExistsResult for T
where
    T: Future + Send,
    T::Output: NotResult,
{
}

/// Async result for operations that return () (like delete, store)
pub trait AsyncDeleteResult: Future + Send
where
    Self::Output: NotResult,
{
}
impl<T> AsyncDeleteResult for T
where
    T: Future + Send,
    T::Output: NotResult,
{
}

/// Async result for operations that return Vec<u8> (like retrieve, generate)
pub trait AsyncRetrieveResult: Future + Send
where
    Self::Output: NotResult,
{
}
impl<T> AsyncRetrieveResult for T
where
    T: Future + Send,
    T::Output: NotResult,
{
}

/// Async result for store operations - MUST return unwrapped ()
pub trait AsyncStoreResult: Future + Send
where
    Self::Output: NotResult,
{
}
impl<T> AsyncStoreResult for T
where
    T: Future + Send,
    T::Output: NotResult,
{
}

/// Async result for key generation - MUST return unwrapped Vec<u8>
pub trait AsyncGenerateResult: Future + Send
where
    Self::Output: NotResult,
{
}
impl<T> AsyncGenerateResult for T
where
    T: Future + Send,
    T::Output: NotResult,
{
}

/// Async result for listing operations - MUST return unwrapped Vec<String>
pub trait AsyncListResult: Future + Send
where
    Self::Output: NotResult,
{
}
impl<T> AsyncListResult for T
where
    T: Future + Send,
    T::Output: NotResult,
{
}
