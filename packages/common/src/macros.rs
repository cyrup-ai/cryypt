//! Macros for transforming clean pattern matching syntax

/// Create a proper Result handler from clean pattern matching syntax
/// Usage: `on_result_handler!(|result| { Ok(value) => value, Err(e) => fallback })`
#[macro_export]
macro_rules! on_result_handler {
    (|$param:ident| { $($arms:tt)* }) => {
        |$param| match $param { $($arms)* }
    };
}

/// Create a proper chunk handler from clean pattern matching syntax
/// Usage: `on_chunk_handler!(|chunk| { Ok => chunk.into(), Err(e) => BadChunk::from_error(e) })`
#[macro_export]
macro_rules! on_chunk_handler {
    (|$param:ident| { $($arms:tt)* }) => {
        |$param| match $param { $($arms)* }
    };
}

/// Transform `on_result` handlers to accept clean pattern matching syntax
#[macro_export]
macro_rules! transform_on_result {
    ($handler:expr) => {
        $handler
    };
}

/// Transform `on_chunk` handlers to accept clean pattern matching syntax  
#[macro_export]
macro_rules! transform_on_chunk {
    ($handler:expr) => {
        $handler
    };
}
