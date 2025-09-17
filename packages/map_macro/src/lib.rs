//! Macros for initializing [`hashbrown`] maps and sets.
//!
//! This crate provides ergonomic macros for creating `hashbrown::HashMap` and
//! `hashbrown::HashSet` instances in version 0.1.0. It includes inferred and
//! explicitly typed variants, with closure-based macros returning `impl FnOnce`
//! for use in method signatures requiring deferred initialization.
//!
//! See the `README.md` for detailed explanations and examples of when to use each macro.
//!
//! # Supported Versions of `hashbrown`
//!
//! Compatible with `hashbrown` version `0.14.5`. Future versions breaking `SemVer`
//! (e.g., `0.15` or `1.0`) may not be compatible if `FromIterator` implementations
//! change.
//!
//! **Note**: You must include `hashbrown` as a dependency and avoid renaming it
//! to ensure macro compatibility.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "hashbrown")]
pub mod hashbrown {
    //! Macros for initializing [`hashbrown`] maps and sets.
    //!
    //! # Supported Versions of `hashbrown`
    //!
    //! Compatible with `hashbrown` version `0.14.5`. Future versions breaking
    //! `SemVer` (e.g., `0.15` or `1.0`) may not be compatible if `FromIterator`
    //! implementations change.
    //!
    //! **Note**: You must include `hashbrown` as a dependency and avoid renaming it
    //! to ensure macro compatibility.

    /// Macro for creating a [`HashMap`](::hashbrown::HashMap) with inferred types.
    ///
    /// Use for direct `HashMap` initialization with concrete types.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashbrown::HashMap;
    /// use map_macro::hashbrown::hash_map;
    ///
    /// #[derive(PartialEq, Eq, Hash)]
    /// enum Key { A, B }
    ///
    /// #[derive(Clone)]
    /// enum Value { X, Y }
    ///
    /// let map = hash_map! {
    ///     Key::A => Value::X,
    ///     Key::B => Value::Y,
    /// };
    /// ```
    #[doc(hidden)]
    #[macro_export]
    macro_rules! __hb_hash_map {
        {$($k: expr => $v: expr),* $(,)?} => {
            <::hashbrown::HashMap::<_, _> as ::core::iter::FromIterator<_>>::from_iter([$(($k, $v),)*])
        };
    }

    /// Explicitly typed equivalent of [`hash_map!`](self::hash_map).
    ///
    /// Supports type coercion for trait objects as keys/values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashbrown::HashMap;
    /// use map_macro::hashbrown::hash_map_e;
    /// use std::fmt::Debug;
    ///
    /// #[derive(PartialEq, Eq, Hash)]
    /// enum Key { A, B }
    ///
    /// let map: HashMap<Key, &dyn Debug> = hash_map_e! {
    ///     Key::A => &42,
    ///     Key::B => &"example",
    /// };
    /// ```
    #[doc(hidden)]
    #[macro_export]
    macro_rules! __hb_hash_map_e {
        {$($k: expr => $v: expr),* $(,)?} => {
            <::hashbrown::HashMap::<_, _> as ::core::iter::FromIterator<_>>::from_iter([$(($k as _, $v as _),)*])
        };
    }

    /// Macro for creating a [`HashSet`](::hashbrown::HashSet) with inferred types.
    ///
    /// Use for direct `HashSet` initialization with concrete types.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashbrown::HashSet;
    /// use map_macro::hashbrown::hash_set;
    ///
    /// #[derive(PartialEq, Eq, Hash)]
    /// enum Item { X, Y, Z }
    ///
    /// let set = hash_set! { Item::X, Item::Y, Item::Z, Item::Z };
    /// assert_eq!(set.len(), 3);
    /// ```
    #[doc(hidden)]
    #[macro_export]
    macro_rules! __hb_hash_set {
        {$($v: expr),* $(,)?} => {
            <::hashbrown::HashSet::<_> as ::core::iter::FromIterator<_>>::from_iter([$($v,)*])
        };
    }

    /// Explicitly typed equivalent of [`hash_set!`](self::hash_set).
    ///
    /// Supports type coercion for trait objects or other types.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashbrown::HashSet;
    /// use map_macro::hashbrown::hash_set_e;
    ///
    /// enum Foo { A, B, C }
    ///
    /// let set: HashSet<u8> = hash_set_e! { Foo::A, Foo::B, Foo::C };
    /// assert_eq!(set.len(), 3);
    /// ```
    #[doc(hidden)]
    #[macro_export]
    macro_rules! __hb_hash_set_e {
        {$($v: expr),* $(,)?} => {
            <::hashbrown::HashSet::<_> as ::core::iter::FromIterator<_>>::from_iter([$($v as _,)*])
        };
    }

    /// Macro for creating a [`HashMap`](::hashbrown::HashMap) within a closure with inferred types.
    ///
    /// Returns `impl FnOnce() -> HashMap<K, V>` for methods accepting closures.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashbrown::HashMap;
    /// use map_macro::hashbrown::hash_map_fn;
    ///
    /// #[derive(Debug, Clone)]
    /// enum TypedValue { Prop, Prop2 }
    ///
    /// #[derive(PartialEq, Eq, Hash)]
    /// enum Locale { En, De }
    ///
    /// struct Builder;
    ///
    /// impl Builder {
    ///     fn some<K, V>(f: impl FnOnce() -> HashMap<K, V>) -> HashMap<K, V>
    ///     where
    ///         K: std::hash::Hash + Eq,
    ///     {
    ///         f()
    ///     }
    /// }
    ///
    /// let map = Builder::some(hash_map_fn! {
    ///     Locale::En => TypedValue::Prop,
    ///     Locale::De => TypedValue::Prop2,
    /// });
    /// ```
    #[doc(hidden)]
    #[macro_export]
    macro_rules! __hb_hash_map_fn {
        {$($k: expr => $v: expr),* $(,)?} => {
            || <::hashbrown::HashMap::<_, _> as ::core::iter::FromIterator<_>>::from_iter([$(($k, $v),)*])
        };
    }

    /// Explicitly typed equivalent of [`hash_map_fn!`](self::hash_map_fn).
    ///
    /// Supports type coercion for trait objects as keys/values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hashbrown::HashMap;
    /// use map_macro::hashbrown::hash_map_fn_e;
    /// use std::fmt::Debug;
    ///
    /// #[derive(PartialEq, Eq, Hash)]
    /// enum Key { A, B }
    ///
    /// struct Builder;
    ///
    /// impl Builder {
    ///     fn some<K, V>(f: impl FnOnce() -> HashMap<K, V>) -> HashMap<K, V>
    ///     where
    ///         K: std::hash::Hash + Eq,
    ///     {
    ///         f()
    ///     }
    /// }
    ///
    /// let map: HashMap<Key, &dyn Debug> = Builder::some(hash_map_fn_e! {
    ///     Key::A => &42,
    ///     Key::B => &true,
    /// });
    /// ```
    #[doc(hidden)]
    #[macro_export]
    macro_rules! __hb_hash_map_fn_e {
        {$($k: expr => $v: expr),* $(,)?} => {
            || <::hashbrown::HashMap::<_, _> as ::core::iter::FromIterator<_>>::from_iter([$(($k as _, $v as _),)*])
        };
    }

    #[doc(inline)]
    pub use __hb_hash_map as hash_map;

    #[doc(inline)]
    pub use __hb_hash_map_e as hash_map_e;

    #[doc(inline)]
    pub use __hb_hash_set as hash_set;

    #[doc(inline)]
    pub use __hb_hash_set_e as hash_set_e;

    #[doc(inline)]
    pub use __hb_hash_map_fn as hash_map_fn;

    #[doc(inline)]
    pub use __hb_hash_map_fn_e as hash_map_fn_e;
}
