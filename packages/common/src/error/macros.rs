//! Macros for error creation and handling

/// Macro for creating errors with automatic file/line context
#[doc(hidden)]
#[macro_export]
macro_rules! err {
    ($kind:ident) => {
        $crate::error::Error::$kind().context(format!("at {}:{}", file!(), line!()))
    };
    ($kind:ident, $msg:expr) => {
        $crate::error::Error::$kind().context(format!("{} at {}:{}", $msg, file!(), line!()))
    };
    ($kind:ident, $fmt:expr, $($arg:tt)*) => {
        $crate::error::Error::$kind().context(format!(concat!($fmt, " at {}:{}"), $($arg)*, file!(), line!()))
    };
}

/// Macro for bailing out with an error
#[doc(hidden)]
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::err!($($arg)*))
    };
}

/// Macro for ensuring a condition holds
#[doc(hidden)]
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            $crate::bail!($($arg)*);
        }
    };
}
