//! Display and trait implementations for Error

use super::types::Error;
use std::fmt;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner.kind)?;

        if let Some(context) = &self.inner.context {
            write!(f, ": {context}")?;
        }

        if let Some(source) = &self.inner.source {
            write!(f, "\nCaused by: {source}")?;
        }

        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner
            .source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}
