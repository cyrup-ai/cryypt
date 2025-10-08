//! Data and ciphertext builder traits
//!
//! Contains traits for adding data and ciphertext to cipher builders.

/// Builder that can accept data
/// NOTE: Library trait - intended for external implementations
#[allow(dead_code)]
pub trait DataBuilder {
    /// The resulting type after adding data
    type Output;
    /// Add data to this builder
    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output;

    /// Accept data from a file
    fn with_file<P: AsRef<std::path::Path> + Send>(
        self,
        path: P,
    ) -> impl std::future::Future<Output = crate::Result<Self::Output>> + Send
    where
        Self: Sized + Send,
    {
        async move {
            let data = tokio::fs::read(path)
                .await
                .map_err(|e| crate::CryptError::Internal(format!("Failed to read file: {e}")))?;
            Ok(self.with_data(data))
        }
    }

    /// Accept data from a string (UTF-8)
    fn with_text(self, text: &str) -> Self::Output
    where
        Self: Sized,
    {
        self.with_data(text.as_bytes())
    }

    /// Accept data from base64 encoded string
    fn with_data_base64(self, data: &str) -> crate::Result<Self::Output>
    where
        Self: Sized,
    {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(data)?;
        Ok(self.with_data(decoded))
    }

    /// Accept data from hex encoded string
    fn with_data_hex(self, data: &str) -> crate::Result<Self::Output>
    where
        Self: Sized,
    {
        let decoded = hex::decode(data)?;
        Ok(self.with_data(decoded))
    }
}

/// Builder that can accept ciphertext
/// NOTE: Library trait - intended for external implementations
#[allow(dead_code)]
pub trait CiphertextBuilder {
    /// The resulting type after adding ciphertext
    type Output;
    /// Add ciphertext to this builder
    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output;

    /// Accept ciphertext from a file
    fn with_ciphertext_file<P: AsRef<std::path::Path> + Send>(
        self,
        path: P,
    ) -> impl std::future::Future<Output = crate::Result<Self::Output>> + Send
    where
        Self: Sized + Send,
    {
        async move {
            let data = tokio::fs::read(path).await.map_err(|e| {
                crate::CryptError::Internal(format!("Failed to read ciphertext file: {e}"))
            })?;
            Ok(self.with_ciphertext(data))
        }
    }

    /// Accept ciphertext from base64 encoded string
    fn with_ciphertext_base64(self, ciphertext: &str) -> crate::Result<Self::Output>
    where
        Self: Sized,
    {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(ciphertext)?;
        Ok(self.with_ciphertext(decoded))
    }

    /// Accept ciphertext from hex encoded string
    fn with_ciphertext_hex(self, ciphertext: &str) -> crate::Result<Self::Output>
    where
        Self: Sized,
    {
        let decoded = hex::decode(ciphertext)?;
        Ok(self.with_ciphertext(decoded))
    }
}
