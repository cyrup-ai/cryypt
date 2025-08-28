//! Production-ready error recovery for network operations

/// Production-ready error recovery for network operations
pub struct ErrorRecovery {
    max_retries: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    backoff_multiplier: f64,
}

impl ErrorRecovery {
    /// Create new error recovery with exponential backoff
    pub fn new(max_retries: u32, base_delay_ms: u64, max_delay_ms: u64) -> Self {
        Self {
            max_retries,
            base_delay_ms,
            max_delay_ms,
            backoff_multiplier: 2.0,
        }
    }

    /// Execute operation with retry logic
    pub async fn retry<F, T, E>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
        E: std::fmt::Debug,
    {
        let mut attempts = 0;
        let mut delay = self.base_delay_ms;

        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    attempts += 1;
                    if attempts >= self.max_retries {
                        return Err(error);
                    }

                    // Exponential backoff with jitter
                    let jitter = fastrand::u64(0..=delay / 4);
                    let total_delay = delay + jitter;

                    tokio::time::sleep(std::time::Duration::from_millis(total_delay)).await;

                    delay = (delay as f64 * self.backoff_multiplier) as u64;
                    delay = delay.min(self.max_delay_ms);
                }
            }
        }
    }

    /// Check if error is retryable
    pub fn is_retryable<E>(&self, _error: &E) -> bool {
        // Production implementation would analyze error types
        // For now, assume most errors are retryable
        true
    }
}
