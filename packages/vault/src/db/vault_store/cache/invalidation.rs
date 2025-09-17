//! Cache invalidation strategies

/// Cache invalidation strategy
#[derive(Debug)]
pub enum InvalidationStrategy {
    /// Invalidate by key pattern
    KeyPattern(String),
    /// Invalidate by age (older than specified seconds)
    Age(u64),
    /// Invalidate by access count (less than specified count)
    AccessCount(u64),
    /// Invalidate all entries
    All,
}
