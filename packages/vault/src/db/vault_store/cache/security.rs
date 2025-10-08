//! Secure value wrapper with automatic zeroization

use zeroize::Zeroize;

/// Secure cache value wrapper with automatic zeroization
#[derive(Debug, Clone)]
pub struct SecureValue<T>
where
    T: Zeroize,
{
    inner: T,
}

impl<T> SecureValue<T>
where
    T: Zeroize,
{
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    pub fn get(&self) -> &T {
        &self.inner
    }

    pub fn into_inner(self) -> T
    where
        T: Default,
    {
        let mut value = self;
        std::mem::take(&mut value.inner)
    }
}

impl<T> Drop for SecureValue<T>
where
    T: Zeroize,
{
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}
