//! Type states for the builder pattern

use cryypt_key::KeyId;
use std::sync::Arc;

/// Type state indicating no data has been set
pub struct NoData;

/// Type state indicating data has been set
pub struct HasData<T>(pub T);

/// Type state indicating no key has been set
pub struct NoKey;

/// Type state indicating a key has been set
pub struct HasKey(pub Arc<dyn KeyId>);
