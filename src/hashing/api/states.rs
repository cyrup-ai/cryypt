//! Type states for the hash builder pattern

use super::passes::HashPasses;

/// Type state indicating no data has been set
pub struct NoData;

/// Type state indicating data has been set
pub struct HasData<T>(pub T);

/// Type state indicating no salt has been set
pub struct NoSalt;

/// Type state indicating salt has been set
pub struct HasSalt(pub Vec<u8>);

/// Type state indicating no passes have been set
pub struct NoPasses;

/// Type state indicating passes have been set
pub struct HasPasses(pub HashPasses);