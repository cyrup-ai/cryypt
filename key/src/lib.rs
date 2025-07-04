#[macro_use]
pub mod result_macro;

pub mod api;
pub mod bits_macro;
pub mod entropy;
pub mod error;
pub mod key_id;
pub mod key_result;
pub mod multi_layer;
pub mod store;
pub mod traits;

// Re-export error types
pub use error::{KeyError, Result};

pub use api::{Key, KeyGenerator, KeyRetriever, KeyRetrieverBatch, KeyRetrieverVersionRange};
pub use key_id::{KeyId, SimpleKeyId};
pub use key_result::KeyResult;
pub use multi_layer::MultiLayerKey;
pub use traits::*;
