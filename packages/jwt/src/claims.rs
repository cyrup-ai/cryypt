//! JWT claims and builder with compile-time validation.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, marker::PhantomData};

/// Typestate markers for builder pattern.
pub mod ts {
    /// Marker for a field that has been set.
    pub struct Set;
    /// Marker for a field that has not been set.
    pub struct Unset;
}

/// Immutable JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject.
    pub sub: String,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Issued-at (unix seconds).
    pub iat: i64,
    /// Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    /// Not before (unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// JWT ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Custom data.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Compile-time checked builder for JWT claims.
pub struct ClaimsBuilder<Sub = ts::Unset, Exp = ts::Unset, Iat = ts::Unset> {
    sub: Option<String>,
    exp: Option<i64>,
    iat: Option<i64>,
    iss: Option<String>,
    aud: Option<Vec<String>>,
    nbf: Option<i64>,
    jti: Option<String>,
    extra: HashMap<String, Value>,
    _phantom: PhantomData<(Sub, Exp, Iat)>,
}

impl ClaimsBuilder {
    /// Create a new claims builder.
    pub fn new() -> Self {
        Self {
            sub: None,
            exp: None,
            iat: None,
            iss: None,
            aud: None,
            nbf: None,
            jti: None,
            extra: HashMap::new(),
            _phantom: PhantomData,
        }
    }
}

impl<Exp, Iat> ClaimsBuilder<ts::Unset, Exp, Iat> {
    /// Set the subject (sub) claim.
    pub fn subject(self, sub: impl Into<String>) -> ClaimsBuilder<ts::Set, Exp, Iat> {
        ClaimsBuilder {
            sub: Some(sub.into()),
            exp: self.exp,
            iat: self.iat,
            iss: self.iss,
            aud: self.aud,
            nbf: self.nbf,
            jti: self.jti,
            extra: self.extra,
            _phantom: PhantomData,
        }
    }
}

impl<Sub, Iat> ClaimsBuilder<Sub, ts::Unset, Iat> {
    /// Set the expiration time relative to now.
    pub fn expires_in(self, dur: Duration) -> ClaimsBuilder<Sub, ts::Set, Iat> {
        ClaimsBuilder {
            sub: self.sub,
            exp: Some((Utc::now() + dur).timestamp()),
            iat: self.iat,
            iss: self.iss,
            aud: self.aud,
            nbf: self.nbf,
            jti: self.jti,
            extra: self.extra,
            _phantom: PhantomData,
        }
    }
}

impl<Sub, Exp> ClaimsBuilder<Sub, Exp, ts::Unset> {
    /// Set the issued-at time to now.
    pub fn issued_now(self) -> ClaimsBuilder<Sub, Exp, ts::Set> {
        ClaimsBuilder {
            sub: self.sub,
            exp: self.exp,
            iat: Some(Utc::now().timestamp()),
            iss: self.iss,
            aud: self.aud,
            nbf: self.nbf,
            jti: self.jti,
            extra: self.extra,
            _phantom: PhantomData,
        }
    }
}

impl<Sub, Exp, Iat> ClaimsBuilder<Sub, Exp, Iat> {
    /// Add a custom claim.
    pub fn claim(mut self, k: impl Into<String>, v: Value) -> Self {
        self.extra.insert(k.into(), v);
        self
    }

    /// Set the issuer (iss) claim.
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Set the audience (aud) claim.
    pub fn audience(mut self, aud: Vec<String>) -> Self {
        self.aud = Some(aud);
        self
    }

    /// Set the not-before (nbf) claim.
    pub fn not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.nbf = Some(nbf.timestamp());
        self
    }

    /// Set the JWT ID (jti) claim.
    pub fn jwt_id(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }
}

impl ClaimsBuilder<ts::Set, ts::Set, ts::Set> {
    /// Build the claims. All required fields must be set.
    pub fn build(self) -> Claims {
        Claims {
            // Type system guarantees these are Some() when build() is callable
            // Using unwrap_or_else with fallbacks instead of panics for safety
            sub: self.sub.unwrap_or_else(|| {
                tracing::error!("ClaimsBuilder: subject field unexpectedly None despite type guarantees");
                String::new()
            }),
            exp: self.exp.unwrap_or_else(|| {
                tracing::error!("ClaimsBuilder: expiry field unexpectedly None despite type guarantees");
                Utc::now().timestamp()
            }),
            iat: self.iat.unwrap_or_else(|| {
                tracing::error!("ClaimsBuilder: issued-at field unexpectedly None despite type guarantees");
                Utc::now().timestamp()
            }),
            iss: self.iss,
            aud: self.aud,
            nbf: self.nbf,
            jti: self.jti,
            extra: self.extra,
        }
    }
}

impl Default for ClaimsBuilder {
    fn default() -> Self {
        Self::new()
    }
}
