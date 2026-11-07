//! The AuthZEN evaluation request the issuer sends to go-trust (design §11).
//!
//! Shape follows go-trust's `pkg/authzen` types (AuthZEN Trust Registry
//! Profile, draft-johansson-authzen-trust), the same construction
//! siros-verifier-core uses on the verification side. The core builds the
//! query and consumes a permit; it never creates a local trust fallback, and
//! any transport failure is fail-closed (`pdp_unavailable`, not a permit).
//!
//! The subject here is the *integrating application's* client-assertion key
//! — the actor requesting issuance — not a credential subject. The PDP
//! decides whether that key may issue this credential type from this
//! authentic source.

use serde_json::{json, Value};

/// Evidence about the integrator, extracted from its verified client
/// assertion. Standard-base64 DER certificates, leaf first; preferred when
/// non-empty, otherwise the embedded JWK.
#[derive(Clone, Debug)]
pub struct IssuanceTrustQuery {
    pub subject_id: String,
    pub x5c: Vec<String>,
    pub jwk: Value,
    /// vct / doctype being issued.
    pub credential_type: String,
    /// Optional authentic-source discriminator (design §6.2).
    pub authentic_source: Option<String>,
}

impl IssuanceTrustQuery {
    pub fn new(
        subject_id: impl Into<String>,
        x5c: Vec<String>,
        jwk: Value,
        credential_type: impl Into<String>,
        authentic_source: Option<String>,
    ) -> Self {
        Self {
            subject_id: subject_id.into(),
            x5c,
            jwk,
            credential_type: credential_type.into(),
            authentic_source,
        }
    }

    /// AuthZEN evaluation request for go-trust.
    pub fn to_authzen(&self) -> Value {
        debug_assert!(
            !(self.x5c.is_empty() && self.jwk.is_null()),
            "IssuanceTrustQuery needs x5c or jwk evidence"
        );
        let (resource_type, key) = if self.x5c.is_empty() {
            ("jwk", json!([self.jwk]))
        } else {
            ("x5c", json!(self.x5c))
        };
        let mut parameters = json!({ "credential_types": [self.credential_type] });
        if let Some(source) = &self.authentic_source {
            parameters["authentic_source"] = json!(source);
        }
        json!({
            "subject":  { "type": "key", "id": self.subject_id },
            "resource": { "type": resource_type, "id": self.subject_id, "key": key },
            "action":   { "name": "issue", "parameters": parameters },
        })
    }
}
