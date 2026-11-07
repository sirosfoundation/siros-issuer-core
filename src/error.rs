//! Errors with stable, machine-readable refusal codes.
//!
//! Codes are part of the wire surface (protocol error responses) and must
//! not be renamed. Messages are for logs; they never contain subject data.

pub type Result<T> = std::result::Result<T, Error>;

/// Refusal codes. Stable across releases; protocol-visible.
pub mod code {
    pub const INVALID_INPUT: &str = "invalid_input";
    /// A proof whose c_nonce value is wrong or stale (OID4VCI credential
    /// error `invalid_nonce`).
    pub const INVALID_NONCE: &str = "invalid_nonce";
    /// A missing or otherwise invalid key proof (OID4VCI credential
    /// error `invalid_proof`).
    pub const INVALID_PROOF: &str = "invalid_proof";
    /// A malformed credential request (OID4VCI credential error
    /// `invalid_credential_request`).
    pub const INVALID_CREDENTIAL_REQUEST: &str = "invalid_credential_request";
    /// An unknown credential identifier (OID4VCI credential error
    /// `unknown_credential_identifier`).
    pub const UNKNOWN_CREDENTIAL_IDENTIFIER: &str = "unknown_credential_identifier";
    pub const CONFIGURATION: &str = "configuration";
    pub const CATALOG_INVALID: &str = "catalog_invalid";
    pub const UNSUPPORTED_CREDENTIAL: &str = "unsupported_credential";
    pub const ILLEGAL_TRANSITION: &str = "illegal_transition";
    pub const PDP_DENIED: &str = "pdp_denied";
    pub const PDP_UNAVAILABLE: &str = "pdp_unavailable";
    pub const NOT_IMPLEMENTED: &str = "not_implemented";
    pub const TRANSPORT: &str = "transport";
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}

impl Error {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(code::INVALID_INPUT, message)
    }

    pub fn configuration(message: impl Into<String>) -> Self {
        Self::new(code::CONFIGURATION, message)
    }

    pub fn catalog_invalid(message: impl Into<String>) -> Self {
        Self::new(code::CATALOG_INVALID, message)
    }

    pub fn unsupported_credential(message: impl Into<String>) -> Self {
        Self::new(code::UNSUPPORTED_CREDENTIAL, message)
    }

    pub fn illegal_transition(message: impl Into<String>) -> Self {
        Self::new(code::ILLEGAL_TRANSITION, message)
    }

    pub fn invalid_nonce(message: impl Into<String>) -> Self {
        Self::new(code::INVALID_NONCE, message)
    }

    pub fn invalid_proof(message: impl Into<String>) -> Self {
        Self::new(code::INVALID_PROOF, message)
    }

    pub fn invalid_credential_request(message: impl Into<String>) -> Self {
        Self::new(code::INVALID_CREDENTIAL_REQUEST, message)
    }

    pub fn transport(message: impl Into<String>) -> Self {
        Self::new(code::TRANSPORT, message)
    }
}

/// Verifier-core errors surface as `catalog_invalid`: in this workspace the
/// verifier core is only consumed at the catalog and presentation-embedding
/// boundaries, and a verifier refusal there is always a catalog refusal.
impl From<siros_verifier_core::Error> for Error {
    fn from(err: siros_verifier_core::Error) -> Self {
        Self::catalog_invalid(err.to_string())
    }
}
