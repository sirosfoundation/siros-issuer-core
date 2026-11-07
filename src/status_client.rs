//! Wire types for siros-status-service (draft-ietf-oauth-status-list).
//!
//! Sans-I/O: the service performs HTTP with its own credentials (client
//! assertion against the status-service AS, design §9.1). The core owns the
//! shapes so issuance and revocation share one vocabulary.

use serde::{Deserialize, Serialize};
use url::Url;

/// `POST /allocate` request. `exp` omitted means the service's maximum.
#[derive(Debug, Serialize)]
pub struct AllocateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
}

/// `POST /allocate` reply.
#[derive(Debug, Deserialize)]
pub struct AllocateReply {
    pub list_url: Url,
    pub index: u64,
    #[serde(default)]
    pub exp: Option<String>,
}

/// Status values of draft-ietf-oauth-status-list §3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Valid,
    Invalid,
    Suspended,
    Resume,
}

/// `PATCH /status/{list}/{index}` request body.
#[derive(Debug, Serialize)]
pub struct UpdateRequest {
    pub status: Status,
}

/// A credential's revocation handle, held by the session (design §9.3).
/// Revocation is by session id; the issuer keeps no subject index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRef {
    pub list_url: Url,
    pub index: u64,
}
