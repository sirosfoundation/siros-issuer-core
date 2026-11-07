//! The issuance session state machine (design doc §5.1).
//!
//! Pure: the host applies events; this module decides legality and computes
//! the next state. Both grants (pre-authorized and authorization-code) and
//! both authorization modes (login handoff, OpenID4VP presentation) converge
//! on this one machine — there is no second path.
//!
//! ```text
//! PRE-AUTH: create → Offered. WALLET-INITIATED: PAR → AwaitingAuthorization,
//! then Authorized (Mode A handoff call or Mode B verified presentation)
//! mints the code and the session becomes Offered.
//! ```

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// How a session was started. OpenID4VCI 1.0 ID1 grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    /// Issuer-initiated via the backend session API.
    PreAuthorized,
    /// Wallet-initiated via PAR → authorize → token.
    AuthorizationCode,
}

/// Opaque, unguessable session identifier: 128 bits of host-supplied
/// entropy, hex-encoded. Newtype so a wrong-length or non-hex value cannot
/// circulate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Hex length of a 128-bit id.
    pub const ENCODED_LEN: usize = 32;

    /// Build from 16 bytes of host entropy.
    pub fn from_random(bytes: [u8; 16]) -> Self {
        Self(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Accept exactly a 32-character lowercase hex string.
    pub fn from_hex(value: &str) -> Result<Self> {
        if value.len() != Self::ENCODED_LEN
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::invalid_input(
                "session id must be 32 lowercase hex characters",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Session state. Design §5.1. Serialize as snake_case labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Wallet-initiated: created by PAR, waiting for the login handoff
    /// (Mode A) or the OpenID4VP presentation (Mode B).
    AwaitingAuthorization,
    /// Code minted; wallet holds the offer / authorization code.
    Offered,
    /// Wallet redeemed at the token endpoint; claims are being assembled.
    Redeeming,
    /// Deferred issuance: resolver or external source still working.
    Pending,
    /// Credential signed; status-list index allocated.
    Issued,
    /// Wallet confirmed receipt (`credential_accepted`).
    Accepted,
    /// Wallet reported failure, or an error occurred mid-flow.
    Failed,
    /// Offer or authorization request expired unredeemed.
    Expired,
    /// Wallet reported `credential_deleted`. The status-list index is kept
    /// for the retention window.
    Deleted,
}

impl SessionState {
    pub fn is_final(&self) -> bool {
        matches!(
            self,
            SessionState::Accepted
                | SessionState::Failed
                | SessionState::Expired
                | SessionState::Deleted
        )
    }
}

/// Events applied to a session. `TtlExpired` is armed by the host clock;
/// `Authorized` carries no payload — the subject-data assertion happened at
/// the host before the event is legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// Mode A authorize-complete call or Mode B verified presentation.
    Authorized,
    /// Wallet redeemed the pre-auth code or authorization code at /token.
    Redeemed,
    /// Slow resolver: the wallet will poll the deferred credential endpoint.
    Deferred,
    /// Credential signed and the status index allocated.
    Issued,
    /// Wallet notification `credential_accepted`.
    WalletAccepted,
    /// Wallet notification `credential_failure`.
    WalletFailed,
    /// Wallet notification `credential_deleted`.
    WalletDeleted,
    /// TTL expiry of the offer or the authorization request.
    TtlExpired,
    /// Classified error; the session fails and keeps its status index.
    ErrorOccurred,
}

/// Compute the next state. Illegal combinations are refusals with the stable
/// `illegal_transition` code — the host must not "recover" them.
pub fn transition(state: SessionState, event: SessionEvent) -> Result<SessionState> {
    use SessionEvent as Ev;
    use SessionState as State;

    let next = match (state, event) {
        (State::AwaitingAuthorization, Ev::Authorized) => State::Offered,
        (State::Offered, Ev::Redeemed) => State::Redeeming,
        (State::Redeeming, Ev::Deferred) => State::Pending,
        (State::Pending, Ev::Deferred) => State::Pending,
        // Re-issuance: the wallet may request the credential again
        // with the same access token (OID4VCI §13.3 multiple accesses;
        // the suite's additional-requests module does exactly this,
        // including after a credential_accepted notification).
        (State::Redeeming, Ev::Issued)
        | (State::Pending, Ev::Issued)
        | (State::Issued, Ev::Issued)
        | (State::Accepted, Ev::Issued) => State::Issued,
        (State::Issued, Ev::WalletAccepted) => State::Accepted,
        (State::Issued, Ev::WalletFailed) => State::Failed,
        (State::Issued, Ev::WalletDeleted) => State::Deleted,
        (State::AwaitingAuthorization, Ev::TtlExpired) | (State::Offered, Ev::TtlExpired) => {
            State::Expired
        }
        (state, Ev::ErrorOccurred) if !state.is_final() => State::Failed,
        (state, event) => {
            return Err(Error::illegal_transition(format!(
                "event {event:?} is illegal in state {state:?}"
            )));
        }
    };
    Ok(next)
}
