//! In-memory session store (design §5.2, decision D1): the reference store
//! for tests and single-process dev; MongoDB replaces it behind the same
//! methods for production. All transitions pass through the core state
//! machine under one lock; indexes exist only for opaque handle lookups
//! (offer uuid, hashed pre-auth code, hashed access token, notification
//! id) — never for subject data.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use siros_issuer_core::session::{
    transition as machine, GrantKind, SessionEvent, SessionId, SessionState,
};
use siros_issuer_core::status_client::StatusRef;
use siros_issuer_core::{Error, Result};
use std::collections::HashMap;
use std::sync::RwLock;

fn sha_hex(data: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(data.as_bytes()).into();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The authorization-code grant's PAR binding (design §7.2): what the
/// wallet asked for, and what its code will be checked against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeBinding {
    pub client_id: String,
    pub redirect_uri: String,
    /// sha256 of the PKCE code_verifier's S256 challenge.
    pub code_challenge: String,
    pub state: Option<String>,
    /// Requested credential configuration ids (validated against the
    /// catalog at PAR time).
    pub credential_configuration_ids: Vec<String>,
}

/// Mode B state (design §7.3): the sealed verifier-core OID4VP session —
/// it carries the ephemeral response-encryption key, so it is sealed at
/// rest — indexed by the opaque challenge handle that rides the request
/// object's `response_uri` path. Taken (consumed) when the wallet's
/// response verifies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeBState {
    pub challenge_handle: String,
    pub sealed_session: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: SessionId,
    pub grant: GrantKind,
    pub state: SessionState,
    /// RFC 7638 thumbprint of the integrator's asserting key: the owner.
    /// Owner checks compare this; unknown-vs-foreign sessions are
    /// indistinguishable to callers.
    pub owner_subject_id: String,
    pub credential_configuration_id: String,
    /// Sealed subject claims (vault). None after purge/final, and until
    /// Mode A/M completes for wallet-initiated sessions.
    pub sealed: Option<Vec<u8>>,
    /// Pre-authorized grant only.
    pub offer_uuid: Option<String>,
    /// sha256 of the pre-authorized code (redemption index; single-use).
    pub pre_authorized_code_hash: Option<String>,
    /// The pre-authorized code itself, sealed in the vault: served to the
    /// wallet in the offer object (the offer URI is the bearer), dropped
    /// with the rest of the sealed data on purge/final.
    pub pre_authorized_code_sealed: Option<Vec<u8>>,
    /// sha256 of the tx_code value (compared at /token); the descriptor
    /// shown to the user is `tx_code_spec`.
    pub tx_code_hash: Option<String>,
    /// Deferred issuance (§7.6): the transaction id the wallet polls
    /// `/deferred-credential` with. sha256 of it indexes the pending
    /// transaction; the value itself rides the credential response.
    /// Set when a session defers instead of issuing.
    pub transaction_id_hash: Option<String>,
    /// OID4VCI tx_code descriptor (input mode/length), safe to serve.
    pub tx_code_spec: Option<siros_issuer_core::oid4vci::TxCode>,
    /// Authorization-code grant only: the PAR binding and the minted
    /// code's hash (single-use at /token).
    pub auth: Option<AuthCodeBinding>,
    pub auth_code_hash: Option<String>,
    /// Mode B (design §7.3): the DPoP jkt that bound the authorization
    /// challenge. When set, /token must present a DPoP proof with the
    /// same jkt — the code is sender-constrained to the wallet that
    /// authenticated. Outlives `mode_b` (consumed at the response).
    pub challenge_jkt: Option<String>,
    /// Mode B: the pending OID4VP exchange (sealed verifier-core session
    /// + its state index). Taken when the wallet's response verifies.
    pub mode_b: Option<ModeBState>,
    pub c_nonce: String,
    pub c_nonce_expires_unix: i64,
    pub status_ref: Option<StatusRef>,
    pub notification_id: String,
    pub revoked: bool,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
    /// (unix, state) transitions, bounded.
    pub history: Vec<(i64, String)>,
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    sessions: RwLock<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    records: HashMap<SessionId, SessionRecord>,
    by_offer_uuid: HashMap<String, SessionId>,
    by_pre_auth: HashMap<String, SessionId>,
    /// access-token hash → (session, expiry, DPoP jkt when DPoP-bound).
    by_access_token: HashMap<String, (SessionId, i64, Option<String>)>,
    by_notification: HashMap<String, SessionId>,
    by_auth_code: HashMap<String, SessionId>,
    /// Mode B: challenge handle → session (the request object's
    /// response_uri path).
    by_challenge_handle: HashMap<String, SessionId>,
    /// Deferred issuance (§7.6): transaction-id hash → session.
    by_transaction: HashMap<String, SessionId>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, record: SessionRecord) -> Result<()> {
        let mut inner = self.lock()?;
        if inner.records.contains_key(&record.id) {
            return Err(Error::invalid_input("session id already exists"));
        }
        if let Some(offer_uuid) = &record.offer_uuid {
            inner
                .by_offer_uuid
                .insert(offer_uuid.clone(), record.id.clone());
        }
        if let Some(code_hash) = &record.pre_authorized_code_hash {
            inner
                .by_pre_auth
                .insert(code_hash.clone(), record.id.clone());
        }
        inner
            .by_notification
            .insert(record.notification_id.clone(), record.id.clone());
        inner.records.insert(record.id.clone(), record);
        Ok(())
    }

    pub fn get(&self, id: &SessionId) -> Option<SessionRecord> {
        self.lock().ok()?.records.get(id).cloned()
    }

    /// Apply an event through the core state machine, under the lock, and
    /// record history. The store never invents a transition.
    pub fn transition(
        &self,
        id: &SessionId,
        event: SessionEvent,
        now: i64,
    ) -> Result<SessionRecord> {
        let mut inner = self.lock()?;
        let record = inner
            .records
            .get_mut(id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        record.state = machine(record.state, event)?;
        record.history.push((now, record.state.label().to_owned()));
        if record.history.len() > 64 {
            record.history.remove(0);
        }
        Ok(record.clone())
    }

    /// Record the status-list reference allocated at issuance time.
    ///
    /// Replaceable by design: a session may be (re)issued multiple times
    /// (the suite's additional-requests module re-requests the credential
    /// with the same access token, and OID4VCI §13.3 permits multiple
    /// accesses to the credential endpoint) — each issuance allocates a
    /// fresh index; the session keeps the latest, revocation flips that
    /// one. (A prior index stays allocated in the status service — its
    /// bit remains VALID, never a false revocation.)
    pub fn set_status_ref(&self, id: &SessionId, status_ref: StatusRef) -> Result<()> {
        let mut inner = self.lock()?;
        let record = inner
            .records
            .get_mut(id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        record.status_ref = Some(status_ref);
        Ok(())
    }

    /// Redeem the pre-authorized code: single-use, atomic (Offered →
    /// Redeeming) or refusal.
    pub fn claim_pre_auth_code(
        &self,
        code: &str,
        tx_code: Option<&str>,
        now: i64,
    ) -> Result<SessionRecord> {
        let mut inner = self.lock()?;
        let id = inner
            .by_pre_auth
            .get(&sha_hex(code))
            .ok_or_else(|| Error::invalid_input("unknown pre-authorized code"))?
            .clone();
        let record = inner
            .records
            .get_mut(&id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        if let Some(expected_hash) = &record.tx_code_hash {
            let given = tx_code.ok_or_else(|| Error::invalid_input("tx_code required"))?;
            if sha_hex(given) != *expected_hash {
                return Err(Error::invalid_input("tx_code mismatch"));
            }
        }
        if record.expires_at_unix < now {
            return Err(Error::new(
                siros_issuer_core::error::code::ILLEGAL_TRANSITION,
                "session expired",
            ));
        }
        // Replay is invalid_input (400, OAuth invalid_grant), not a state
        // conflict: the code was valid and is spent.
        if record.state != siros_issuer_core::session::SessionState::Offered {
            return Err(Error::invalid_input("pre-authorized code already redeemed"));
        }
        record.state = machine(record.state, SessionEvent::Redeemed)?;
        record.history.push((now, record.state.label().to_owned()));
        Ok(record.clone())
    }

    /// Bind a hashed access token to a session (token endpoint), with its
    /// DPoP key thumbprint when the token is DPoP sender-constrained.
    #[allow(clippy::type_complexity)]
    pub fn bind_access_token(
        &self,
        token_hash: String,
        id: &SessionId,
        expires_unix: i64,
        dpop_jkt: Option<String>,
    ) -> Result<()> {
        let mut inner = self.lock()?;
        if !inner.records.contains_key(id) {
            return Err(Error::invalid_input("unknown session"));
        }
        if inner.by_access_token.contains_key(&token_hash) {
            return Err(Error::invalid_input("access token already bound"));
        }
        inner
            .by_access_token
            .insert(token_hash, (id.clone(), expires_unix, dpop_jkt));
        Ok(())
    }

    /// Resolve an access token to its session and DPoP binding; expired
    /// tokens are absent.
    pub fn session_by_access_token(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Option<(SessionId, Option<String>)> {
        let inner = self.lock().ok()?;
        let (id, exp, jkt) = inner.by_access_token.get(token_hash)?;
        if now >= *exp {
            return None;
        }
        Some((id.clone(), jkt.clone()))
    }

    /// Rotate the c_nonce (token and credential endpoints both return one).
    pub fn rotate_c_nonce(&self, id: &SessionId, nonce: String, expires_unix: i64) -> Result<()> {
        let mut inner = self.lock()?;
        let record = inner
            .records
            .get_mut(id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        record.c_nonce = nonce;
        record.c_nonce_expires_unix = expires_unix;
        Ok(())
    }

    pub fn find_by_offer_uuid(&self, offer_uuid: &str) -> Option<SessionRecord> {
        let inner = self.lock().ok()?;
        let id = inner.by_offer_uuid.get(offer_uuid)?;
        inner.records.get(id).cloned()
    }

    pub fn find_by_notification_id(&self, notification_id: &str) -> Option<SessionRecord> {
        let inner = self.lock().ok()?;
        let id = inner.by_notification.get(notification_id)?;
        inner.records.get(id).cloned()
    }

    /// Drop the sealed subject data and the sealed pre-authorized code
    /// (DELETE / final states). The record skeleton survives: status
    /// feedback and the revocation handle must outlive the data
    /// (design §6.3, §9.3).
    pub fn purge_subject_data(&self, id: &SessionId) -> Result<()> {
        let mut inner = self.lock()?;
        let record = inner
            .records
            .get_mut(id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        record.sealed = None;
        record.pre_authorized_code_sealed = None;
        Ok(())
    }

    /// Bind the owner (integrator subject id) of a wallet-initiated
    /// session at authorize-complete time (design §7.2).
    pub fn set_owner(&self, id: &SessionId, owner_subject_id: String) -> Result<()> {
        let mut inner = self.lock()?;
        let record = inner
            .records
            .get_mut(id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        record.owner_subject_id = owner_subject_id;
        Ok(())
    }

    pub fn set_revoked(&self, id: &SessionId) -> Result<()> {
        let mut inner = self.lock()?;
        let record = inner
            .records
            .get_mut(id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        record.revoked = true;
        Ok(())
    }

    /// PAR: same insert path (request_uri handle == offer_uuid).
    pub fn insert_par_session(&self, record: SessionRecord) -> Result<()> {
        self.insert(record)
    }

    /// Mode A authorize-complete: seal subject data, mint the code,
    /// transition AwaitingAuthorization → Offered through the core
    /// machine (design §7.2).
    pub fn complete_authorization(
        &self,
        offer_uuid: &str,
        subject_sealed: Vec<u8>,
        auth: AuthCodeBinding,
        auth_code_hash: String,
        now: i64,
    ) -> Result<()> {
        let mut inner = self.lock()?;
        let id = inner
            .by_offer_uuid
            .get(offer_uuid)
            .ok_or_else(|| Error::invalid_input("no such authorization request"))?
            .clone();
        let record = inner
            .records
            .get_mut(&id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        if record.auth_code_hash.is_some() {
            return Err(Error::illegal_transition(
                "authorization code already minted",
            ));
        }
        record.state = machine(record.state, SessionEvent::Authorized)?;
        record.sealed = Some(subject_sealed);
        record.auth = Some(auth);
        record.auth_code_hash = Some(auth_code_hash.clone());
        record.history.push((now, record.state.label().to_owned()));
        inner.by_auth_code.insert(auth_code_hash, id.clone());
        Ok(())
    }

    /// Mode B (design §7.3 step 2): arm the OID4VP exchange — store the
    /// sealed verifier-core session and remember the challenge's DPoP jkt.
    pub fn set_mode_b(
        &self,
        id: &SessionId,
        mode_b: ModeBState,
        challenge_jkt: Option<String>,
    ) -> Result<()> {
        let mut inner = self.lock()?;
        let record = inner
            .records
            .get_mut(id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        if record.mode_b.is_some() {
            return Err(Error::illegal_transition(
                "an authorization challenge is already pending for this session",
            ));
        }
        let handle = mode_b.challenge_handle.clone();
        record.challenge_jkt = challenge_jkt;
        record.mode_b = Some(mode_b);
        inner.by_challenge_handle.insert(handle, id.clone());
        Ok(())
    }

    /// Mode B step 3: consume the pending exchange by its challenge handle
    /// (single-use — the ephemeral key dies with the take). Returns the
    /// session record and the sealed verifier-core session.
    pub fn take_mode_b(&self, challenge_handle: &str) -> Option<(SessionRecord, Vec<u8>)> {
        let mut inner = self.lock().ok()?;
        let id = inner.by_challenge_handle.remove(challenge_handle)?;
        let record = inner.records.get_mut(&id)?;
        let mode_b = record.mode_b.take()?;
        Some((record.clone(), mode_b.sealed_session))
    }

    /// Deferred issuance (§7.6): arm a transaction on a `pending`
    /// session. Single-arm.
    pub fn set_transaction(&self, id: &SessionId, transaction_id_hash: String) -> Result<()> {
        let mut inner = self.lock()?;
        let record = inner
            .records
            .get_mut(id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        if record.state != SessionState::Pending {
            return Err(Error::illegal_transition(
                "a deferred transaction arms only on a pending session",
            ));
        }
        if record.transaction_id_hash.is_some() {
            return Err(Error::illegal_transition(
                "a deferred transaction is already armed for this session",
            ));
        }
        record.transaction_id_hash = Some(transaction_id_hash.clone());
        inner.by_transaction.insert(transaction_id_hash, id.clone());
        Ok(())
    }

    /// Deferred issuance: consume a pending transaction (single-use —
    /// the arm is cleared under the lock; a second take misses).
    pub fn take_transaction(&self, transaction_id_hash: &str) -> Option<SessionRecord> {
        let mut inner = self.lock().ok()?;
        let id = inner.by_transaction.remove(transaction_id_hash)?;
        let record = inner.records.get_mut(&id)?;
        record.transaction_id_hash = None;
        Some(record.clone())
    }

    /// Read-only lookup by authorization code (no consumption): Mode B's
    /// DPoP sender-constraint check runs before the single-use claim, so
    /// a wrong key refuses without burning the code.
    pub fn peek_auth_code(&self, code: &str) -> Option<SessionRecord> {
        let inner = self.lock().ok()?;
        let code_hash = sha_hex(code);
        let id = inner.by_auth_code.get(&code_hash)?;
        inner.records.get(id).cloned()
    }

    /// authorization_code at /token: consume the single-use code with
    /// redirect + client + PKCE S256 checks (RFC 7636 §4.6).
    pub fn claim_auth_code(
        &self,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        code_verifier: &str,
        now: i64,
    ) -> Result<SessionRecord> {
        let mut inner = self.lock()?;
        let code_hash = sha_hex(code);
        let id = inner
            .by_auth_code
            .get(&code_hash)
            .ok_or_else(|| Error::invalid_input("unknown authorization code"))?
            .clone();
        let record = inner
            .records
            .get_mut(&id)
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        if record.expires_at_unix < now {
            return Err(Error::invalid_input("authorization code expired"));
        }
        if record.state != SessionState::Offered {
            return Err(Error::invalid_input("authorization code already redeemed"));
        }
        let binding = record
            .auth
            .clone()
            .ok_or_else(|| Error::illegal_transition("session has no authorization binding"))?;
        if binding.redirect_uri != redirect_uri {
            return Err(Error::invalid_input("redirect_uri mismatch"));
        }
        if binding.client_id != client_id {
            return Err(Error::invalid_input("client_id mismatch"));
        }
        let computed: String =
            siros_issuer_core::sdjwt_issue::b64u(&Sha256::digest(code_verifier.as_bytes()));
        if !constant_time_eq(computed.as_bytes(), binding.code_challenge.as_bytes()) {
            return Err(Error::invalid_input("PKCE code_verifier mismatch"));
        }
        record.state = machine(record.state, SessionEvent::Redeemed)?;
        record.history.push((now, record.state.label().to_owned()));
        Ok(record.clone())
    }

    fn lock(&self) -> Result<std::sync::RwLockWriteGuard<'_, Inner>> {
        self.sessions.write().map_err(|_| {
            Error::new(
                siros_issuer_core::error::code::ILLEGAL_TRANSITION,
                "session store lock poisoned",
            )
        })
    }

    pub fn len(&self) -> usize {
        self.sessions.read().map(|i| i.records.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The wire label of a session state (SSE payloads, status JSON).
pub trait StateLabel {
    fn label(&self) -> &'static str;
}

impl StateLabel for SessionState {
    fn label(&self) -> &'static str {
        match self {
            SessionState::AwaitingAuthorization => "awaiting_authorization",
            SessionState::Offered => "offered",
            SessionState::Redeeming => "redeeming",
            SessionState::Pending => "pending",
            SessionState::Issued => "issued",
            SessionState::Accepted => "accepted",
            SessionState::Failed => "failed",
            SessionState::Expired => "expired",
            SessionState::Deleted => "deleted",
        }
    }
}

/// Constant-time byte comparison (PKCE checks; no early exit).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ─────────────────────────────────────────────────────────────────────────
// The pluggable storage boundary (design §6.4: MongoDB is the production
// backend; the in-memory store serves tests and single-process dev)
// ─────────────────────────────────────────────────────────────────────────

/// The session storage contract every backend implements.
///
/// The methods are async and take whole owned values where the wire does:
/// a document backend (MongoDB) maps them to atomic compare-and-set
/// operations — offer redemption and authorization-code claims MUST be
/// single-use and atomic across replicas (`claim_pre_auth_code`,
/// `claim_auth_code`, `take_mode_b` consume; a backend that cannot make
/// the claim atomic must refuse it, never linearize a race).
///
/// State transitions delegate to the core state machine
/// (`siros_issuer_core::session::transition`): a backend stores the result
/// it is handed, it never invents a transition.
///
/// Handles (pre-authorized codes, authorization codes, access tokens,
/// offer uuids, notification ids, challenge handles) are opaque and
/// stored hashed; backends must not attach meaning to them.
#[async_trait::async_trait]
pub trait SessionStore: Send + Sync {
    /// Insert a session created by the backend session API (creation
    /// index: offer uuid, notification id). Refuses duplicate ids.
    async fn insert(&self, record: SessionRecord) -> Result<()>;

    /// Insert a PAR session (request_uri handle == offer uuid).
    async fn insert_par_session(&self, record: SessionRecord) -> Result<()>;

    /// Fetch one session by id.
    async fn get(&self, id: &SessionId) -> Option<SessionRecord>;

    /// Apply a state-machine event under the store's atomicity and
    /// record history. Returns the post-transition record.
    async fn transition(
        &self,
        id: &SessionId,
        event: SessionEvent,
        now: i64,
    ) -> Result<SessionRecord>;

    /// Record the status-list reference allocated at issuance time
    /// (replaceable — a session may be (re)issued multiple times;
    /// OID4VCI §13.3).
    async fn set_status_ref(&self, id: &SessionId, status_ref: StatusRef) -> Result<()>;

    /// Redeem the pre-authorized code: single-use, atomic
    /// (Offered → Redeeming) or refusal (tx_code check included).
    async fn claim_pre_auth_code(
        &self,
        code: &str,
        tx_code: Option<&str>,
        now: i64,
    ) -> Result<SessionRecord>;

    /// Mode A authorize-complete: seal subject data, mint the
    /// authorization code (single-issuance), transition through the core
    /// machine (AwaitingAuthorization → Offered). Refuses a second mint.
    async fn complete_authorization(
        &self,
        offer_uuid: &str,
        subject_sealed: Vec<u8>,
        auth: AuthCodeBinding,
        auth_code_hash: String,
        now: i64,
    ) -> Result<()>;

    /// authorization_code at /token: consume the single-use code with
    /// redirect + client + PKCE S256 checks (RFC 7636 §4.6).
    async fn claim_auth_code(
        &self,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        code_verifier: &str,
        now: i64,
    ) -> Result<SessionRecord>;

    /// Read-only lookup by authorization code (no consumption): Mode B's
    /// DPoP sender-constraint check runs before the single-use claim, so
    /// a wrong key refuses without burning the code.
    async fn peek_auth_code(&self, code: &str) -> Option<SessionRecord>;

    /// Bind a hashed access token to a session (token endpoint), with
    /// its DPoP key thumbprint when sender-constrained.
    #[allow(clippy::type_complexity)]
    async fn bind_access_token(
        &self,
        token_hash: String,
        id: &SessionId,
        expires_unix: i64,
        dpop_jkt: Option<String>,
    ) -> Result<()>;

    /// Resolve an access token to its session and DPoP binding;
    /// expired tokens are absent.
    #[allow(clippy::type_complexity)]
    async fn session_by_access_token(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Option<(SessionId, Option<String>)>;

    /// Rotate the c_nonce (token and credential endpoints both return one).
    async fn rotate_c_nonce(&self, id: &SessionId, nonce: String, expires_unix: i64) -> Result<()>;

    /// Resolve an offer uuid (the credential-offer URI path).
    async fn find_by_offer_uuid(&self, offer_uuid: &str) -> Option<SessionRecord>;

    /// Resolve a notification id (the notification feedback loop).
    async fn find_by_notification_id(&self, notification_id: &str) -> Option<SessionRecord>;

    /// Drop the sealed subject data and the sealed pre-authorized code
    /// (DELETE / final states). The record skeleton survives: status
    /// feedback and the revocation handle outlive the data (§6.3, §9.3).
    async fn purge_subject_data(&self, id: &SessionId) -> Result<()>;

    /// Bind the owner (integrator subject id) of a wallet-initiated
    /// session at authorize-complete time (design §7.2).
    async fn set_owner(&self, id: &SessionId, owner_subject_id: String) -> Result<()>;

    /// Mark the session revoked (the status index flips in the status
    /// service by the caller).
    async fn set_revoked(&self, id: &SessionId) -> Result<()>;

    /// Mode B (§7.3 step 2): arm the OID4VP exchange — the sealed
    /// verifier-core session and the challenge's DPoP jkt. One pending
    /// exchange per session.
    async fn set_mode_b(
        &self,
        id: &SessionId,
        mode_b: ModeBState,
        challenge_jkt: Option<String>,
    ) -> Result<()>;

    /// Mode B step 3: consume the pending exchange by its challenge
    /// handle (single-use, atomic — the ephemeral key dies with the
    /// take). Returns the record and the sealed verifier-core session.
    async fn take_mode_b(&self, challenge_handle: &str) -> Option<(SessionRecord, Vec<u8>)>;

    /// Deferred issuance (§7.6): arm a transaction on a `pending`
    /// session — the wallet polls `/deferred-credential` with the
    /// transaction id. Single-arm: a second arm refuses.
    async fn set_transaction(&self, id: &SessionId, transaction_id_hash: String) -> Result<()>;

    /// Deferred issuance: consume a pending transaction by its
    /// transaction-id hash. Returns the session record iff the
    /// transaction is pending and claimed atomically (single-use —
    /// completion transitions `issued` exactly once); `None` when
    /// absent or already claimed.
    async fn take_transaction(&self, transaction_id_hash: &str) -> Option<SessionRecord>;

    /// The retention sweeper (design §6.3): expire, purge, hard-delete.
    /// One call, three phases, under the backend's own atomicity:
    ///
    /// 1. **Expire**: sessions in `awaiting_authorization`/`offered`
    ///    past their expiry transition `TtlExpired` through the core
    ///    state machine (the backend never invents a transition) —
    ///    the returned ids broadcast on the SSE stream like every
    ///    other transition (§7.7: one state machine, two audiences).
    /// 2. **Purge**: records in a **non-reissuable** final state
    ///    (`failed`, `expired`) still carrying sealed subject data
    ///    drop it (§6.3). `accepted`/`deleted` sessions KEEP their
    ///    sealed data until the hard delete — they stay re-issuable
    ///    (§13.3 multiple accesses; the suite's additional-requests
    ///    module re-issues after credential_accepted — reconciled).
    ///    The DELETE endpoint purges immediately. The record skeleton
    ///    survives every purge: status feedback and the revocation
    ///    handle outlive the data (§9.3).
    /// 3. **Hard-delete**: records final for longer than
    ///    `retention_after_final_secs` (measured from their final
    ///    transition) are removed entirely, indices included.
    async fn sweep(&self, now: i64, retention_after_final_secs: i64) -> Result<SweepReport>;
}

/// What one sweep pass did (for logging and the SSE broadcast).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// Sessions transitioned `TtlExpired` this pass (SSE `expired`).
    pub expired_ids: Vec<String>,
    /// Final records whose sealed subject data was dropped this pass.
    pub purged: usize,
    /// Records hard-deleted past the retention window this pass.
    pub deleted: usize,
}

/// The in-memory backend: tests and single-process dev. The first
/// (and reference) [`SessionStore`] — the production MongoDB backend
/// implements the same contract with atomic compare-and-set operations.
#[async_trait::async_trait]
impl SessionStore for MemoryStore {
    async fn insert(&self, record: SessionRecord) -> Result<()> {
        MemoryStore::insert(self, record)
    }

    async fn insert_par_session(&self, record: SessionRecord) -> Result<()> {
        MemoryStore::insert_par_session(self, record)
    }

    async fn get(&self, id: &SessionId) -> Option<SessionRecord> {
        MemoryStore::get(self, id)
    }

    async fn transition(
        &self,
        id: &SessionId,
        event: SessionEvent,
        now: i64,
    ) -> Result<SessionRecord> {
        MemoryStore::transition(self, id, event, now)
    }

    async fn set_status_ref(&self, id: &SessionId, status_ref: StatusRef) -> Result<()> {
        MemoryStore::set_status_ref(self, id, status_ref)
    }

    async fn claim_pre_auth_code(
        &self,
        code: &str,
        tx_code: Option<&str>,
        now: i64,
    ) -> Result<SessionRecord> {
        MemoryStore::claim_pre_auth_code(self, code, tx_code, now)
    }

    async fn complete_authorization(
        &self,
        offer_uuid: &str,
        subject_sealed: Vec<u8>,
        auth: AuthCodeBinding,
        auth_code_hash: String,
        now: i64,
    ) -> Result<()> {
        MemoryStore::complete_authorization(
            self,
            offer_uuid,
            subject_sealed,
            auth,
            auth_code_hash,
            now,
        )
    }

    async fn claim_auth_code(
        &self,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        code_verifier: &str,
        now: i64,
    ) -> Result<SessionRecord> {
        MemoryStore::claim_auth_code(self, code, redirect_uri, client_id, code_verifier, now)
    }

    async fn peek_auth_code(&self, code: &str) -> Option<SessionRecord> {
        MemoryStore::peek_auth_code(self, code)
    }

    async fn bind_access_token(
        &self,
        token_hash: String,
        id: &SessionId,
        expires_unix: i64,
        dpop_jkt: Option<String>,
    ) -> Result<()> {
        MemoryStore::bind_access_token(self, token_hash, id, expires_unix, dpop_jkt)
    }

    async fn session_by_access_token(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Option<(SessionId, Option<String>)> {
        MemoryStore::session_by_access_token(self, token_hash, now)
    }

    async fn rotate_c_nonce(&self, id: &SessionId, nonce: String, expires_unix: i64) -> Result<()> {
        MemoryStore::rotate_c_nonce(self, id, nonce, expires_unix)
    }

    async fn find_by_offer_uuid(&self, offer_uuid: &str) -> Option<SessionRecord> {
        MemoryStore::find_by_offer_uuid(self, offer_uuid)
    }

    async fn find_by_notification_id(&self, notification_id: &str) -> Option<SessionRecord> {
        MemoryStore::find_by_notification_id(self, notification_id)
    }

    async fn purge_subject_data(&self, id: &SessionId) -> Result<()> {
        MemoryStore::purge_subject_data(self, id)
    }

    async fn set_owner(&self, id: &SessionId, owner_subject_id: String) -> Result<()> {
        MemoryStore::set_owner(self, id, owner_subject_id)
    }

    async fn set_revoked(&self, id: &SessionId) -> Result<()> {
        MemoryStore::set_revoked(self, id)
    }

    async fn set_mode_b(
        &self,
        id: &SessionId,
        mode_b: ModeBState,
        challenge_jkt: Option<String>,
    ) -> Result<()> {
        MemoryStore::set_mode_b(self, id, mode_b, challenge_jkt)
    }

    async fn take_mode_b(&self, challenge_handle: &str) -> Option<(SessionRecord, Vec<u8>)> {
        MemoryStore::take_mode_b(self, challenge_handle)
    }

    async fn set_transaction(&self, id: &SessionId, transaction_id_hash: String) -> Result<()> {
        MemoryStore::set_transaction(self, id, transaction_id_hash)
    }

    async fn take_transaction(&self, transaction_id_hash: &str) -> Option<SessionRecord> {
        MemoryStore::take_transaction(self, transaction_id_hash)
    }

    async fn sweep(&self, now: i64, retention_after_final_secs: i64) -> Result<SweepReport> {
        MemoryStore::sweep(self, now, retention_after_final_secs)
    }
}

impl MemoryStore {
    /// The in-memory sweep (the trait docs above are the contract).
    pub fn sweep(&self, now: i64, retention_after_final_secs: i64) -> Result<SweepReport> {
        use siros_issuer_core::session::{SessionEvent as Ev, SessionState as St};

        let mut inner = self.lock()?;
        let mut report = SweepReport::default();
        let ids: Vec<SessionId> = inner.records.keys().cloned().collect();

        let final_at = |record: &SessionRecord| -> Option<i64> {
            // The last transition INTO a final state (from history; the
            // Sweeper itself appends it, so a session expired this pass
            // still measures from now — correct, its retention starts
            // at the expiry).
            record
                .history
                .iter()
                .rev()
                .find(|(_, label)| {
                    matches!(
                        label.as_str(),
                        "accepted" | "failed" | "expired" | "deleted"
                    )
                })
                .map(|(unix, _)| *unix)
        };

        for id in ids {
            let Some(record) = inner.records.get(&id) else {
                continue;
            };
            // 1. Expire (TtlExpired) — the machine's legal transitions.
            let expired_now = record.expires_at_unix <= now
                && matches!(record.state, St::AwaitingAuthorization | St::Offered);
            let is_final = record.state.is_final() || expired_now;
            let final_unix = if is_final {
                final_at(record).or(Some(now))
            } else {
                None
            };
            // Snapshot the index keys before the mutable work (the
            // record borrow ends here).
            let offer_uuid = record.offer_uuid.clone();
            let pre_auth_hash = record.pre_authorized_code_hash.clone();
            let auth_code_hash = record.auth_code_hash.clone();
            let notification_id = record.notification_id.clone();
            let mode_b_handle = record.mode_b.as_ref().map(|m| m.challenge_handle.clone());
            let carries_sealed = record.sealed.is_some();

            if expired_now {
                let record = inner
                    .records
                    .get_mut(&id)
                    .ok_or_else(|| Error::invalid_input("session vanished mid-sweep"))?;
                record.state = machine(record.state, Ev::TtlExpired)?;
                record.history.push((now, record.state.label().to_owned()));
                report.expired_ids.push(id.as_str().to_owned());
            }
            // 2. Purge sealed subject data off NON-REISSUABLE finals
            //    (failed/expired); accepted/deleted keep it until the
            //    hard delete (§13.3 re-issuance).
            let purged_now = is_final
                && carries_sealed
                && matches!(
                    inner.records.get(&id).map(|r| &r.state),
                    Some(St::Failed | St::Expired)
                );
            if purged_now {
                let record = inner
                    .records
                    .get_mut(&id)
                    .ok_or_else(|| Error::invalid_input("session vanished mid-sweep"))?;
                record.sealed = None;
                record.pre_authorized_code_sealed = None;
                // The pending Mode B exchange (sealed verifier-core
                // session, ephemeral key inside) dies with the data —
                // usually already taken at the response.
                if let Some(mode_b) = record.mode_b.take() {
                    inner.by_challenge_handle.remove(&mode_b.challenge_handle);
                }
                report.purged += 1;
            }
            // 3. Hard-delete past the retention window (measured from
            //    the final transition).
            if final_unix.is_some_and(|f| now >= f + retention_after_final_secs) {
                if let Some(uuid) = offer_uuid {
                    inner.by_offer_uuid.remove(&uuid);
                }
                if let Some(hash) = pre_auth_hash {
                    inner.by_pre_auth.remove(&hash);
                }
                if let Some(hash) = auth_code_hash {
                    inner.by_auth_code.remove(&hash);
                }
                inner.by_notification.remove(&notification_id);
                if let Some(handle) = mode_b_handle {
                    inner.by_challenge_handle.remove(&handle);
                }
                // Access-token bindings die with the record.
                inner
                    .by_access_token
                    .retain(|_, (bound, _, _)| bound != &id);
                inner.records.remove(&id);
                report.deleted += 1;
            }
        }
        Ok(report)
    }
}
