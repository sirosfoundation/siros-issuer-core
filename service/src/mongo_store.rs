//! MongoDB session storage (design §6.4: the production backend behind
//! `SessionStore`). The in-memory store is the reference implementation;
//! this is the deployment backend — atomic single-use claims across
//! replicas, TTL-indexed retention.
//!
//! House style: verifier-core's `mongo_store.rs` — a wrapped record
//! type (nested `record`, not flattened: dotted `$set`/`$unset` paths
//! must address real fields), `find_one_and_update` compare-and-set for
//! the single-use claims (the state filter IS the machine legality
//! check: a claim succeeds only from the exact pre-state the core state
//! machine permits), a TTL index for the retention hard-delete
//! (MongoDB expires `retain_at` natively), and per-op time bounds.
//!
//! Access-token bindings are raw documents in the same collection,
//! marked `binding: true` (their `_id` is the token hash) — the same
//! one-collection contract the memory store keeps with its index maps.
//!
//! State transitions: the CAS update writes the post-state the machine
//! allows from the filtered pre-state — never invented here.

use std::time::Duration;

use mongodb::bson::{self, doc, DateTime, Document};
use mongodb::options::{FindOneAndUpdateOptions, IndexOptions, ReturnDocument};
use mongodb::{Client, Collection, IndexModel};
use serde::{Deserialize, Serialize};

use crate::store::StateLabel as _;
use siros_issuer_core::session::{SessionEvent, SessionId, SessionState};
use siros_issuer_core::{Error, Result};

use crate::store::{AuthCodeBinding, ModeBState, SessionRecord, SessionStore, SweepReport};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const RETENTION_INDEX: &str = "retain_at_ttl";

/// The stored session document: the record (nested — dotted update
/// paths address its real fields), the hash/handle index copies
/// (findable keys; the record's own fields remain the source of truth),
/// and the BSON DateTime a TTL index expires on.
#[derive(Debug, Serialize, Deserialize)]
struct MongoSession {
    /// The session id (the document `_id`).
    #[serde(rename = "_id")]
    id: String,
    record: SessionRecord,
    /// sha256 of the pre-authorized code — the find index copy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_authorized_code_hash: Option<String>,
    /// sha256 of the authorization code — the find index copy.
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_code_hash: Option<String>,
    /// The Mode B challenge handle — the take index copy.
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_handle: Option<String>,
    /// TTL: `final_at + retention` on final records (the hard delete,
    /// §6.3), `created + retention` on live ones (an upper bound: a
    /// session that never finalizes still dies).
    retain_at: DateTime,
}

impl MongoSession {
    fn new(record: SessionRecord, retention_after_final_secs: i64, now: i64) -> Self {
        let base = if record.state.is_final() {
            now
        } else {
            record.created_at_unix
        };
        Self {
            id: record.id.as_str().to_owned(),
            pre_authorized_code_hash: record.pre_authorized_code_hash.clone(),
            auth_code_hash: record.auth_code_hash.clone(),
            challenge_handle: record.mode_b.as_ref().map(|m| m.challenge_handle.clone()),
            retain_at: DateTime::from_millis(
                (base + retention_after_final_secs).saturating_mul(1000),
            ),
            record,
        }
    }
}

/// The MongoDB `SessionStore`. Untyped (`Collection<Document>`): session
/// documents and access-token binding documents share the collection
/// (marked), converting via `bson::to_document`/`from_document` — the
/// extra wrapper fields serde ignores on the `record` round-trip.
pub struct MongoStore {
    sessions: Collection<Document>,
    retention_after_final_secs: i64,
    /// The shared client (the rate counter connects over the same
    /// deployment MongoDB; tests reuse the handle).
    client: mongodb::Client,
}

impl MongoStore {
    /// The shared client handle (tests connect sibling services over
    /// the same deployment MongoDB).
    pub fn client(&self) -> &mongodb::Client {
        &self.client
    }
}

impl MongoStore {
    /// Connect and ensure indexes. `database`/`collection` are the
    /// deployment's clean separation (design §6.4) — one tenant per
    /// database, purely from config.
    pub async fn connect(
        uri: &str,
        database: &str,
        collection: &str,
        retention_after_final_secs: i64,
    ) -> Result<Self> {
        let options = mongodb::options::ClientOptions::parse(uri)
            .await
            .map_err(|e| Error::configuration(format!("MongoDB uri: {e}")))?;
        let client =
            Client::with_options(options).map_err(|e| Error::configuration(format!("{e}")))?;
        let sessions = client.database(database).collection::<Document>(collection);
        // TTL index: MongoDB expires `retain_at` natively (expireAfter=0
        // → at the DateTime itself) — the retention hard-delete, §6.3.
        let index = IndexModel::builder()
            .keys(doc! { "retain_at": 1 })
            .options(
                IndexOptions::builder()
                    .name(RETENTION_INDEX.to_owned())
                    .expire_after(Duration::from_secs(0))
                    .build(),
            )
            .build();
        let store = Self {
            sessions,
            retention_after_final_secs,
            client,
        };
        store
            .sessions
            .create_index(index)
            .await
            .map_err(|e| Error::configuration(format!("creating the retention index: {e}")))?;
        Ok(store)
    }

    /// Test support: re-create the retention index after a collection
    /// drop (`connect` creates it once).
    pub async fn create_test_index(&self) -> Result<()> {
        let index = IndexModel::builder()
            .keys(doc! { "retain_at": 1 })
            .options(
                IndexOptions::builder()
                    .name(RETENTION_INDEX.to_owned())
                    .expire_after(Duration::from_secs(0))
                    .build(),
            )
            .build();
        self.sessions
            .create_index(index)
            .await
            .map_err(|e| Error::configuration(format!("creating the retention index: {e}")))?;
        Ok(())
    }

    /// Test support: a store over a configured collection.
    pub fn with_collection(
        client: mongodb::Client,
        sessions: Collection<Document>,
        retention_after_final_secs: i64,
    ) -> Self {
        Self {
            sessions,
            retention_after_final_secs,
            client,
        }
    }

    fn wrap(&self, record: SessionRecord, now: i64) -> Result<Document> {
        let wrapped = MongoSession::new(record, self.retention_after_final_secs, now);
        bson::to_document(&wrapped)
            .map_err(|e| Error::invalid_input(format!("session document: {e}")))
    }

    async fn load(&self, id: &SessionId) -> Result<Option<SessionRecord>> {
        let doc = self
            .sessions
            .find_one(doc! { "_id": id.as_str() })
            .max_time(OPERATION_TIMEOUT)
            .await
            .map_err(mongo_error)?;
        let Some(doc) = doc else {
            return Ok(None);
        };
        let record = record_of(&doc)?;
        Ok(Some(record))
    }

    /// CAS: conditional update from `expected_state`; returns the
    /// post-record. A miss (wrong state, absent) is `None`.
    async fn cas(
        &self,
        id: &SessionId,
        expected_state: Option<&str>,
        update: Document,
    ) -> Result<Option<SessionRecord>> {
        let mut filter = doc! { "_id": id.as_str() };
        if let Some(state) = expected_state {
            filter.insert("record.state", state);
        }
        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();
        let doc = self
            .sessions
            .find_one_and_update(filter, update)
            .with_options(options)
            .max_time(OPERATION_TIMEOUT)
            .await
            .map_err(mongo_error)?;
        doc.map(|d| record_of(&d)).transpose()
    }

    /// The machine-checked transition document for `event` from
    /// `record` (history bounded, post-state from the machine).
    fn transition_update(
        &self,
        record: &SessionRecord,
        event: SessionEvent,
        now: i64,
    ) -> Result<(Document, Option<i64>, &'static str)> {
        let next = siros_issuer_core::session::transition(record.state, event)?;
        let mut history = record.history.clone();
        history.push((now, next.label().to_owned()));
        if history.len() > 64 {
            history.remove(0);
        }
        let mut set = doc! {
            "record.state": next.label(),
            "record.history": bson::to_bson(&history)
                .map_err(|e| Error::invalid_input(format!("history: {e}")))?,
        };
        let final_at = if next.is_final() {
            // Retention starts at the final transition (§6.3): the TTL
            // index hard-deletes there.
            let retain =
                DateTime::from_millis((now + self.retention_after_final_secs).saturating_mul(1000));
            set.insert("retain_at", retain);
            Some(now)
        } else {
            None
        };
        Ok((doc! { "$set": set }, final_at, next.label()))
    }
}

fn record_of(doc: &Document) -> Result<SessionRecord> {
    // The record is nested (`record: …`) under the wrapper's index
    // copies; bindings never route through here (raw fields).
    let record = doc
        .get_document("record")
        .map_err(|e| Error::invalid_input(format!("session document decode: {e}")))?;
    bson::from_document::<SessionRecord>(record.clone())
        .map_err(|e| Error::invalid_input(format!("session document decode: {e}")))
}

#[async_trait::async_trait]
impl SessionStore for MongoStore {
    async fn insert(&self, record: SessionRecord) -> Result<()> {
        let now = crate::status::now_unix();
        // `_id` is the session id: a duplicate insert is a driver
        // duplicate-key refusal (the session API generates the ids).
        let doc = self.wrap(record, now)?;
        self.sessions.insert_one(doc).await.map_err(mongo_error)?;
        Ok(())
    }

    async fn insert_par_session(&self, record: SessionRecord) -> Result<()> {
        self.insert(record).await
    }

    async fn get(&self, id: &SessionId) -> Option<SessionRecord> {
        self.load(id).await.ok().flatten()
    }

    /// Apply an event: read, machine-check, CAS from the exact
    /// pre-state. A concurrent transition between the read and the CAS
    /// misses the filter → `illegal_transition` (retryable by the
    /// caller, matching the contract's atomicity requirement).
    async fn transition(
        &self,
        id: &SessionId,
        event: SessionEvent,
        now: i64,
    ) -> Result<SessionRecord> {
        let record = self
            .load(id)
            .await?
            .ok_or_else(|| Error::invalid_input("unknown session"))?;
        let (update, _final_at, _label) = self.transition_update(&record, event, now)?;
        self.cas(id, Some(record.state.label()), update)
            .await?
            .ok_or_else(|| Error::illegal_transition("the session changed under us"))
    }

    async fn set_status_ref(&self, id: &SessionId, status_ref: StatusRef) -> Result<()> {
        let value = bson::to_bson(&status_ref)
            .map_err(|e| Error::invalid_input(format!("status ref: {e}")))?;
        self.sessions
            .update_one(
                doc! { "_id": id.as_str() },
                doc! { "$set": { "record.status_ref": value } },
            )
            .await
            .map_err(mongo_error)?;
        Ok(())
    }

    /// Redeem the pre-authorized code: atomic (Offered → Redeeming)
    /// against the code-hash index — the CAS filter IS the single-use
    /// enforcement (a second redemption misses the `offered` leg).
    async fn claim_pre_auth_code(
        &self,
        code: &str,
        tx_code: Option<&str>,
        now: i64,
    ) -> Result<SessionRecord> {
        use sha2::{Digest, Sha256};
        let code_hash = hex(&Sha256::digest(code.as_bytes()));
        // tx_code check BEFORE the claim (never burns the code on a
        // wrong tx).
        let record = self
            .sessions
            .find_one(doc! {
                "pre_authorized_code_hash": &code_hash,
                "record.expires_at_unix": { "$gt": now },
            })
            .await
            .map_err(mongo_error)?
            .map(|d| record_of(&d))
            .transpose()?
            .ok_or_else(|| Error::invalid_input("unknown pre-authorized code"))?;
        if let Some(expected_hash) = &record.tx_code_hash {
            let given = tx_code.ok_or_else(|| Error::invalid_input("tx_code required"))?;
            if hex(&Sha256::digest(given.as_bytes())) != *expected_hash {
                return Err(Error::invalid_input("tx_code mismatch"));
            }
        }
        let (update, _f, _l) = self.transition_update(&record, SessionEvent::Redeemed, now)?;
        let filter = doc! {
            "pre_authorized_code_hash": &code_hash,
            "record.state": SessionState::Offered.label(),
            "record.expires_at_unix": { "$gt": now },
        };
        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();
        let claimed = self
            .sessions
            .find_one_and_update(filter, update)
            .with_options(options)
            .await
            .map_err(mongo_error)?
            .ok_or_else(|| Error::invalid_input("pre-authorized code already redeemed"))?;
        record_of(&claimed)
    }

    /// Mode A authorize-complete: CAS on `auth_code_hash` absent (the
    /// single-issuance mint) and the awaiting state.
    async fn complete_authorization(
        &self,
        offer_uuid: &str,
        subject_sealed: Vec<u8>,
        auth: AuthCodeBinding,
        auth_code_hash: String,
        now: i64,
    ) -> Result<()> {
        let record = self
            .sessions
            .find_one(doc! { "record.offer_uuid": offer_uuid })
            .await
            .map_err(mongo_error)?
            .map(|d| record_of(&d))
            .transpose()?
            .ok_or_else(|| Error::invalid_input("no such authorization request"))?;
        let mut history = record.history.clone();
        history.push((now, SessionState::Offered.label().to_owned()));
        let update = doc! {
            "$set": {
                "record.state": SessionState::Offered.label(),
                "record.sealed": bson::to_bson(&subject_sealed)
                    .map_err(|e| Error::invalid_input(format!("sealed: {e}")))?,
                "record.auth": bson::to_bson(&auth)
                    .map_err(|e| Error::invalid_input(format!("auth: {e}")))?,
                "record.history": bson::to_bson(&history).expect("history serializes"),
                // The index copy (the CAS leg above proves it absent).
                "auth_code_hash": &auth_code_hash,
            }
        };
        let filter = doc! {
            "_id": record.id.as_str(),
            "record.state": SessionState::AwaitingAuthorization.label(),
            "auth_code_hash": { "$exists": false },
        };
        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();
        self.sessions
            .find_one_and_update(filter, update)
            .with_options(options)
            .max_time(OPERATION_TIMEOUT)
            .await
            .map_err(mongo_error)?
            .ok_or_else(|| Error::illegal_transition("authorization code already minted"))?;
        Ok(())
    }

    /// authorization_code at /token: PKCE checks on the read, then CAS
    /// Offered → Redeeming against the code-hash index (single-use).
    async fn claim_auth_code(
        &self,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        code_verifier: &str,
        now: i64,
    ) -> Result<SessionRecord> {
        use sha2::{Digest, Sha256};
        let code_hash = hex(&Sha256::digest(code.as_bytes()));
        let record = self
            .sessions
            .find_one(doc! { "auth_code_hash": &code_hash })
            .await
            .map_err(mongo_error)?
            .map(|d| record_of(&d))
            .transpose()?
            .ok_or_else(|| Error::invalid_input("unknown authorization code"))?;
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
        let computed =
            siros_issuer_core::sdjwt_issue::b64u(&Sha256::digest(code_verifier.as_bytes()));
        if !constant_time_eq(computed.as_bytes(), binding.code_challenge.as_bytes()) {
            return Err(Error::invalid_input("PKCE code_verifier mismatch"));
        }
        let (update, _f, _l) = self.transition_update(&record, SessionEvent::Redeemed, now)?;
        let filter = doc! {
            "auth_code_hash": &code_hash,
            "record.state": SessionState::Offered.label(),
        };
        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();
        let claimed = self
            .sessions
            .find_one_and_update(filter, update)
            .with_options(options)
            .await
            .map_err(mongo_error)?
            .ok_or_else(|| Error::invalid_input("authorization code already redeemed"))?;
        record_of(&claimed)
    }

    async fn peek_auth_code(&self, code: &str) -> Option<SessionRecord> {
        use sha2::{Digest, Sha256};
        let code_hash = hex(&Sha256::digest(code.as_bytes()));
        self.sessions
            .find_one(doc! { "auth_code_hash": &code_hash })
            .max_time(OPERATION_TIMEOUT)
            .await
            .ok()
            .flatten()
            .and_then(|d| record_of(&d).ok())
    }

    /// Access-token bindings are marked raw documents, `_id` = the
    /// token hash (the memory store's index map, Mongo-shaped).
    async fn bind_access_token(
        &self,
        token_hash: String,
        id: &SessionId,
        expires_unix: i64,
        dpop_jkt: Option<String>,
    ) -> Result<()> {
        let doc = doc! {
            "_id": token_hash,
            "binding": true,
            "session_id": id.as_str(),
            "expires_unix": expires_unix,
            "dpop_jkt": dpop_jkt,
            "retain_at": DateTime::from_millis(expires_unix.saturating_mul(1000)),
        };
        self.sessions.insert_one(doc).await.map_err(mongo_error)?;
        Ok(())
    }

    async fn session_by_access_token(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Option<(SessionId, Option<String>)> {
        let binding = self
            .sessions
            .find_one(doc! {
                "_id": token_hash,
                "binding": true,
                "expires_unix": { "$gt": now },
            })
            .await
            .ok()??;
        let id = binding.get_str("session_id").ok()?.to_owned();
        let jkt = binding.get_str("dpop_jkt").ok().map(str::to_owned);
        Some((SessionId::from_hex(&id).ok()?, jkt))
    }

    async fn rotate_c_nonce(&self, id: &SessionId, nonce: String, expires_unix: i64) -> Result<()> {
        self.sessions
            .update_one(
                doc! { "_id": id.as_str() },
                doc! { "$set": {
                    "record.c_nonce": nonce,
                    "record.c_nonce_expires_unix": expires_unix,
                }},
            )
            .await
            .map_err(mongo_error)?;
        Ok(())
    }

    async fn find_by_offer_uuid(&self, offer_uuid: &str) -> Option<SessionRecord> {
        self.sessions
            .find_one(doc! { "record.offer_uuid": offer_uuid })
            .max_time(OPERATION_TIMEOUT)
            .await
            .ok()
            .flatten()
            .and_then(|d| record_of(&d).ok())
    }

    async fn find_by_notification_id(&self, notification_id: &str) -> Option<SessionRecord> {
        self.sessions
            .find_one(doc! { "record.notification_id": notification_id })
            .max_time(OPERATION_TIMEOUT)
            .await
            .ok()
            .flatten()
            .and_then(|d| record_of(&d).ok())
    }

    /// Drop the sealed data (+ the pending Mode B exchange): `$unset`
    /// — the skeleton survives (§6.3).
    async fn purge_subject_data(&self, id: &SessionId) -> Result<()> {
        self.sessions
            .update_one(
                doc! { "_id": id.as_str() },
                doc! { "$unset": {
                    "record.sealed": "",
                    "record.pre_authorized_code_sealed": "",
                    "record.mode_b": "",
                    "challenge_handle": "",
                }},
            )
            .await
            .map_err(mongo_error)?;
        Ok(())
    }

    async fn set_owner(&self, id: &SessionId, owner_subject_id: String) -> Result<()> {
        self.sessions
            .update_one(
                doc! { "_id": id.as_str() },
                doc! { "$set": { "record.owner_subject_id": owner_subject_id } },
            )
            .await
            .map_err(mongo_error)?;
        Ok(())
    }

    async fn set_revoked(&self, id: &SessionId) -> Result<()> {
        self.sessions
            .update_one(
                doc! { "_id": id.as_str() },
                doc! { "$set": { "record.revoked": true } },
            )
            .await
            .map_err(mongo_error)?;
        Ok(())
    }

    /// One pending exchange per session: the `$exists: false` leg
    /// refuses a second arm.
    async fn set_mode_b(
        &self,
        id: &SessionId,
        mode_b: ModeBState,
        challenge_jkt: Option<String>,
    ) -> Result<()> {
        let handle = mode_b.challenge_handle.clone();
        let mode_b_doc =
            bson::to_bson(&mode_b).map_err(|e| Error::invalid_input(format!("mode b: {e}")))?;
        let result = self
            .sessions
            .update_one(
                doc! {
                    "_id": id.as_str(),
                    "challenge_handle": { "$exists": false },
                },
                doc! {
                    "$set": {
                        "record.mode_b": mode_b_doc,
                        "record.challenge_jkt": challenge_jkt,
                        "challenge_handle": handle,
                    }
                },
            )
            .await
            .map_err(mongo_error)?;
        if result.modified_count == 0 {
            return Err(Error::illegal_transition(
                "an authorization challenge is already pending for this session",
            ));
        }
        Ok(())
    }

    /// Mode B step 3: `find_one_and_delete` by the handle — atomic
    /// single-use; the ephemeral key dies with the delete.
    async fn take_mode_b(&self, challenge_handle: &str) -> Option<(SessionRecord, Vec<u8>)> {
        let deleted = self
            .sessions
            .find_one_and_delete(doc! { "challenge_handle": challenge_handle })
            .await
            .ok()??;
        let record = record_of(&deleted).ok()?;
        let sealed = record.mode_b.as_ref().map(|m| m.sealed_session.clone())?;
        Some((record, sealed))
    }

    /// Deferred issuance (§7.6): arm — a compare-and-set on the
    /// transaction index (single-arm server-side: the filter demands the
    /// index absent AND the session `pending`).
    async fn set_transaction(
        &self,
        id: &SessionId,
        transaction_id_hash: String,
        holder_jwks: Vec<serde_json::Value>,
    ) -> Result<()> {
        let holder_jwks_doc =
            bson::to_bson(&holder_jwks).map_err(|e| Error::invalid_input(format!("jwks: {e}")))?;
        let result = self
            .sessions
            .update_one(
                doc! {
                    "_id": id.as_str(),
                    "transaction_id_hash": { "$exists": false },
                    "record.state": "pending",
                },
                doc! {
                    "$set": {
                        "record.transaction_id_hash": transaction_id_hash.clone(),
                        "record.pending_holder_jwks": holder_jwks_doc,
                        "transaction_id_hash": transaction_id_hash,
                    }
                },
            )
            .await
            .map_err(mongo_error)?;
        if result.modified_count == 0 {
            return Err(Error::illegal_transition(
                "a deferred transaction arms only on a pending, unarmed session",
            ));
        }
        Ok(())
    }

    /// Deferred issuance: consume — `find_one_and_update` unsets the
    /// transaction arm (filtered to the access token's own session) and
    /// returns the BEFORE-picture (the armed snapshot, holder JWKs
    /// intact) in one server-side step: the session survives (it
    /// transitions `issued`), the arm does not (single-use, atomic). A
    /// second take misses the index; another principal's poll never
    /// matches the filter and never burns the arm.
    async fn take_transaction(
        &self,
        transaction_id_hash: &str,
        session_id: &SessionId,
    ) -> Option<SessionRecord> {
        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::Before)
            .build();
        let before = self
            .sessions
            .find_one_and_update(
                doc! {
                    "transaction_id_hash": transaction_id_hash,
                    "_id": session_id.as_str(),
                },
                doc! {
                    "$unset": {
                        "transaction_id_hash": "",
                        "record.transaction_id_hash": "",
                        "record.pending_holder_jwks": "",
                    }
                },
            )
            .with_options(options)
            .max_time(OPERATION_TIMEOUT)
            .await
            .ok()??;
        record_of(&before).ok()
    }

    /// The sweep (§6.3). Pass 3 (the hard delete) is MongoDB's own: the
    /// TTL index expires `retain_at` asynchronously (the transition
    /// updates keep it current). This pass does the expire + purge
    /// phases.
    async fn sweep(&self, now: i64, _retention_after_final_secs: i64) -> Result<SweepReport> {
        use SessionState as St;
        let mut report = SweepReport::default();

        // 1. Expire: awaiting/offered past their ttl → expired
        // (machine transitions, retention from the expiry).
        let filter = doc! {
            "record.state": {
                "$in": [St::AwaitingAuthorization.label(), St::Offered.label()]
            },
            "record.expires_at_unix": { "$lte": now },
            "binding": { "$exists": false },
        };
        let mut cursor = self
            .sessions
            .find(filter)
            .max_time(OPERATION_TIMEOUT)
            .await
            .map_err(mongo_error)?;
        let mut expired = Vec::new();
        while cursor.advance().await.map_err(mongo_error)? {
            let doc = cursor.deserialize_current().map_err(mongo_error)?;
            expired.push(record_of(&doc)?);
        }
        for record in &expired {
            let mut history = record.history.clone();
            history.push((now, St::Expired.label().to_owned()));
            let update = doc! {
                "$set": {
                    "record.state": St::Expired.label(),
                    "record.history": bson::to_bson(&history).expect("history serializes"),
                    "retain_at": DateTime::from_millis(
                        (now + self.retention_after_final_secs).saturating_mul(1000)
                    ),
                }
            };
            self.sessions
                .update_one(doc! { "_id": record.id.as_str() }, update)
                .await
                .map_err(mongo_error)?;
            report.expired_ids.push(record.id.as_str().to_owned());
        }

        // 2. Purge: non-reissuable finals (failed/expired) still
        // sealed (§6.3 — accepted/deleted keep, §13.3 re-issuance).
        let purged = self
            .sessions
            .update_many(
                doc! {
                    "record.state": { "$in": [St::Failed.label(), St::Expired.label()] },
                    "record.sealed": { "$exists": true },
                    "binding": { "$exists": false },
                },
                doc! { "$unset": {
                    "record.sealed": "",
                    "record.pre_authorized_code_sealed": "",
                    "record.mode_b": "",
                }},
            )
            .await
            .map_err(mongo_error)?;
        report.purged = purged.modified_count as usize;

        // 3. Hard delete: the TTL index (async; nothing here).
        report.deleted = 0;
        Ok(report)
    }
}

use siros_issuer_core::status_client::StatusRef;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn mongo_error(e: mongodb::error::Error) -> Error {
    Error::new(
        siros_issuer_core::error::code::TRANSPORT,
        format!("MongoDB: {e}"),
    )
}
