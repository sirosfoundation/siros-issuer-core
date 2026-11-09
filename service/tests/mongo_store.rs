//! The MongoDB `SessionStore` e2e (design §6.4): the production backend
//! proves out against a **real mongod** — gated on the `mongo` feature
//! (the same feature gates the backend itself; default builds run the
//! memory-store suites).
#![cfg(feature = "mongo")]
//! proves out against a **real mongod** — CAS single-use claims across
//! the wire, TTL-indexed retention, atomic mode-B takes.
//!
//! Sources of truth: the `SessionStore` contract (atomic single-use
//! offer/code/challenge claims — a claim raced from two tasks succeeds
//! exactly once; state transitions come from the core machine), PKCE
//! (RFC 7636 §4.6), and §6.3's retention (expire → purge → hard-delete).
//!
//! Connects to `mongodb://127.0.0.1:27017` (env
//! `SIROS_MONGO_TEST_URI`); skips when no mongod answers — the
//! backend is optional (dev/test builds default to the memory store).

use std::sync::Arc;

use serde_json::json;
use siros_issuer_core::session::{SessionEvent, SessionId, SessionState as St};
use siros_issuer_service::mongo_store::MongoStore;
use siros_issuer_service::rate_limit::RateCounter as _;
use siros_issuer_service::store::{
    AuthCodeBinding, ModeBState, SessionRecord, SessionStore, SweepReport,
};
use url::Url;

const DEFAULT_URI: &str = "mongodb://127.0.0.1:27017";
const DB: &str = "siros_issuer_store_test";
const RETENTION: i64 = 3_600;

/// A session id from the host clock (unique per call).
fn session_id(tag: u64) -> SessionId {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    SessionId::from_hex(&format!("{tag:016x}{nanos:016x}")).unwrap()
}

/// A record seeded into a fresh collection.
fn record(id: &SessionId, state: St, expires_at: i64) -> SessionRecord {
    SessionRecord {
        id: id.clone(),
        grant: siros_issuer_core::session::GrantKind::PreAuthorized,
        state,
        owner_subject_id: "integrator".to_owned(),
        credential_configuration_id: "urn:eudi:pid:1".to_owned(),
        sealed: Some(vec![1, 2, 3]),
        offer_uuid: Some(format!("offer-{}", id.as_str())),
        pre_authorized_code_hash: Some(format!("pre-{}", id.as_str())),
        pre_authorized_code_sealed: Some(vec![4, 5, 6]),
        tx_code_hash: None,
        transaction_id_hash: None,
        pending_holder_jwks: None,
        identity_match_sealed: None,
        tx_code_spec: None,
        auth: None,
        auth_code_hash: None,
        challenge_jkt: None,
        mode_b: None,
        c_nonce: "n".to_owned(),
        c_nonce_expires_unix: expires_at + 300,
        status_ref: None,
        notification_id: format!("ntf-{}", id.as_str()),
        revoked: false,
        created_at_unix: expires_at - 300,
        expires_at_unix: expires_at,
        history: Vec::new(),
    }
}

/// Connect or skip. Each test gets its own collection (dropped after)
/// for isolation.
async fn store(
    name: &str,
) -> Option<(
    Arc<MongoStore>,
    mongodb::Collection<mongodb::bson::Document>,
)> {
    let uri = std::env::var("SIROS_MONGO_TEST_URI").unwrap_or_else(|_| DEFAULT_URI.to_owned());
    let store = MongoStore::connect(&uri, DB, name, RETENTION).await.ok()?;
    let client = mongodb::Client::with_uri_str(&uri).await.ok()?;
    let coll = client
        .database(DB)
        .collection::<mongodb::bson::Document>(name);
    // Fresh collection per run (leftovers from a failed run would
    // otherwise pollute the sweep's expiry assertions).
    let _ = coll.drop().await;
    let _ = store.create_test_index().await;
    Some((Arc::new(store), coll))
}

const NOW: i64 = 1_800_000_000;

/// The CAS single-use contract: two concurrent pre-authorized-code
/// claims against one stored code — exactly one wins.
#[tokio::test]
async fn pre_authorized_claim_is_single_use_across_concurrent_claims() {
    let Some((store, _coll)) = store("pre_auth_single_use").await else {
        eprintln!("skipping: no mongod at {DEFAULT_URI} — the host mongod");
        return;
    };
    let id = session_id(1);
    // The code string whose sha256 rides the record's index field.
    use sha2::{Digest, Sha256};
    let code = format!("pac-{}", id.as_str());
    let mut seeded = record(&id, St::Offered, NOW + 300);
    seeded.pre_authorized_code_hash = Some(
        seeded
            .pre_authorized_code_hash
            .as_deref()
            .unwrap_or("")
            .to_owned(),
    );
    // Seed with the real code hash (the index copy).
    let code_hash: String = seeded.pre_authorized_code_hash.clone().unwrap_or_default();
    let _ = code_hash;
    // Fix the record's hash to the real code (record_of reads it for tx
    // checks; the index copy is what the CAS finds by).
    seeded.pre_authorized_code_hash = Some(hex(&Sha256::digest(code.as_bytes())));
    store.insert(seeded).await.unwrap();

    // Two concurrent claims: exactly one wins.
    let (a, b) = tokio::join!(
        store.claim_pre_auth_code(&code, None, NOW),
        store.claim_pre_auth_code(&code, None, NOW),
    );
    let winners = [a.is_ok(), b.is_ok()].iter().filter(|w| **w).count();
    assert_eq!(winners, 1, "exactly one concurrent claim wins");
    if let Ok(won) = a {
        assert_eq!(won.state, St::Redeeming);
    } else {
        let won = b.unwrap();
        assert_eq!(won.state, St::Redeeming);
    }

    // A third claim (sequential) also misses (already redeemed).
    let again = store.claim_pre_auth_code(&code, None, NOW).await;
    assert!(again.is_err(), "the code is spent");
}

#[tokio::test]
async fn authorization_code_pkce_and_single_use() {
    let Some((store, _coll)) = store("auth_code_pkce").await else {
        eprintln!("skipping: no mongod at {DEFAULT_URI} — the host mongod");
        return;
    };
    use sha2::{Digest, Sha256};
    let id = session_id(2);
    let mut seeded = record(&id, St::Offered, NOW + 300);
    // Complete a Mode A authorization: mint the code + the binding.
    let verifier = "the-code-verifier".to_owned();
    let code = format!("ac-{}", id.as_str());
    seeded.auth = Some(AuthCodeBinding {
        client_id: "client-1".to_owned(),
        redirect_uri: "http://localhost:3000/cb".to_owned(),
        code_challenge: siros_issuer_core::sdjwt_issue::b64u(&Sha256::digest(verifier.as_bytes())),
        state: Some("wallet-state".to_owned()),
        credential_configuration_ids: vec!["urn:eudi:pid:1".to_owned()],
    });
    seeded.state = St::AwaitingAuthorization;
    let binding = seeded.auth.clone().unwrap();
    store.insert(seeded).await.unwrap();
    store
        .complete_authorization(
            &format!("offer-{}", id.as_str()),
            vec![9, 9],
            binding,
            hex(&Sha256::digest(code.as_bytes())),
            NOW,
        )
        .await
        .unwrap();

    // Wrong redirect/PKCE refuse; the code stays unburned.
    assert!(store
        .claim_auth_code(&code, "http://evil.example/cb", "client-1", &verifier, NOW)
        .await
        .is_err());
    assert!(store
        .claim_auth_code(&code, "http://localhost:3000/cb", "client-1", "wrong", NOW)
        .await
        .is_err());
    // The real claim wins; the second one refuses (single-use).
    store
        .claim_auth_code(
            &code,
            "http://localhost:3000/cb",
            "client-1",
            &verifier,
            NOW,
        )
        .await
        .unwrap();
    assert!(store
        .claim_auth_code(
            &code,
            "http://localhost:3000/cb",
            "client-1",
            &verifier,
            NOW
        )
        .await
        .is_err());
}

/// Mode B arm/take: the take is atomic single-use (two concurrent takes
/// → one record).
#[tokio::test]
async fn mode_b_take_is_atomic_single_use() {
    let Some((store, _coll)) = store("mode_b_take").await else {
        eprintln!("skipping: no mongod at {DEFAULT_URI} — the host mongod");
        return;
    };
    let id = session_id(3);
    let mut seeded = record(&id, St::AwaitingAuthorization, NOW + 300);
    seeded.mode_b = Some(ModeBState {
        challenge_handle: format!("ch-{}", id.as_str()),
        sealed_session: vec![7, 7, 7],
    });
    // Seed via insert (the index copy).
    store.insert(seeded.clone()).await.unwrap();
    // set_mode_b refuses a second arm.
    assert!(store
        .set_mode_b(
            &id,
            ModeBState {
                challenge_handle: "ch-other".to_owned(),
                sealed_session: vec![1],
            },
            None,
        )
        .await
        .is_err());

    // Two concurrent takes: exactly one record + session.
    let handle = format!("ch-{}", id.as_str());
    let first = store.take_mode_b(&handle);
    let second = store.take_mode_b(&handle);
    let (a, b) = tokio::join!(first, second);
    let wins = [a.is_some(), b.is_some()].iter().filter(|w| **w).count();
    assert_eq!(wins, 1);
    let (record, sealed) = a.or(b).unwrap();
    assert_eq!(sealed, vec![7, 7, 7]);
    assert_eq!(record.id, id);
}

/// The sweeper: expire (machine transition + SSE id), purge
/// non-reissuable finals, keep accepted sealed (§13.3). The
/// hard-delete phase is the TTL index's (async — not asserted here;
/// the expire/purge phases are).
#[tokio::test]
async fn sweeper_expires_and_purges() {
    let Some((store, _coll)) = store("sweep").await else {
        eprintln!("skipping: no mongod at {DEFAULT_URI} — the host mongod");
        return;
    };
    // (a) TTL-lapsed, offered → expired this pass.
    let a_id = session_id(0xa);
    let a = record(&a_id, St::Offered, NOW - 10);
    store.insert(a).await.unwrap();

    // (b) failed 10s ago, sealed → purged (non-reissuable).
    let b_id = session_id(0xb);
    let mut b = record(&b_id, St::Failed, NOW + 300);
    b.history.push((NOW - 10, "failed".to_owned()));
    store.insert(b).await.unwrap();

    // (c) accepted, sealed → KEEPS (§13.3 re-issuance).
    let c_id = session_id(0xc);
    let mut c = record(&c_id, St::Accepted, NOW + 300);
    c.history.push((NOW - 10, "accepted".to_owned()));
    store.insert(c).await.unwrap();

    let report: SweepReport = store.sweep(NOW, RETENTION).await.unwrap();
    assert_eq!(report.expired_ids, vec![a_id.as_str().to_owned()]);
    assert_eq!(
        report.purged, 2,
        "(a) expired this pass → purged; (b) failed → purged; (c) accepted → kept (§13.3)"
    );
    // (a) expired: sealed gone, machine transition recorded.
    let a = store.get(&a_id).await.unwrap();
    assert_eq!(a.state, St::Expired);
    assert!(a.sealed.is_none());
    // (b) failed: sealed gone.
    let b = store.get(&b_id).await.unwrap();
    assert!(b.sealed.is_none());
    // (c) accepted: sealed KEEPS (§13.3).
    let c = store.get(&c_id).await.unwrap();
    assert!(c.sealed.is_some(), "accepted keeps sealed data (§13.3)");
}

/// The transition path through the store applies the core machine
/// (illegal transitions refused).
#[tokio::test]
async fn transitions_delegate_to_the_core_machine() {
    let Some((store, _coll)) = store("transitions").await else {
        eprintln!("skipping: no mongod at {DEFAULT_URI} — the host mongod");
        return;
    };
    let id = session_id(5);
    let seeded = record(&id, St::Offered, NOW + 300);
    store.insert(seeded).await.unwrap();

    // Legal: Redeemed from Offered.
    let after = store
        .transition(&id, SessionEvent::Redeemed, NOW)
        .await
        .unwrap();
    assert_eq!(after.state, St::Redeeming);
    // Illegal: Redeemed again (from Redeeming) refuses.
    assert!(store
        .transition(&id, SessionEvent::Redeemed, NOW)
        .await
        .is_err());
    // Legal: Issued from Redeeming.
    let issued = store
        .transition(&id, SessionEvent::Issued, NOW)
        .await
        .unwrap();
    assert_eq!(issued.state, St::Issued);
    // History bounded + labeled.
    assert_eq!(issued.history.last().unwrap().1, "issued");
}

/// The access-token binding resolves and expires.
#[tokio::test]
async fn access_token_bindings_resolve_and_expire() {
    let Some((store, _coll)) = store("bindings").await else {
        eprintln!("skipping: no mongod at {DEFAULT_URI} — the host mongod");
        return;
    };
    let id = session_id(6);
    store
        .insert(record(&id, St::Offered, NOW + 300))
        .await
        .unwrap();
    let token_hash = format!("tok-{}", id.as_str());
    store
        .bind_access_token(token_hash.clone(), &id, NOW + 300, Some("jkt-1".to_owned()))
        .await
        .unwrap();
    let (resolved, jkt) = store
        .session_by_access_token(&token_hash, NOW)
        .await
        .unwrap();
    assert_eq!(resolved, id);
    assert_eq!(jkt.as_deref(), Some("jkt-1"));
    // Expired: absent.
    assert!(store
        .session_by_access_token(&token_hash, NOW + 301)
        .await
        .is_none());
    // Status ref round-trips (the URL serde).
    store
        .set_status_ref(
            &id,
            siros_issuer_core::status_client::StatusRef {
                list_url: Url::parse("http://status.example/lists/1").unwrap(),
                index: 42,
            },
        )
        .await
        .unwrap();
    let reloaded = store.get(&id).await.unwrap();
    assert_eq!(reloaded.status_ref.unwrap().index, 42);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// A second concurrent-claim test file's helper: keep `json` import used
// (serde_json is part of the test deps for record shaping).
#[allow(dead_code)]
fn _keep_json(value: serde_json::Value) -> serde_json::Value {
    let _ = json!({});
    value
}

/// Deferred issuance (§7.6): the transaction arm is single-use and
/// session-bound — a mismatched principal's take never claims (and never
/// burns), the owner's take returns the ARMED snapshot (holder keys
/// intact), and concurrent takes yield exactly one. CAS across replicas.
#[tokio::test]
async fn transaction_arm_is_single_use_and_session_bound() {
    let Some((store, _coll)) = store("txn_arm").await else {
        eprintln!("skipping: no mongod at {DEFAULT_URI} — the host mongod");
        return;
    };
    let owner = session_id(7);
    let other = session_id(8);
    let seeded = record(&owner, St::Pending, NOW + 300);
    // Pending arms (the state machine's Deferred transition already ran).
    let other_record = record(&other, St::Pending, NOW + 300);
    store.insert(seeded.clone()).await.unwrap();
    store.insert(other_record).await.unwrap();
    let txn = format!("urn:txn:siros:{}", owner.as_str());
    let txn_hash = {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(txn.as_bytes()).into();
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push_str(&format!("{b:02x}"));
        }
        out
    };
    let holder_jwk = json!({"kty": "EC", "crv": "P-256", "x": "e", "y": "d"});
    store
        .set_transaction(&owner, txn_hash.clone(), vec![holder_jwk.clone()])
        .await
        .unwrap();

    // A second arm on the same session refuses.
    let mut other_txn = txn_hash.clone();
    other_txn.push('x'); // a distinct id, same session
    assert!(store
        .set_transaction(&owner, other_txn, Vec::new())
        .await
        .is_err());
    // An arm on a non-pending session refuses.
    let offered = session_id(9);
    store
        .insert(record(&offered, St::Offered, NOW + 300))
        .await
        .unwrap();
    assert!(store
        .set_transaction(&offered, "urn:txn:siros:offered".to_owned(), Vec::new())
        .await
        .is_err());

    // Another principal's take never claims (and never burns).
    assert!(store.take_transaction(&txn_hash, &other).await.is_none());

    // The owner's take: the ARMED snapshot (holder keys intact).
    let first = store.take_transaction(&txn_hash, &owner);
    let second = store.take_transaction(&txn_hash, &owner);
    let (a, b) = tokio::join!(first, second);
    let wins = [a.is_some(), b.is_some()].iter().filter(|w| **w).count();
    assert_eq!(wins, 1, "concurrent takes claim exactly once");
    let claimed = a.or(b).unwrap();
    assert_eq!(claimed.id, owner);
    assert_eq!(
        claimed.pending_holder_jwks,
        Some(vec![holder_jwk]),
        "the take returns the ARMED snapshot"
    );
    // A re-take after the claim misses.
    assert!(store.take_transaction(&txn_hash, &owner).await.is_none());
}

/// The shared-replica rate counter (§11): fixed 60-second buckets keyed
/// (endpoint, client, window) — two counter *instances* over one
/// collection share the budget exactly, fail-closed on transport, and
/// the window rolls on the bucket boundary.
#[tokio::test]
async fn rate_counter_shares_the_budget_across_instances() {
    let Some((store, _coll)) = store("rate_counter").await else {
        eprintln!("skipping: no mongod at {DEFAULT_URI} — the host mongod");
        return;
    };
    let client = store.client();
    let db = format!("rate_test_{}", std::process::id());
    // Two instances = two replicas: same collection, same budget.
    let a = siros_issuer_service::mongo_rate::MongoRateCounter::connect(client, &db, 3)
        .await
        .unwrap();
    let b = siros_issuer_service::mongo_rate::MongoRateCounter::connect(client, &db, 3)
        .await
        .unwrap();
    let now = 1_800_000_000i64;

    // Three requests across BOTH instances: all allowed, the fourth
    // refused by whichever instance sees it — the budget is shared.
    assert!(a.allow("/token", "10.0.0.1", now).await.unwrap());
    assert!(b.allow("/token", "10.0.0.1", now).await.unwrap());
    assert!(a.allow("/token", "10.0.0.1", now).await.unwrap());
    assert!(!b.allow("/token", "10.0.0.1", now).await.unwrap());

    // A different client has its own budget.
    assert!(a.allow("/token", "10.0.0.2", now).await.unwrap());
    // A different endpoint has its own budget.
    assert!(b.allow("/credential", "10.0.0.1", now).await.unwrap());

    // The next window rolls the budget: the bucket start is pinned by
    // floor(now/60); a request in the NEXT bucket starts fresh.
    let next_window = now + 61;
    assert!(a.allow("/token", "10.0.0.1", next_window).await.unwrap());

    // One bucket's spend never leaks into another client's id.
    assert!(b.allow("/token", "10.0.0.3", now).await.unwrap());
    client.database(&db).drop().await.ok();
}
