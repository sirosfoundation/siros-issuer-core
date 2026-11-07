//! P1 end-to-end: the pre-authorized grant from the backend session API to
//! a verified SD-JWT VC. Sources of truth: OpenID4VCI 1.0 ID1 (offer,
//! token, credential, notification), RFC 7523/7638 (client assertion,
//! thumbprint), and **siros-verifier-core's `sdjwt::verify`** — the issued
//! credential is verified by the verifier, not by re-running the issuer's
//! own code (design §13.3 cross-check invariant).

use serde_json::{json, Value};
use siros_issuer_core::oid4vci::{GRANT_AUTHORIZATION_CODE, GRANT_PRE_AUTHORIZED_CODE};
use siros_issuer_core::signer::Signer;
use siros_issuer_core::status_client::Status;
use siros_issuer_service::api::{AppState, RefreshStatus};
use siros_issuer_service::pdp::TrustPdp;
use siros_issuer_service::status::{now_unix, StatusAllocator};
use siros_issuer_service::store::MemoryStore;
use siros_issuer_service::vault::Vault;
use siros_issuer_service::{config::Config, fetch};
use siros_verifier_core::sdjwt::{verify as verify_sdjwt, HolderBinding, StaticKey, VerifyParams};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use url::Url;

// ─── Test doubles (public traits; tests live outside src/) ───────────────

struct PermitPdp;
#[async_trait::async_trait]
impl TrustPdp for PermitPdp {
    async fn permit(
        &self,
        _query: &siros_issuer_core::trust::IssuanceTrustQuery,
    ) -> siros_issuer_core::Result<()> {
        Ok(())
    }

    // Mode B: a presented credential the test PDP permits.
    async fn permit_presentation(
        &self,
        _query: &siros_verifier_core::trust::TrustQuery,
    ) -> siros_issuer_core::Result<()> {
        Ok(())
    }
}

struct DenyPdp;
#[async_trait::async_trait]
impl TrustPdp for DenyPdp {
    async fn permit(
        &self,
        _query: &siros_issuer_core::trust::IssuanceTrustQuery,
    ) -> siros_issuer_core::Result<()> {
        Err(siros_issuer_core::Error::new(
            siros_issuer_core::error::code::PDP_DENIED,
            "test denies everything",
        ))
    }
}

/// Records allocations and updates; stands in for siros-status-service.
struct RecordingAllocator {
    list_url: Url,
    next_index: AtomicU64,
    updates: Mutex<Vec<(String, u64, Status)>>,
}

#[async_trait::async_trait]
impl StatusAllocator for RecordingAllocator {
    async fn allocate(
        &self,
        _exp: Option<String>,
    ) -> siros_issuer_core::Result<siros_issuer_core::status_client::StatusRef> {
        Ok(siros_issuer_core::status_client::StatusRef {
            list_url: self.list_url.clone(),
            index: self.next_index.fetch_add(1, Ordering::SeqCst),
        })
    }

    async fn update(
        &self,
        list_url: &Url,
        index: u64,
        status: Status,
    ) -> siros_issuer_core::Result<()> {
        self.updates
            .lock()
            .expect("updates lock")
            .push((list_url.to_string(), index, status));
        Ok(())
    }
}

// ─── Fixture service ─────────────────────────────────────────────────────

struct TestService {
    base: String,
    signer: siros_issuer_core::signer::JwkSigner,
}

/// A signer-agnostic service handle: the HSM-provider tests verify
/// issued credentials under the provider's `public_jwk()` instead.
struct SignerAgnosticService {
    base: String,
}

fn fixture_config() -> Config {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata")
        .display()
        .to_string();
    Config::from_toml_str(&format!(
        r#"
[issuer]
url = "http://127.0.0.1:8080"

[catalog]
static_dir = "{dir}/ts11"
refresh_seconds = 0

# The ZK layer fixtures (design §8.3): the circuit manifest
# (testdata/zkcircuits — vega-mc publishes saltBytes 32 for nym_auth)
# and the nym_auth rulebook (rulebook #1): HKDF over
# issuing_country + personal_administrative_number, 16 bytes, committed
# at [doctype, ssc]. LOCAL TEST ONLY: the seed is in-line.
[zk.circuits]
static_dir = "{dir}/zkcircuits"

[zk.rulebooks.nym_auth]
credentials = ["eu.europa.ec.eudi.nym_auth.1"]
zk_systems = ["vega-mc"]

[[zk.rulebooks.nym_auth.auxiliary_data.to_wallet]]
alg = "sha-256"
path = ["eu.europa.ec.eudi.nym_auth.1", "ssc"]
encoding = "base64url"

[zk.rulebooks.nym_auth.auxiliary_data.to_wallet.opening]
hkdf = {{ secret_b64url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", inputs = [
    "issuing_country",
    "personal_administrative_number",
], bytes = 16 }}
"#
    ))
    .expect("test config parses")
}

/// Test material (never production): the pre-registered suite client's
/// fixed key pair, mirroring the OIDF plan's client config.
const CLIENT_PRIVATE_JWK: &str = r#"{"kty":"EC","x":"MpY3glbcq9njtQLM1hCREOrfQqPgOKyGOl7xkMwHsSI","y":"ZDT-zr7lt2R12MaFbXuapq4eXS5hprKjegb5yq3UlXE","crv":"P-256","d":"gaknst5YK3n03zh8vvDXA4HydaNQfzYtnC0CiMHADmI","kid":"test-client-key-1","alg":"ES256","use":"sig"}"#;

fn suite_client_registry() -> siros_issuer_service::client_auth::ClientRegistry {
    let mut clients = std::collections::HashMap::new();
    clients.insert(
        "suite-wallet".to_owned(),
        siros_issuer_service::client_auth::ClientRegistration {
            jwks: vec![serde_json::json!({
                "kty": "EC",
                "x": "MpY3glbcq9njtQLM1hCREOrfQqPgOKyGOl7xkMwHsSI",
                "y": "ZDT-zr7lt2R12MaFbXuapq4eXS5hprKjegb5yq3UlXE",
                "crv": "P-256",
                "kid": "test-client-key-1",
                "alg": "ES256",
                "use": "sig",
            })],
            redirect_uris: vec!["http://localhost:3000/cb".to_owned()],
            allow_any_redirect_uri: false,
            scope: Some("pid".to_owned()),
        },
    );
    siros_issuer_service::client_auth::ClientRegistry { clients }
}

/// RFC 7523 private_key_jwt for the test client.
fn client_assertion_jwt() -> String {
    let key: jose_rs::jwk::Jwk = serde_json::from_str(CLIENT_PRIVATE_JWK).expect("test client key");
    let now = now_unix();
    sign_jwt(
        &key,
        "jwt",
        &json!({
            "iss": "suite-wallet",
            "sub": "suite-wallet",
            "aud": ISSUER_BASE,
            "iat": now,
            "exp": now + 300,
            "jti": siros_issuer_core::sdjwt_issue::b64u(&{
                let mut b = [0u8; 16];
                getrandom::fill(&mut b).expect("OS randomness");
                b
            }),
        }),
        false,
    )
}

/// Token request params with the private_key_jwt client auth folded in.
fn token_form(pairs: &[(&str, String)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .chain([
            ("client_id".to_owned(), "suite-wallet".to_owned()),
            (
                "client_assertion_type".to_owned(),
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned(),
            ),
            ("client_assertion".to_owned(), client_assertion_jwt()),
        ])
        .collect()
}

/// The test signer AND its private JWK: JwkSigner hides private material
/// (by design), but the certificate chain must cover the signing key, so
/// the chain is built where the key is still in hand.
fn test_signer() -> (siros_issuer_core::signer::JwkSigner, jose_rs::jwk::Jwk) {
    let mut issuer_jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
    issuer_jwk.alg = Some("ES256".to_owned());
    issuer_jwk.kid = Some("test-issuer-key".to_owned());
    let signer = siros_issuer_core::signer::JwkSigner::new(issuer_jwk.clone()).expect("signer");
    (signer, issuer_jwk)
}

/// A self-signed certificate chain over the signer's key (leaf only, SPKI
/// = the signing key — the mdoc-roundtrip pattern): Mode B request
/// objects and mdoc IssuerSigned x5chains.
fn signer_cert_chain(private: &jose_rs::jwk::Jwk) -> Vec<Vec<u8>> {
    let d = private.d.as_deref().expect("private scalar");
    let bytes = siros_issuer_core::sdjwt_issue::b64u_decode(d).expect("d is base64url");
    let key = p256::ecdsa::SigningKey::from_slice(&bytes).expect("signing key");
    use p256::pkcs8::EncodePrivateKey;
    let pkcs8 = key.to_pkcs8_der().unwrap();
    let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let params = rcgen::CertificateParams::new(vec!["issuer.example.org".to_string()]).unwrap();
    vec![params.self_signed(&kp).unwrap().der().to_vec()]
}

async fn spawn_service(
    pdp: Arc<dyn TrustPdp>,
    allocator: Arc<RecordingAllocator>,
    signer_pair: (siros_issuer_core::signer::JwkSigner, jose_rs::jwk::Jwk),
) -> TestService {
    let (signer, private) = signer_pair;
    let public = siros_issuer_core::signer::Signer::public_jwk(&signer).expect("public jwk");
    let cert_chain = signer_cert_chain(&private);
    let svc = spawn_service_dyn(pdp, allocator, Arc::new(signer), public, cert_chain, false).await;
    TestService {
        base: svc.base,
        // The file key verifies the oracles (public material).
        signer: siros_issuer_core::signer::JwkSigner::new(private).expect("signer"),
    }
}

/// The deferred-issuance surface (§7.6): same spawn, `deferred = true` —
/// /credential arms a transaction and answers pending;
/// /deferred-credential completes.
async fn spawn_service_deferred(
    pdp: Arc<dyn TrustPdp>,
    allocator: Arc<RecordingAllocator>,
    signer_pair: (siros_issuer_core::signer::JwkSigner, jose_rs::jwk::Jwk),
) -> TestService {
    let (signer, private) = signer_pair;
    let public = siros_issuer_core::signer::Signer::public_jwk(&signer).expect("public jwk");
    let cert_chain = signer_cert_chain(&private);
    let svc = spawn_service_dyn(pdp, allocator, Arc::new(signer), public, cert_chain, true).await;
    TestService {
        base: svc.base,
        signer: siros_issuer_core::signer::JwkSigner::new(private).expect("signer"),
    }
}

/// Spawn with any `signer::Signer` provider (the HSM test signs through
/// its provider; the public JWK / cert chain ride along for the oracles).
/// `deferred` arms the deferred-issuance surface (§7.6): the credential
/// endpoint answers pending and `/deferred-credential` completes.
async fn spawn_service_dyn(
    pdp: Arc<dyn TrustPdp>,
    allocator: Arc<RecordingAllocator>,
    signer: Arc<dyn siros_issuer_core::signer::Signer>,
    _public: jose_rs::jwk::Jwk,
    cert_chain_der: Vec<Vec<u8>>,
    deferred: bool,
) -> SignerAgnosticService {
    // Any port: issuer_base is what signed URLs carry; bind 0 and use it.
    let issuer_base = Url::parse("http://127.0.0.1:8080").unwrap();
    let config = fixture_config();
    let source = fetch::CatalogSource::from_config(&config.catalog).unwrap();
    let catalog =
        futures_util::FutureExt::now_or_never(async { fetch::load_catalog(&source).await })
            .expect("catalog loads")
            .expect("fixture catalog builds");
    let circuit_manifest = config
        .zk
        .circuits
        .static_dir
        .as_deref()
        .map(siros_issuer_service::zk_load::load_circuit_manifest)
        .transpose()
        .expect("fixture circuit manifest loads")
        .map(std::sync::Arc::new);
    let (events_tx, _) = tokio::sync::broadcast::channel(64);
    let state = AppState {
        catalog: Arc::new(std::sync::RwLock::new(Arc::new(catalog))),
        issuer_base,
        authorization_servers: vec![],
        refresh: Arc::new(RefreshStatus::default()),
        sessions: Arc::new(MemoryStore::new()),
        dpop: Arc::new(siros_issuer_service::dpop::DpopValidator::new(60)),
        last_public_nonce: Arc::new(std::sync::Mutex::new(String::new())),
        login_url: Some(Url::parse("http://127.0.0.1:8080/dev-portal/login").unwrap()),
        clients: Arc::new(suite_client_registry()),
        scopes: std::collections::HashMap::new(),
        endpoint_paths: siros_issuer_core::oid4vci::EndpointPaths {
            batch_credential: Some(("batch-credential", 4)),
            deferred_credential: deferred.then_some("deferred-credential"),
            ..Default::default()
        },
        deferred_interval_seconds: 5,
        request_encryption_key: None,
        cert_chain_der: cert_chain_der.clone(),
        attestation: Arc::new(siros_issuer_service::client_auth::WildcardRulesPolicy::new(
            Vec::new(),
        )),
        signer: signer.clone(),
        vault: Arc::new(Vault::new().expect("vault")),
        pdp,
        allocator: allocator.clone(),
        events_tx,
        credential_validity_seconds: 3600,
        access_token_ttl_seconds: 300,
        c_nonce_ttl_seconds: 300,
        rulebooks: config.zk.rulebooks.clone(),
        circuit_manifest,
        rate_limit: config.rate_limit.clone(),
        wallet_attestation: None,
    };
    let app = siros_issuer_service::api::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    SignerAgnosticService {
        base: format!("http://{addr}"),
    }
}

// ─── JWT helpers (RFC 7523 assertion, OID4VCI proof) ──────────────────────

/// A signing-ready EC key (jose-rs demands alg on sign_with_jwk).
fn ec_key() -> jose_rs::jwk::Jwk {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").expect("keygen");
    jwk.alg = Some("ES256".to_owned());
    jwk
}

fn sign_jwt(key: &jose_rs::jwk::Jwk, typ: &str, claims: &Value, embed_jwk: bool) -> String {
    let mut header = jose_rs::JoseHeader::new("ES256");
    header.typ = Some(typ.to_owned());
    header.kid = key.kid.clone();
    if embed_jwk {
        header.jwk = Some(serde_json::to_value(key.to_public_jwk()).unwrap());
    }
    let payload = serde_json::to_vec(claims).unwrap();
    let mut opts = jose_rs::jws::compact::SignOptions::new();
    if embed_jwk {
        // The inline jwk is a key-reference member; sign with it enabled
        // (the assertion and the proof both carry the holder/integrator
        // key this way — RFC 7523 / OpenID4VCI ID1).
        opts = opts.with_key_reference_headers(true);
    }
    jose_rs::jws::compact::sign_with_jwk_options(key, &payload, &header, &opts).expect("jwt signs")
}

fn client_assertion(key: &jose_rs::jwk::Jwk, issuer_base: &Url) -> String {
    let now = now_unix();
    sign_jwt(
        key,
        "jwt",
        &json!({
            "iss": "https://portal.example.org/",
            "sub": "https://portal.example.org/",
            "aud": siros_issuer_core::oid4vci::issuer_identifier(issuer_base),
            "iat": now,
            "exp": now + 300,
        }),
        true,
    )
}

fn proof_jwt(holder: &jose_rs::jwk::Jwk, issuer_base: &Url, nonce: &str) -> String {
    sign_jwt(
        holder,
        "openid4vci-proof+jwt",
        &json!({
            "iss": "wallet",
            "aud": siros_issuer_core::oid4vci::issuer_identifier(issuer_base),
            "nonce": nonce,
            "iat": now_unix(),
        }),
        true,
    )
}

const ISSUER_BASE: &str = "http://127.0.0.1:8080";

async fn create_session(
    service: &TestService,
    key: &jose_rs::jwk::Jwk,
    body: Value,
) -> (reqwest::Response, Value) {
    let response = reqwest::Client::new()
        .post(format!("{}/api/v1/issuance/sessions", service.base))
        .header(
            "Authorization",
            format!(
                "Bearer {}",
                client_assertion(key, &Url::parse(ISSUER_BASE).unwrap())
            ),
        )
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let parsed: Value = response.json().await.unwrap_or(Value::Null);
    let _ = status;
    // Re-issue to get both status and body: reqwest consumes.
    let response = reqwest::Client::new()
        .post(format!("{}/api/v1/issuance/sessions", service.base))
        .header(
            "Authorization",
            format!(
                "Bearer {}",
                client_assertion(key, &Url::parse(ISSUER_BASE).unwrap())
            ),
        )
        .json(&body)
        .send()
        .await
        .unwrap();
    (response, parsed)
}

/// Mint a pre-auth session and redeem it to a DPoP-free access token
/// (the deferred tests' base), returning the offer + access token.
async fn deferred_arm(service: &TestService, subject: Value) -> (Value, String) {
    let client = reqwest::Client::new();
    let integrator = ec_key();
    let (created, _) = create_session(
        service,
        &integrator,
        json!({"credential": "urn:eudi:pid:1", "subject": subject, "grant": {"tx_code": {"value": "654321"}}}),
    )
    .await;
    let body: Value = created.json().await.unwrap();
    let offer_uri = body["offer_uri"].as_str().unwrap().to_owned();
    let offer: Value = client
        .get(format!(
            "{}{}",
            service.base,
            offer_uri.trim_start_matches(ISSUER_BASE)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned();
    let token: Value = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre_authorized_code", code),
            ("tx_code", "654321".to_owned()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access_token = token["access_token"].as_str().unwrap().to_owned();
    (offer, access_token)
}

/// POST /credential with a fresh jwt proof — under the deferred surface
/// this ARMS a transaction and answers pending (Final §9): the response
/// carries {transaction_id, interval} and MUST NOT carry credentials or
/// notification_id (§8.3's closed set). Returns the parsed response.
async fn credential_request_pending(
    service: &TestService,
    offer: &Value,
    access_token: &str,
) -> Value {
    let client = reqwest::Client::new();
    let holder = ec_key();
    // Fetch the session's c_nonce through the public nonce endpoint
    // (the proof binds whatever the wallet holds; the endpoint mints).
    let nonce: Value = client
        .post(format!("{}/nonce", service.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let c_nonce = nonce["c_nonce"].as_str().unwrap().to_owned();
    let proof = proof_jwt(&holder, &Url::parse(ISSUER_BASE).unwrap(), &c_nonce);
    let response = client
        .post(format!("{}/credential", service.base))
        .bearer_auth(access_token)
        .json(&json!({
            "credential_configuration_id": offer["credential_configuration_ids"][0],
            "proof": { "proof_type": "jwt", "jwt": proof },
        }))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "credential endpoint (deferred arm): {}",
        response.status()
    );
    response.json().await.unwrap()
}

/// Deferred issuance (design §7.6, Final §9): /credential answers
/// pending with a transaction_id (credentials and notification_id
/// absent — §8.3's closed set), the metadata advertises the deferred
/// endpoint, /deferred-credential completes the issuance exactly once,
/// and the completed transaction is single-use: a second poll refuses.
#[tokio::test]
async fn deferred_issuance_answers_pending_then_completes_exactly_once() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service_deferred(Arc::new(PermitPdp), allocator, test_signer()).await;
    let client = reqwest::Client::new();

    let (offer, access_token) = deferred_arm(
        &service,
        json!({"given_name": "Deferred", "family_name": "Wallet"}),
    )
    .await;

    // The arm: pending, §8.3's closed set respected.
    let pending = credential_request_pending(&service, &offer, &access_token).await;
    let transaction_id = pending["transaction_id"]
        .as_str()
        .expect("pending response carries transaction_id")
        .to_owned();
    assert!(!transaction_id.is_empty(), "transaction_id is not empty");
    assert_eq!(
        pending["interval"], 5,
        "interval guidance rides the pending response"
    );
    assert!(
        pending["credentials"].is_null(),
        "no credentials in the pending response (Final §8.3)"
    );
    assert!(
        pending["notification_id"].is_null(),
        "no notification_id without credentials (Final §8.3)"
    );

    // The metadata advertises the deferred endpoint (only when enabled
    // — endpoint_paths drives it).
    let metadata: Value = client
        .get(format!(
            "{}/.well-known/openid-credential-issuer",
            service.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        metadata["deferred_credential_endpoint"]
            .as_str()
            .unwrap_or("")
            .ends_with("/deferred-credential"),
        "deferred_credential_endpoint advertised: {}",
        metadata["deferred_credential_endpoint"]
    );

    // The completion: one poll issues the credential (verified by
    // verifier-core, the P1 discipline).
    let completed: Value = client
        .post(format!("{}/deferred-credential", service.base))
        .bearer_auth(&access_token)
        .json(&json!({"transaction_id": transaction_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let issued = completed["credentials"][0]["credential"]
        .as_str()
        .expect("the deferred completion carries the credential")
        .to_owned();
    assert_eq!(completed["credentials"][0]["format"], "dc+sd-jwt");
    assert!(
        completed["notification_id"].is_string(),
        "the completion carries notification_id (credentials present)"
    );
    verify_sdjwt(
        &issued,
        &StaticKey(service.signer.public_jwk().expect("public jwk")),
        &VerifyParams::new(now_unix(), HolderBinding::NotRequired),
    )
    .expect("the deferred-completed credential verifies in verifier-core");

    // Single-use (Final §9: the transaction_id MUST be invalidated once
    // obtained): the second poll refuses.
    let second = client
        .post(format!("{}/deferred-credential", service.base))
        .bearer_auth(&access_token)
        .json(&json!({"transaction_id": transaction_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a claimed transaction refuses on re-poll"
    );
    let refused: Value = second.json().await.unwrap();
    assert!(
        refused["error"].is_string(),
        "the refusal is the 1.0 Final error shape: {refused}"
    );

    // An unknown transaction_id refuses the same way.
    let unknown = client
        .post(format!("{}/deferred-credential", service.base))
        .bearer_auth(&access_token)
        .json(&json!({"transaction_id": "urn:txn:siros:not-armed"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// The deferred transaction is bound to its own session's access token:
/// another principal's poll refuses AND never burns the arm — the
/// owning token still completes (§9's single-use is a claim by the
/// rightful principal only).
#[tokio::test]
async fn deferred_poll_is_bound_to_its_own_access_token() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service_deferred(Arc::new(PermitPdp), allocator, test_signer()).await;
    let client = reqwest::Client::new();

    // Two armed sessions: A (the owner) and B (another principal).
    let (offer_a, token_a) =
        deferred_arm(&service, json!({"given_name": "Owner", "family_name": "A"})).await;
    let (_offer_b, token_b) =
        deferred_arm(&service, json!({"given_name": "Other", "family_name": "B"})).await;
    let pending = credential_request_pending(&service, &offer_a, &token_a).await;
    let transaction_id = pending["transaction_id"]
        .as_str()
        .expect("transaction_id")
        .to_owned();

    // B polls A's transaction: refused.
    let refused = client
        .post(format!("{}/deferred-credential", service.base))
        .bearer_auth(&token_b)
        .json(&json!({"transaction_id": transaction_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "another principal's poll refuses"
    );

    // The arm survived: A's own poll still completes.
    let completed: Value = client
        .post(format!("{}/deferred-credential", service.base))
        .bearer_auth(&token_a)
        .json(&json!({"transaction_id": transaction_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        completed["credentials"][0]["credential"].is_string(),
        "the owning token completes after the foreign refusal"
    );
}

/// A DPoP-bound access token demands its proof at /deferred-credential
/// too (RFC 9449 §4; Final §9 rides the same token): a proofless poll
/// refuses WITHOUT burning the arm (the check precedes the claim), and
/// the rightful proof completes.
#[tokio::test]
async fn dpop_bound_deferred_poll_requires_its_proof() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service_deferred(Arc::new(PermitPdp), allocator, test_signer()).await;
    let client = reqwest::Client::new();

    // Session + offer (the DPoP binding is minted at /token).
    let integrator = ec_key();
    let (created, _) = create_session(
        &service,
        &integrator,
        json!({"credential": "urn:eudi:pid:1", "subject": {"given_name": "D", "family_name": "X"}, "grant": {"tx_code": {"value": "654321"}}}),
    )
    .await;
    let body: Value = created.json().await.unwrap();
    let offer_uri = body["offer_uri"].as_str().unwrap().to_owned();
    let offer: Value = client
        .get(format!(
            "{}{}",
            service.base,
            offer_uri.trim_start_matches(ISSUER_BASE)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned();

    let dpop_key = ec_key();
    let now = now_unix();
    let jti = || {
        siros_issuer_core::sdjwt_issue::b64u(&{
            let mut b = [0u8; 16];
            getrandom::fill(&mut b).expect("OS randomness");
            b
        })
    };
    let dpop_proof = |htm: &str, htu: &str, ath: Option<&str>| {
        let mut claims = json!({"htm": htm, "htu": htu, "iat": now, "jti": jti()});
        if let Some(ath) = ath {
            claims["ath"] = json!(ath);
        }
        sign_jwt(&dpop_key, "dpop+jwt", &claims, true)
    };
    let token: Value = client
        .post(format!("{}/token", service.base))
        .header(
            "DPoP",
            dpop_proof(
                "POST",
                Url::parse(ISSUER_BASE)
                    .unwrap()
                    .join("token")
                    .unwrap()
                    .as_str(),
                None,
            ),
        )
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre_authorized_code", code),
            ("tx_code", "654321".to_owned()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access_token = token["access_token"].as_str().unwrap().to_owned();

    // Arm the transaction (/credential with the DPoP proof + jwt proof).
    let holder = ec_key();
    let nonce: Value = client
        .post(format!("{}/nonce", service.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cred_proof = proof_jwt(
        &holder,
        &Url::parse(ISSUER_BASE).unwrap(),
        nonce["c_nonce"].as_str().unwrap(),
    );
    let pending: Value = client
        .post(format!("{}/credential", service.base))
        .header(
            "DPoP",
            dpop_proof(
                "POST",
                Url::parse(ISSUER_BASE)
                    .unwrap()
                    .join("credential")
                    .unwrap()
                    .as_str(),
                Some(&siros_issuer_service::dpop::access_token_hash(
                    &access_token,
                )),
            ),
        )
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": "urn:eudi:pid:1",
            "proof": { "proof_type": "jwt", "jwt": cred_proof },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let transaction_id = pending["transaction_id"]
        .as_str()
        .expect("DPoP-bound arm still yields the transaction")
        .to_owned();

    // Proofless poll: refused, arm intact.
    let refused = client
        .post(format!("{}/deferred-credential", service.base))
        .bearer_auth(&access_token)
        .json(&json!({"transaction_id": transaction_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a DPoP-bound token refuses a proofless deferred poll"
    );

    // The rightful proof completes.
    let completed: Value = client
        .post(format!("{}/deferred-credential", service.base))
        .header(
            "DPoP",
            dpop_proof(
                "POST",
                Url::parse(ISSUER_BASE)
                    .unwrap()
                    .join("deferred-credential")
                    .unwrap()
                    .as_str(),
                Some(&siros_issuer_service::dpop::access_token_hash(
                    &access_token,
                )),
            ),
        )
        .bearer_auth(&access_token)
        .json(&json!({"transaction_id": transaction_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        completed["credentials"][0]["credential"].is_string(),
        "the DPoP-proven deferred poll completes"
    );
}

/// The whole wallet-side redemption, returning the issued credential
/// (compact SD-JWT with disclosures).
async fn wallet_redeem(service: &TestService, offer_uri: &str) -> (String, Value) {
    let client = reqwest::Client::new();
    // 1. Fetch the offer (the offer URI is the bearer).
    let offer_uri_url = offer_uri.trim_start_matches(ISSUER_BASE).to_owned();
    let offer: Value = client
        .get(format!("{}{}", service.base, offer_uri_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]
        .as_object()
        .expect("offer carries the pre-authorized grant")
        .clone();
    let code = grant["pre-authorized_code"]
        .as_str()
        .expect("grant carries the code");

    // 2. Token exchange (OAuth form encoding).
    let token: Value = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre_authorized_code", code.to_string()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(token["token_type"], "Bearer");
    let access_token = token["access_token"].as_str().unwrap().to_owned();
    let c_nonce = token["c_nonce"].as_str().unwrap().to_owned();

    // 3. Proof + credential request (unencrypted response).
    let holder = ec_key();
    let proof = proof_jwt(&holder, &Url::parse(ISSUER_BASE).unwrap(), &c_nonce);
    let response = client
        .post(format!("{}/credential", service.base))
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": offer["credential_configuration_ids"][0],
            "proof": { "proof_type": "jwt", "jwt": proof },
        }))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "credential endpoint: {}",
        response.status()
    );
    let credential: Value = response.json().await.unwrap();
    let issued = credential["credentials"][0]["credential"]
        .as_str()
        .expect("credentials[0].credential")
        .to_owned();
    (issued, token)
}

// ─── Tests ────────────────────────────────────────────────────────────────

/// The P1 exit criterion: backend session API → offer → token → proof →
/// SD-JWT VC, **verified by siros-verifier-core**, then notification
/// feedback and revocation through the (recording) status allocator.
#[tokio::test]
async fn pre_authorized_issuance_verifies_in_verifier_core() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/test-list").unwrap(),
        next_index: AtomicU64::new(7),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator.clone(), test_signer()).await;
    let integrator = ec_key();

    let (created, _) = create_session(
        &service,
        &integrator,
        json!({
            "credential": "urn:eudi:pid:1",
            "subject": {
                "given_name": "Anna",
                "family_name": "Andersson",
                "birth_date": "1982-07-12"
            }
        }),
    )
    .await;
    assert_eq!(created.status(), reqwest::StatusCode::CREATED);
    let body: Value = created.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap().to_owned();
    let offer_uri = body["offer_uri"].as_str().unwrap().to_owned();
    let notification_id = body["notification_id"].as_str().unwrap().to_owned();
    assert!(offer_uri.starts_with(ISSUER_BASE));

    // Wallet side: offer → token → credential.
    let (issued, _token) = wallet_redeem(&service, &offer_uri).await;

    // The cross-check (design §13.3): verifier-core verifies what the
    // issuer produced. HolderBinding::NotRequired — the issuer's SD-JWT
    // carries cnf, the KB-JWT is the holder's at presentation time.
    let verified = verify_sdjwt(
        &issued,
        &StaticKey(service.signer.public_jwk().expect("public jwk")),
        &VerifyParams::new(now_unix(), HolderBinding::NotRequired),
    )
    .expect("verifier-core verifies the issued credential");
    assert_eq!(verified.vct, "urn:eudi:pid:1");
    // Subject claims survive disclosure construction.
    assert_eq!(verified.claims["given_name"], "Anna");
    assert_eq!(verified.claims["family_name"], "Andersson");
    assert_eq!(verified.claims["birth_date"], "1982-07-12");
    // The status reference matches the allocator's first allocation.
    let status = verified.status.expect("status reference embedded");
    assert_eq!(status.idx, 7);
    assert_eq!(status.uri, "http://127.0.0.1:9/lists/test-list");
    // cnf binds the holder key from the proof.
    assert!(verified.holder_key.is_some());

    // Notification → feedback into the state machine.
    let notification: Value = reqwest::Client::new()
        .post(format!("{}/notification", service.base))
        .json(&json!({
            "notification_id": notification_id,
            "event": "credential_accepted",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap_or(Value::Null);
    assert!(notification.is_null(), "notification is 204 no-content");

    // Status visible to the integrating application.
    let status_body: Value = reqwest::Client::new()
        .get(format!(
            "{}/api/v1/issuance/sessions/{session_id}",
            service.base
        ))
        .header(
            "Authorization",
            format!(
                "Bearer {}",
                client_assertion(&integrator, &Url::parse(ISSUER_BASE).unwrap())
            ),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status_body["state"], "accepted");
    let states: Vec<&str> = status_body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["state"].as_str().unwrap())
        .collect();
    assert!(states.contains(&"issued"));
    assert!(states.contains(&"accepted"));

    // Revocation: the allocator received INVALID for the allocated index.
    let revoke = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/issuance/sessions/{session_id}/revoke",
            service.base
        ))
        .header(
            "Authorization",
            format!(
                "Bearer {}",
                client_assertion(&integrator, &Url::parse(ISSUER_BASE).unwrap())
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), reqwest::StatusCode::NO_CONTENT);
    let updates = allocator.updates.lock().unwrap();
    assert_eq!(updates.len(), 1, "revocation PATCHed once");
    assert_eq!(updates[0].0, "http://127.0.0.1:9/lists/test-list");
    assert_eq!(updates[0].1, 7);
    assert_eq!(updates[0].2, Status::Invalid);
}

/// Discovery advertises the implemented P2 surface (design §12.1).
#[tokio::test]
async fn discovery_advertises_the_p2_surface() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let client = reqwest::Client::new();

    let as_metadata: Value = client
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            service.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // P2: both grants are live; Mode B challenge is not (design §12.1).
    assert_eq!(
        as_metadata["grant_types_supported"],
        json!([GRANT_AUTHORIZATION_CODE, GRANT_PRE_AUTHORIZED_CODE])
    );
    assert!(as_metadata["authorization_endpoint"].is_string());
    assert!(as_metadata["pushed_authorization_request_endpoint"].is_string());
    assert_eq!(
        as_metadata["authorization_details_types_supported"],
        json!(["openid_credential"])
    );
    assert!(as_metadata
        .get("authorization_challenge_endpoint")
        .is_none());

    // The issuer metadata is served; OID4VCI 1.0 Final §12.2.1 has no
    // jwks/jwks_uri member at the issuer level — keys resolve via the
    // AS metadata's jwks_uri.
    let metadata: Value = client
        .get(format!(
            "{}/.well-known/openid-credential-issuer",
            service.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(metadata.get("jwks_uri").is_none());

    // …and the JWKS serves the signing key.
    let jwks: Value = client
        .get(format!("{}/jwks", service.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(jwks["keys"][0]["kty"], "EC");
}

/// A pre-authorized code is single-use: the second token exchange with
/// the same code is refused (ID1 §5.2; design §7.1).
#[tokio::test]
async fn pre_authorized_code_is_single_use() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let integrator = ec_key();

    let (created, _) = create_session(
        &service,
        &integrator,
        json!({"credential": "urn:eudi:pid:1", "subject": {"given_name": "A", "family_name": "B"}}),
    )
    .await;
    let body: Value = created.json().await.unwrap();
    let offer_uri = body["offer_uri"].as_str().unwrap().to_owned();

    let client = reqwest::Client::new();
    let offer: Value = client
        .get(format!(
            "{}{}",
            service.base,
            offer_uri.trim_start_matches(ISSUER_BASE)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned();

    // First redemption succeeds; the same code again is refused.
    let first = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre-authorized_code", code.to_owned()),
            ("tx_code", "654321".to_owned()),
        ]))
        .send()
        .await
        .unwrap();
    let dbg_status = first.status();
    let dbg_body = first.text().await.unwrap_or_default();
    assert!(
        dbg_status.is_success(),
        "token answered {dbg_status}: {dbg_body}"
    );
    let second = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre-authorized_code", code.to_owned()),
            ("tx_code", "654321".to_owned()),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// A denied integrator may not create sessions (fail-closed PDP, design
/// §11); an unknown credential is refused with the stable code.
#[tokio::test]
async fn pdp_denial_and_unknown_credential_refuse_creation() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(DenyPdp), allocator.clone(), test_signer()).await;
    let integrator = ec_key();

    let (denied, _) = create_session(
        &service,
        &integrator,
        json!({"credential": "urn:eudi:pid:1", "subject": {}}),
    )
    .await;
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
    let body: Value = denied.json().await.unwrap();
    assert_eq!(body["error"], "pdp_denied");
    assert!(allocator.updates.lock().unwrap().is_empty());

    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let (unknown, _) = create_session(
        &service,
        &integrator,
        json!({"credential": "urn:example:absent:1", "subject": {}}),
    )
    .await;
    assert_eq!(unknown.status(), reqwest::StatusCode::NOT_FOUND);
    let body: Value = unknown.json().await.unwrap();
    assert_eq!(body["error"], "unsupported_credential");
}

/// When the wallet requests response encryption, the credential response
/// is an ECDHE-ES JWE decryptable with the wallet's key (design §7.5) —
/// verified by decrypting and re-verifying the credential.
#[tokio::test]
async fn encrypted_credential_response_round_trips() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let integrator = ec_key();

    let (created, _) = create_session(
        &service,
        &integrator,
        json!({"credential": "urn:eudi:pid:1", "subject": {"given_name": "A", "family_name": "B"}}),
    )
    .await;
    let body: Value = created.json().await.unwrap();
    let offer_uri = body["offer_uri"].as_str().unwrap().to_owned();

    let client = reqwest::Client::new();
    let offer: Value = client
        .get(format!(
            "{}{}",
            service.base,
            offer_uri.trim_start_matches(ISSUER_BASE)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned();
    let token: Value = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre-authorized_code", code.to_owned()),
            ("tx_code", "654321".to_owned()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let holder = ec_key();
    let proof = proof_jwt(
        &holder,
        &Url::parse(ISSUER_BASE).unwrap(),
        token["c_nonce"].as_str().unwrap(),
    );
    // The response-encryption key declares its agreement purpose (the same
    // EC key, `alg: ECDH-ES` — wallets send exactly this per metadata).
    let mut enc_jwk = holder.to_public_jwk();
    enc_jwk.alg = Some("ECDH-ES".to_owned());
    let response = client
        .post(format!("{}/credential", service.base))
        .bearer_auth(token["access_token"].as_str().unwrap())
        .json(&json!({
            "credential_configuration_id": "urn:eudi:pid:1",
            "proof": { "proof_type": "jwt", "jwt": proof },
            "credential_response_encryption": {
                "jwk": serde_json::to_value(&enc_jwk).unwrap(),
                "alg": "ECDH-ES",
                "enc": "A128GCM",
            }
        }))
        .send()
        .await
        .unwrap();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let status = response.status();
    let body_text = response.text().await.unwrap();
    assert!(
        status.is_success(),
        "credential endpoint answered {status}: {body_text}"
    );
    assert_eq!(content_type.as_deref(), Some("application/jwt"));

    // Decrypt with the wallet's key and re-verify the credential inside.
    let plaintext = siros_issuer_core::response::decrypt_response(&body_text, &holder)
        .expect("wallet key decrypts the response");
    let credential: Value = serde_json::from_slice(&plaintext).unwrap();
    let issued = credential["credentials"][0]["credential"]
        .as_str()
        .expect("credentials[0].credential");
    verify_sdjwt(
        issued,
        &StaticKey(service.signer.public_jwk().expect("public jwk")),
        &VerifyParams::new(now_unix(), HolderBinding::NotRequired),
    )
    .expect("encrypted-path credential verifies too");
}

/// Configuration is fail-closed at startup (design §4.3, §11): the
/// catalog needs exactly one source, and remote plain HTTP is refused.
#[test]
fn configuration_refusals() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/ts11")
        .display()
        .to_string();
    let neither = r#"
[issuer]
url = "http://127.0.0.1:8080"
"#;
    assert!(Config::from_toml_str(neither).is_err());
    let both = format!(
        r#"
[issuer]
url = "http://127.0.0.1:8080"

[catalog]
static_dir = "{dir}"
mirrors = ["https://registry.example.org/"]
"#
    );
    assert!(Config::from_toml_str(&both).is_err());
    let plaintext_remote = format!(
        r#"
[issuer]
url = "http://issuer.example.org"

[catalog]
static_dir = "{dir}"
"#
    );
    assert!(Config::from_toml_str(&plaintext_remote).is_err());
}
/// The SSE stream (decision D2) opens with the session's current state
/// and then carries live transitions (design §6.1).
#[tokio::test]
async fn sse_streams_session_state() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let integrator = ec_key();

    let (created, _) = create_session(
        &service,
        &integrator,
        json!({"credential": "urn:eudi:pid:1", "subject": {"given_name": "A", "family_name": "B"}}),
    )
    .await;
    let body: Value = created.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap().to_owned();

    let mut response = reqwest::Client::new()
        .get(format!(
            "{}/api/v1/issuance/sessions/{session_id}/events",
            service.base
        ))
        .header(
            "Authorization",
            format!(
                "Bearer {}",
                client_assertion(&integrator, &Url::parse(ISSUER_BASE).unwrap())
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    // The first SSE event is the current state snapshot.
    let first = response.chunk().await.unwrap().expect("initial event");
    let text = String::from_utf8_lossy(&first);
    assert!(text.contains("\"state\":\"offered\""), "got: {text}");
}

// ─── P2: the wallet-initiated authorization-code grant (design §7.2) ──────

fn pkce_pair() -> (String, String) {
    // verifier + S256 challenge (RFC 7636).
    let verifier = siros_issuer_core::sdjwt_issue::b64u(&{
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("OS randomness");
        b
    });
    let challenge = siros_issuer_core::sdjwt_issue::b64u(&{
        use sha2::Digest;
        sha2::Sha256::digest(verifier.as_bytes())
    });
    (verifier, challenge)
}

/// PAR → authorize (Mode A login handoff) → authorize-complete →
/// authorization_code token (PKCE) → credential, verified by
/// verifier-core — the P2 exit criterion.
#[tokio::test]
async fn wallet_initiated_grant_completes_over_mode_a() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(11),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let integrator = ec_key();
    let client = reqwest::Client::new();

    // 1. PAR: the wallet pushes its request (PKCE required).
    let (verifier, challenge) = pkce_pair();
    let par: Value = client
        .post(format!("{}/op/par", service.base))
        .json(&json!({
            "client_id": "suite-wallet",
            "redirect_uri": "http://localhost:3000/cb",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "wallet-state-42",
            "authorization_details": [{
                "type": "openid_credential",
                "credential_configuration_id": "urn:eudi:pid:1",
            }],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_uri = par["request_uri"].as_str().unwrap().to_owned();
    assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri/"));

    // 2. Authorize: 302 to the integrator login with the issuer_state.
    // The handoff is a 302; do not follow it (reqwest would try the
    // mock login URL).
    let no_follow = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let authorize = no_follow
        .get(format!("{}/authorize", service.base))
        .query(&[
            ("client_id", "suite-wallet"),
            ("request_uri", request_uri.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(authorize.status(), reqwest::StatusCode::FOUND);
    let location = authorize
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("login handoff location")
        .to_owned();
    let issuer_state = location
        .split("issuer_state=")
        .nth(1)
        .map(|v| v.split('&').next().unwrap_or(v))
        .expect("issuer_state in the handoff")
        .to_owned();
    assert_eq!(
        location,
        format!("http://127.0.0.1:8080/dev-portal/login?issuer_state={issuer_state}")
    );

    // 3. The integrator authenticates the user and completes (S2S).
    let complete: Value = client
        .post(format!(
            "{}/api/v1/issuance/sessions/{issuer_state}/authorize",
            service.base
        ))
        .header(
            "Authorization",
            format!(
                "Bearer {}",
                client_assertion(&integrator, &Url::parse(ISSUER_BASE).unwrap())
            ),
        )
        .json(&json!({
            "credential": "urn:eudi:pid:1",
            "subject": {
                "given_name": "Mode",
                "family_name": "A",
                "birth_date": "1990-01-01"
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let redirect = complete["redirect"].as_str().unwrap().to_owned();
    assert!(redirect.starts_with("http://localhost:3000/cb?"));
    let code = redirect
        .split("code=")
        .nth(1)
        .map(|v| v.split('&').next().unwrap_or(v))
        .expect("code in the redirect")
        .to_owned();
    assert!(redirect.contains("state=wallet-state-42"));

    // 4. Token: authorization_code + PKCE.
    let token: Value = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.clone()),
            ("redirect_uri", "http://localhost:3000/cb".to_owned()),
            ("code_verifier", verifier.clone()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(token["token_type"], "Bearer");

    // 5. Credential with the jwt proof.
    let holder = ec_key();
    let proof = proof_jwt(
        &holder,
        &Url::parse(ISSUER_BASE).unwrap(),
        token["c_nonce"].as_str().unwrap(),
    );
    let response: Value = client
        .post(format!("{}/credential", service.base))
        .bearer_auth(token["access_token"].as_str().unwrap())
        .json(&json!({
            "credential_configuration_id": "urn:eudi:pid:1",
            "proof": { "proof_type": "jwt", "jwt": proof },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let issued = response["credentials"][0]["credential"]
        .as_str()
        .expect("credentials[0].credential");
    let verified = verify_sdjwt(
        issued,
        &StaticKey(service.signer.public_jwk().expect("public jwk")),
        &VerifyParams::new(now_unix(), HolderBinding::NotRequired),
    )
    .expect("verifier-core verifies the wallet-initiated credential");
    assert_eq!(verified.vct, "urn:eudi:pid:1");
    assert_eq!(verified.claims["given_name"], "Mode");
}

/// PKCE mismatch is refused at /token (RFC 7636 §4.6) — and the code is
/// not consumed by a failed attempt... it *is* single-use on success only.
#[tokio::test]
async fn pkce_mismatch_refuses_the_token() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let integrator = ec_key();
    let client = reqwest::Client::new();

    let (_verifier, challenge) = pkce_pair();
    let par: Value = client
        .post(format!("{}/op/par", service.base))
        .json(&json!({
            "client_id": "suite-wallet",
            "redirect_uri": "http://localhost:3000/cb",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "authorization_details": [{
                "type": "openid_credential",
                "credential_configuration_id": "urn:eudi:pid:1",
            }],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_uri = par["request_uri"].as_str().unwrap().to_owned();
    // The handoff is a 302; do not follow it (reqwest would try the
    // mock login URL).
    let no_follow = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let authorize = no_follow
        .get(format!("{}/authorize", service.base))
        .query(&[
            ("client_id", "suite-wallet"),
            ("request_uri", request_uri.as_str()),
        ])
        .send()
        .await
        .unwrap();
    let location = authorize
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("location")
        .to_owned();
    let issuer_state = location
        .split("issuer_state=")
        .nth(1)
        .map(|v| v.split('&').next().unwrap_or(v))
        .expect("issuer_state")
        .to_owned();
    let complete: Value = client
        .post(format!(
            "{}/api/v1/issuance/sessions/{issuer_state}/authorize",
            service.base
        ))
        .header(
            "Authorization",
            format!(
                "Bearer {}",
                client_assertion(&integrator, &Url::parse(ISSUER_BASE).unwrap())
            ),
        )
        .json(&json!({
            "credential": "urn:eudi:pid:1",
            "subject": {"given_name": "A", "family_name": "B"}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = complete["redirect"]
        .as_str()
        .unwrap()
        .split("code=")
        .nth(1)
        .map(|v| v.split('&').next().unwrap_or(v))
        .expect("code")
        .to_owned();

    // Wrong verifier → refused.
    let refused = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.clone()),
            ("redirect_uri", "http://localhost:3000/cb".to_owned()),
            ("code_verifier", "wrong-verifier-entirely".to_owned()),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// A DPoP-bound access token demands a matching DPoP proof (correct jkt,
/// correct ath) at /credential (RFC 9449 §4) — and a proof from another
/// key is refused.
#[tokio::test]
async fn dpop_bound_tokens_require_matching_proofs() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let client = reqwest::Client::new();

    // Mint a pre-auth session, then redeem with a DPoP proof at /token.
    let integrator = ec_key();
    let (created, _) = create_session(
        &service,
        &integrator,
        json!({"credential": "urn:eudi:pid:1", "subject": {"given_name": "D", "family_name": "P"}, "grant": {"tx_code": {"value": "654321"}}}),
    )
    .await;
    let body: Value = created.json().await.unwrap();
    let offer_uri = body["offer_uri"].as_str().unwrap().to_owned();
    let offer: Value = client
        .get(format!(
            "{}{}",
            service.base,
            offer_uri.trim_start_matches(ISSUER_BASE)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned();

    // DPoP key + proof for /token (no ath at the token endpoint).
    let dpop_key = ec_key();
    let now = now_unix();
    let token_htu = Url::parse(ISSUER_BASE).unwrap().join("token").unwrap();
    let proof = sign_jwt(
        &dpop_key,
        "dpop+jwt",
        &json!({
            "htm": "POST",
            "htu": token_htu.as_str(),
            "iat": now,
            "jti": siros_issuer_core::sdjwt_issue::b64u(&{
                let mut b = [0u8; 16];
                getrandom::fill(&mut b).expect("OS randomness");
                b
            }),
        }),
        true,
    );
    let token: Value = client
        .post(format!("{}/token", service.base))
        .header("DPoP", &proof)
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre-authorized_code", code.to_owned()),
            ("tx_code", "654321".to_owned()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access_token = token["access_token"].as_str().unwrap().to_owned();

    // Holder + proof; /credential without DPoP → refused.
    let holder = ec_key();
    let cred_proof = proof_jwt(
        &holder,
        &Url::parse(ISSUER_BASE).unwrap(),
        token["c_nonce"].as_str().unwrap(),
    );
    let refused = client
        .post(format!("{}/credential", service.base))
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": "urn:eudi:pid:1",
            "proof": { "proof_type": "jwt", "jwt": cred_proof },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);

    // With a DPoP proof from the SAME key + ath → issued and verified.
    let ath = siros_issuer_service::dpop::access_token_hash(&access_token);
    let cred_htu = Url::parse(ISSUER_BASE).unwrap().join("credential").unwrap();
    let dpop_cred = sign_jwt(
        &dpop_key,
        "dpop+jwt",
        &json!({
            "htm": "POST",
            "htu": cred_htu.as_str(),
            "iat": now,
            "jti": siros_issuer_core::sdjwt_issue::b64u(&{
                let mut b = [0u8; 16];
                getrandom::fill(&mut b).expect("OS randomness");
                b
            }),
            "ath": ath,
        }),
        true,
    );
    let cred_proof = proof_jwt(
        &holder,
        &Url::parse(ISSUER_BASE).unwrap(),
        token["c_nonce"].as_str().unwrap(),
    );
    let issued: Value = client
        .post(format!("{}/credential", service.base))
        .header("DPoP", &dpop_cred)
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": "urn:eudi:pid:1",
            "proof": { "proof_type": "jwt", "jwt": cred_proof },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    verify_sdjwt(
        issued["credentials"][0]["credential"]
            .as_str()
            .expect("credential"),
        &StaticKey(service.signer.public_jwk().expect("public jwk")),
        &VerifyParams::new(now_unix(), HolderBinding::NotRequired),
    )
    .expect("DPoP-constrained issuance verifies");

    // A proof from a DIFFERENT key → refused.
    let other_key = ec_key();
    let bad_dpop = sign_jwt(
        &other_key,
        "dpop+jwt",
        &json!({
            "htm": "POST",
            "htu": cred_htu.as_str(),
            "iat": now,
            "jti": siros_issuer_core::sdjwt_issue::b64u(&{
                let mut b = [0u8; 16];
                getrandom::fill(&mut b).expect("OS randomness");
                b
            }),
            "ath": ath,
        }),
        true,
    );
    let cred_proof = proof_jwt(
        &holder,
        &Url::parse(ISSUER_BASE).unwrap(),
        token["c_nonce"].as_str().unwrap(),
    );
    let refused = client
        .post(format!("{}/credential", service.base))
        .header("DPoP", &bad_dpop)
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": "urn:eudi:pid:1",
            "proof": { "proof_type": "jwt", "jwt": cred_proof },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// A JWT proof carrying a non-issued nonce is refused with
/// `invalid_nonce` — OpenID4VCI 1.0 ID1 §7.2.2 — and never with a proof
/// refusal: the credential endpoint verifies jwt proofs with the jwt
/// verifier only, so a nonce mismatch cannot be masked by the attestation
/// path's typ refusal. Regression: a cross-type fallback chain made this
/// answer `invalid_proof` (the suite's invalid-nonce module reads the
/// code). Reverting the dispatch reintroduces the mask; this test fails.
#[tokio::test]
async fn jwt_proof_with_wrong_nonce_is_invalid_nonce_not_invalid_proof() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let integrator = ec_key();

    let (created, _) = create_session(
        &service,
        &integrator,
        json!({"credential": "urn:eudi:pid:1", "subject": {"given_name": "A", "family_name": "B"}}),
    )
    .await;
    let body: Value = created.json().await.unwrap();
    let offer_uri = body["offer_uri"].as_str().unwrap().to_owned();

    let client = reqwest::Client::new();
    let offer: Value = client
        .get(format!(
            "{}{}",
            service.base,
            offer_uri.trim_start_matches(ISSUER_BASE)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned();
    let token: Value = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre-authorized_code", code.to_owned()),
            ("tx_code", "654321".to_owned()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // A well-formed jwt proof whose nonce was never minted by this issuer.
    let holder = ec_key();
    let proof = proof_jwt(
        &holder,
        &Url::parse(ISSUER_BASE).unwrap(),
        "not-a-issued-nonce",
    );
    let response = client
        .post(format!("{}/credential", service.base))
        .bearer_auth(token["access_token"].as_str().unwrap())
        .json(&json!({
            "credential_configuration_id": "urn:eudi:pid:1",
            "proof": { "proof_type": "jwt", "jwt": proof },
        }))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let error: Value = response.json().await.unwrap();
    assert!(
        !status.is_success(),
        "wrong nonce must be refused, got {status}"
    );
    assert_eq!(error["error"], "invalid_nonce", "body: {error}");
    assert_ne!(error["error"], "invalid_proof");
}

/// The mso_mdoc flow end-to-end (design §8.2): a session over the catalog's
/// mdoc PID (subject nested under the doctype namespace — its claim paths
/// are [namespace, element]), redeemed with a key-attestation proof
/// (Appendix D.1, the OIDF suite's shape: typ key-attestation+jwt, x5c
/// leaf, attested_keys[0] the device key, nonce = c_nonce, no aud). The
/// oracle is threefold: the response carries the base64url IssuerSigned
/// (Appendix A.2), its COSE_Sign1 verifies under the issuer's public key,
/// and the MSO's DeviceKey IS the attested key — the attestation chain
/// binds the credential to the device, not to the transport.
#[tokio::test]
async fn mdoc_credential_via_attestation_proof_binds_the_attested_device_key() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(0),
        updates: Mutex::new(Vec::new()),
    });
    let (signer, signer_private) = test_signer();
    let service = spawn_service(
        Arc::new(PermitPdp),
        allocator,
        (signer.clone(), signer_private),
    )
    .await;
    let integrator = ec_key();

    let (created, _) = create_session(
        &service,
        &integrator,
        json!({
            "credential": "eu.europa.ec.eudi.pid.1",
            "subject": {
                "eu.europa.ec.eudi.pid.1": {
                    "given_name": "A",
                    "family_name": "B",
                    "birth_date": "1982-07-12",
                    "place_of_birth": {
                        "country": "SE",
                        "locality": "Stockholm",
                    },
                    "nationality": ["SE"],
                    "issuing_authority": "Skatteverket",
                    "issuing_country": "SE",
                }
            }
        }),
    )
    .await;
    let status = created.status();
    let body: Value = created.json().await.unwrap();
    assert!(status.is_success(), "session create: {status} {body}");
    let offer_uri = body["offer_uri"].as_str().unwrap().to_owned();

    let client = reqwest::Client::new();
    let offer: Value = client
        .get(format!(
            "{}{}",
            service.base,
            offer_uri.trim_start_matches(ISSUER_BASE)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        offer["credential_configuration_ids"][0], "eu.europa.ec.eudi.pid.1",
        "the offer names the mdoc configuration"
    );
    let code = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned();
    let token: Value = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre-authorized_code", code),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access_token = token["access_token"].as_str().unwrap().to_owned();
    let c_nonce = token["c_nonce"].as_str().unwrap().to_owned();

    // The attestation: signed by an attestation issuer whose self-signed
    // cert rides the x5c header; attested_keys[0] is the device key.
    let attestation_key: jose_rs::jwk::Jwk = serde_json::from_str(
        r#"{"kty":"EC","x":"ktT77AqMntawPyU772lBg8nd7cwENrYyOL_KWbYN8Jc","y":"67lPXEq5gJdimDYD0AacxLfRfIm2-fSNd3HBqyXXvBI","crv":"P-256","d":"KJEKZo2PQq6E40P6HMenViCVBRXoWD2FDyevRsJnlG0","kid":"attestation-1","alg":"ES256","use":"sig"}"#,
    )
    .unwrap();
    let device_jwk: Value = serde_json::from_str(
        r#"{"kty":"EC","x":"_MUU-7kbV7WJXhrXJuDaAhHKqvDBHq-a4NH1ekAqo8I","y":"7JpnjHEJoyGLdjw_HkNBI9KU7CsswTrDTb7RSmLZ5m0","crv":"P-256","kid":"device-1","alg":"ES256","use":"sig"}"#,
    )
    .unwrap();
    let attestation_cert_der = {
        let key = p256::ecdsa::SigningKey::from_slice(
            &base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                attestation_key.d.as_deref().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        use p256::pkcs8::EncodePrivateKey;
        let pkcs8 = key.to_pkcs8_der().unwrap();
        let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .unwrap();
        let params =
            rcgen::CertificateParams::new(vec!["attestation.example.org".to_string()]).unwrap();
        params.self_signed(&kp).unwrap().der().to_vec()
    };
    let mut header = jose_rs::JoseHeader::new("ES256");
    header.typ = Some("key-attestation+jwt".to_owned());
    header.x5c = Some(vec![STANDARD.encode(attestation_cert_der)]);
    let now = now_unix();
    let claims = json!({
        "attested_keys": [device_jwk],
        "nonce": c_nonce,
        "iat": now,
        "exp": now + 300,
    });
    let attestation = jose_rs::jws::compact::sign_with_jwk_options(
        &attestation_key,
        &serde_json::to_vec(&claims).unwrap(),
        &header,
        &jose_rs::jws::compact::SignOptions::new().with_key_reference_headers(true),
    )
    .unwrap();

    let response = client
        .post(format!("{}/credential", service.base))
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": "eu.europa.ec.eudi.pid.1",
            "proofs": { "attestation": [attestation] },
        }))
        .send()
        .await
        .unwrap();
    let http_status = response.status();
    let credential: Value = response.json().await.unwrap();
    assert!(
        http_status.is_success(),
        "mdoc credential endpoint: {http_status} {credential}"
    );
    assert_eq!(credential["credentials"][0]["format"], "mso_mdoc");
    assert!(
        credential["notification_id"].is_string(),
        "the notification handle rides the response"
    );
    let issued_b64 = credential["credentials"][0]["credential"]
        .as_str()
        .expect("base64url IssuerSigned");

    // Oracle 1: base64url decodes to the IssuerSigned CBOR object.
    let issuer_signed_bytes =
        siros_issuer_core::sdjwt_issue::b64u_decode(issued_b64).expect("base64url");
    let issuer_signed: ciborium::Value =
        ciborium::from_reader(issuer_signed_bytes.as_slice()).expect("IssuerSigned CBOR");
    let doc_map = issuer_signed.as_map().expect("IssuerSigned is a map");
    let get = |key: &str| {
        doc_map
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == key))
            .map(|(_, v)| v.clone())
    };
    // ISO 18013-5: IssuerSigned = {nameSpaces, issuerAuth} — the
    // docType lives in the MSO (issuerAuth's payload) and the wallet's
    // surrounding Document, not here.
    assert!(
        get("nameSpaces").is_some() && get("issuerAuth").is_some(),
        "IssuerSigned carries nameSpaces and issuerAuth"
    );
    let issuer_auth = get("issuerAuth")
        .and_then(|v| v.as_array().cloned())
        .expect("issuerAuth COSE_Sign1 array");

    // Oracle 2: the COSE_Sign1 signature verifies under the issuer's
    // public key (Sig_structure: "Signature1", protected, empty aad,
    // payload — RFC 9052 §4.2 with the JOSE raw r||s signature format).
    let protected = issuer_auth[0].as_bytes().expect("protected header").clone();
    let payload = issuer_auth[2].as_bytes().expect("MSO payload").clone();
    let signature = issuer_auth[3].as_bytes().expect("signature").clone();
    let sig_structure = {
        let mut out = Vec::new();
        ciborium::into_writer(
            &ciborium::Value::Array(vec![
                ciborium::Value::Text("Signature1".into()),
                ciborium::Value::Bytes(protected.clone()),
                ciborium::Value::Bytes(Vec::new()),
                ciborium::Value::Bytes(payload.clone()),
            ]),
            &mut out,
        )
        .unwrap();
        out
    };
    let issuer_public = signer.public_jwk().unwrap();
    let x =
        siros_issuer_core::sdjwt_issue::b64u_decode(issuer_public.x.as_deref().unwrap()).unwrap();
    let y =
        siros_issuer_core::sdjwt_issue::b64u_decode(issuer_public.y.as_deref().unwrap()).unwrap();
    let sec1: Vec<u8> = std::iter::once(0x04u8)
        .chain(x.into_iter())
        .chain(y.into_iter())
        .collect();
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).unwrap();
    let cose_sig = p256::ecdsa::Signature::from_slice(&signature).expect("raw r||s signature");
    use p256::ecdsa::signature::Verifier as _;
    vk.verify(&sig_structure, &cose_sig)
        .expect("the IssuerSigned verifies under the issuer's public key");

    // Oracle 3: the MSO's DeviceKey is the ATTESTED key — the credential
    // is bound to the device key from the attestation proof. The MSO also
    // carries the docType (ISO 18013-5 §9.1.2.5).
    // The COSE_Sign1 payload is Tag24(MSO bytes) (ISO 18013-5 §9.1.2.5):
    // unwrap the tag, then parse the MSO map.
    let payload_value: ciborium::Value =
        ciborium::from_reader(payload.as_slice()).expect("payload CBOR");
    let mso_bytes = match &payload_value {
        ciborium::Value::Tag(24, inner) => match inner.as_ref() {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => panic!("tag24 inner is not bytes"),
        },
        _ => panic!("payload is not tag24-wrapped"),
    };
    let mso: ciborium::Value = ciborium::from_reader(mso_bytes.as_slice()).expect("MSO CBOR");
    let mso_map = mso.as_map().expect("MSO is a map").clone();
    let mso_get = |key: &str| {
        mso_map
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == key))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(
        mso_get("docType")
            .and_then(|v| v.as_text().map(str::to_owned))
            .as_deref(),
        Some("eu.europa.ec.eudi.pid.1")
    );
    let device_key = mso_map
        .iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == "deviceKeyInfo"))
        .and_then(|(_, v)| v.as_map().cloned())
        .and_then(|info| {
            info.iter()
                .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == "deviceKey"))
                .map(|(_, v)| v.clone())
        })
        .and_then(|v| v.as_map().cloned())
        .expect("deviceKeyInfo.deviceKey (COSE Key map)");
    let cose_int = |label: i64| {
        device_key
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Integer(i) if *i == label.into()))
            .map(|(_, v)| v.clone())
    };
    let x = cose_int(-2)
        .and_then(|v| v.as_bytes().cloned())
        .expect("kty EC2 x (-2)");
    let y = cose_int(-3)
        .and_then(|v| v.as_bytes().cloned())
        .expect("kty EC2 y (-3)");
    assert_eq!(
        x,
        siros_issuer_core::sdjwt_issue::b64u_decode(device_jwk["x"].as_str().unwrap()).unwrap(),
        "the MSO DeviceKey x is the attested key's x"
    );
    assert_eq!(
        y,
        siros_issuer_core::sdjwt_issue::b64u_decode(device_jwk["y"].as_str().unwrap()).unwrap(),
        "the MSO DeviceKey y is the attested key's y"
    );

    // And the elements: the nested subject became namespace elements.
    let name_spaces = get("nameSpaces")
        .and_then(|v| v.as_map().cloned())
        .expect("nameSpaces");
    assert_eq!(name_spaces.len(), 1, "one namespace (the doctype's)");
    let (ns_key, items) = name_spaces.first().unwrap();
    assert!(matches!(ns_key, ciborium::Value::Text(t) if t == "eu.europa.ec.eudi.pid.1"));
    let items = items.as_array().expect("namespace items array");
    // The EUDI PID Rulebook mandatory set, as the suite's
    // PidDataElements encodes it.
    assert_eq!(
        items.len(), 7,
        "family_name, given_name, birth_date, place_of_birth, nationality, issuing_authority, issuing_country"
    );
    // The birth_date element's value is an RFC 8943 full-date: tag-1004
    // text (ISO 18013-5 element typing — the suite's fullDate constraint
    // and wallets demand the tag).
    let mut saw_tagged_birth_date = false;
    for item in items {
        let inner = match item {
            ciborium::Value::Tag(24, inner) => inner.as_ref().clone(),
            _ => panic!("item not tag24"),
        };
        let bytes = match inner {
            ciborium::Value::Bytes(b) => b,
            _ => panic!("tag24 inner not bytes"),
        };
        let entry: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let map = entry.as_map().expect("item map").clone();
        let identifier = map
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == "elementIdentifier"))
            .and_then(|(_, v)| v.as_text().map(str::to_owned));
        if identifier.as_deref() == Some("birth_date") {
            let value = map
                .iter()
                .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == "elementValue"))
                .map(|(_, v)| v.clone())
                .expect("elementValue");
            assert_eq!(
                value,
                ciborium::Value::Tag(1004, Box::new(ciborium::Value::Text("1982-07-12".into()))),
                "birth_date is an RFC 8943 tag-1004 full-date"
            );
            saw_tagged_birth_date = true;
        }
    }
    assert!(saw_tagged_birth_date, "birth_date element present");
}

/// Mode B end-to-end (design §7.3): the wallet authenticates the subject
/// by PRESENTING a PID, and the presented claims become the issued
/// credential's subject data. Sources of truth: the flow contract in
/// §7.3 (PAR → DPoP-bound challenge → signed OID4VCI request →
/// direct_post.jwt presentation → code → token), and verifier-core's
/// testutil for the wallet side (the presented PID and its KB-JWT are
/// built with the verifier's own tooling, not re-implemented here). The
/// oracle: the issued credential carries the PRESENTED PID's claim
/// values, and the code was sender-constrained to the challenge's DPoP
/// key (a mismatched key is refused at /token).
#[tokio::test]
async fn wallet_initiated_grant_completes_over_mode_b_presentation() {
    use siros_verifier_core::sdjwt::HashAlg;
    use siros_verifier_core::testutil::{self, IssueSpec, KbSpec, Seg};

    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(21),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let client = reqwest::Client::new();
    let base = Url::parse(ISSUER_BASE).unwrap();

    // 1. PAR for the PID (PKCE required, like any wallet-initiated flow).
    let (verifier, challenge) = pkce_pair();
    let par: Value = client
        .post(format!("{}/op/par", service.base))
        .json(&json!({
            "client_id": "suite-wallet",
            "redirect_uri": "http://localhost:3000/cb",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "wallet-state-b",
            "authorization_details": [{
                "type": "openid_credential",
                "credential_configuration_id": "urn:eudi:pid:1",
            }],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request_uri = par["request_uri"].as_str().unwrap().to_owned();

    // 2. /authorize hands off with the issuer_state; the Mode B wallet
    //    takes it to the challenge instead of a portal login.
    let no_follow = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let authorize = no_follow
        .get(format!("{}/authorize", service.base))
        .query(&[
            ("client_id", "suite-wallet"),
            ("request_uri", request_uri.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(authorize.status(), reqwest::StatusCode::FOUND);
    let location = authorize
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("login handoff location")
        .to_owned();
    let issuer_state = location
        .split("issuer_state=")
        .nth(1)
        .map(|v| v.split('&').next().unwrap_or(v))
        .expect("issuer_state in the handoff")
        .to_owned();

    // 3. DPoP-bound challenge: the wallet key that proves possession here
    //    must re-appear at /token with the code.
    let dpop_key = ec_key();
    let now = now_unix();
    let challenge_htu = base.join("authorization-challenge").unwrap();
    let jti = || {
        siros_issuer_core::sdjwt_issue::b64u(&{
            let mut b = [0u8; 16];
            getrandom::fill(&mut b).expect("OS randomness");
            b
        })
    };
    let dpop_proof = sign_jwt(
        &dpop_key,
        "dpop+jwt",
        &json!({ "htm": "POST", "htu": challenge_htu.as_str(), "iat": now, "jti": jti() }),
        true,
    );
    let challenge_reply: Value = client
        .post(format!("{}/authorization-challenge", service.base))
        .header("DPoP", &dpop_proof)
        .json(&json!({ "issuer_state": issuer_state }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let jar = challenge_reply["authorization_request"]
        .as_str()
        .unwrap_or_else(|| panic!("the signed OpenID4VP request object, reply: {challenge_reply}"))
        .to_owned();

    // 4. The wallet reads the request object: nonce, client_id, the
    //    ephemeral encryption key and the response_uri.
    let jar_payload: Value = serde_json::from_slice(
        &siros_issuer_core::sdjwt_issue::b64u_decode(jar.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    let oid4vp_nonce = jar_payload["nonce"].as_str().unwrap().to_owned();
    let oid4vp_state = jar_payload["state"].as_str().unwrap().to_owned();
    let oid4vp_client_id = jar_payload["client_id"].as_str().unwrap().to_owned();
    // The request object carries the configured issuer base (8080); the
    // spawned test service binds a random port — rewrite like offer URIs.
    let response_uri = jar_payload["response_uri"]
        .as_str()
        .unwrap()
        .replace(ISSUER_BASE, service.base.trim_end_matches('/'));
    let enc_pub: jose_rs::jwk::Jwk =
        serde_json::from_value(jar_payload["client_metadata"]["jwks"]["keys"][0].clone()).unwrap();
    let enc_kid = enc_pub.kid.clone().unwrap();

    // 5. The wallet holds a PID issued by another issuer (x5c-carried,
    //    resolved by the verifier's X5cLeaf; trust decided by the PDP).
    let (pid_issuer_cert, pid_issuer_key) = testutil::self_signed_ec("pid-issuer.example", "ES256");
    let holder = testutil::ec_jwk("ES256", "holder");
    let mut spec = IssueSpec::new(json!({
        "iss": "https://pid-issuer.example",
        "vct": "urn:eudi:pid:1",
        "iat": now - 10,
        "exp": now + 100_000,
        "given_name": "Presented",
        "family_name": "Subject",
        "birth_date": "1999-12-31",
    }));
    spec.holder_pub = Some(testutil::public_of(&holder));
    spec.x5c_der = vec![pid_issuer_cert];
    spec.conceal = vec![
        vec![Seg::Key("given_name")],
        vec![Seg::Key("family_name")],
        vec![Seg::Key("birth_date")],
    ];
    let issued_pid = testutil::issue(&pid_issuer_key, &spec).unwrap();
    let presentation = testutil::present(
        &issued_pid,
        &[0, 1, 2],
        Some(KbSpec {
            holder: &holder,
            aud: &oid4vp_client_id,
            nonce: &oid4vp_nonce,
            iat: now,
        }),
        HashAlg::Sha256,
    )
    .unwrap();

    // 6. direct_post.jwt: vp_token + state, JWE-encrypted to the
    //    request's ephemeral key, POSTed to the response_uri.
    let body = serde_json::to_vec(&json!({
        "vp_token": { "pid": [presentation] },
        "state": oid4vp_state,
    }))
    .unwrap();
    let jwe = siros_issuer_core::response::encrypt_response(
        &enc_pub,
        &body,
        Some(&enc_kid),
        jose_rs::algorithm::JweEncryption::A128GCM,
    )
    .unwrap();
    let response_reply: Value = client
        .post(&response_uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("response={}", urlencoding_encode(&jwe)))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let auth_code = response_reply["authorization_code"]
        .as_str()
        .unwrap_or_else(|| panic!("the minted authorization code, reply: {response_reply}"))
        .to_owned();

    // 7. The code is sender-constrained: a DIFFERENT DPoP key is refused.
    let other_key = ec_key();
    let token_htu = base.join("token").unwrap();
    let other_proof = sign_jwt(
        &other_key,
        "dpop+jwt",
        &json!({ "htm": "POST", "htu": token_htu.as_str(), "iat": now, "jti": jti() }),
        true,
    );
    let refused: Value = client
        .post(format!("{}/token", service.base))
        .header("DPoP", &other_proof)
        .form(&token_form(&[
            ("grant_type", "authorization_code".to_owned()),
            ("code", auth_code.clone()),
            ("redirect_uri", "http://localhost:3000/cb".to_owned()),
            ("code_verifier", verifier.clone()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // The token endpoint's OAuth error mapping (RFC 6749 §5.2).
    assert_eq!(refused["error"], "invalid_grant", "body: {refused}");

    // 8. The challenge's key exchanges the code.
    let token_proof = sign_jwt(
        &dpop_key,
        "dpop+jwt",
        &json!({ "htm": "POST", "htu": token_htu.as_str(), "iat": now, "jti": jti() }),
        true,
    );
    let token: Value = client
        .post(format!("{}/token", service.base))
        .header("DPoP", &token_proof)
        .form(&token_form(&[
            ("grant_type", "authorization_code".to_owned()),
            ("code", auth_code.clone()),
            ("redirect_uri", "http://localhost:3000/cb".to_owned()),
            ("code_verifier", verifier.clone()),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access_token = token["access_token"].as_str().unwrap().to_owned();
    let c_nonce = token["c_nonce"].as_str().unwrap().to_owned();

    // 9. Credential: jwt proof + DPoP (ath) — the issued SD-JWT carries
    //    the PRESENTED PID's claims.
    let proof = proof_jwt(&holder, &base, &c_nonce);
    let ath = siros_issuer_service::dpop::access_token_hash(&access_token);
    let cred_htu = base.join("credential").unwrap();
    let dpop_cred = sign_jwt(
        &dpop_key,
        "dpop+jwt",
        &json!({ "htm": "POST", "htu": cred_htu.as_str(), "iat": now, "jti": jti(), "ath": ath }),
        true,
    );
    let credential: Value = client
        .post(format!("{}/credential", service.base))
        .header("DPoP", &dpop_cred)
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": "urn:eudi:pid:1",
            "proof": { "proof_type": "jwt", "jwt": proof },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sd_jwt = credential["credentials"][0]["credential"]
        .as_str()
        .expect("the issued SD-JWT")
        .to_owned();

    // Oracle: the presented claims became the subject data. Walk the
    // disclosures and assert the presented values are among them (the
    // credential discloses exactly the catalog's claims).
    let mut found = Vec::new();
    for part in sd_jwt.split('~').skip(1) {
        if part.is_empty() {
            continue;
        }
        let decoded: Value =
            serde_json::from_slice(&siros_issuer_core::sdjwt_issue::b64u_decode(part).unwrap())
                .unwrap();
        if decoded.as_array().is_some_and(|a| a.len() == 3) {
            found.push((
                decoded[1].as_str().unwrap_or_default().to_owned(),
                decoded[2].clone(),
            ));
        }
    }
    let claim = |name: &str| {
        found
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .unwrap_or(Value::Null)
    };
    assert_eq!(
        claim("given_name"),
        json!("Presented"),
        "disclosures: {found:?}"
    );
    assert_eq!(claim("family_name"), json!("Subject"));
    assert_eq!(claim("birth_date"), json!("1999-12-31"));
}

/// Minimal percent-encoding for the JWE inside a form body (base64url
/// needs only `=` and `+`/`/` are absent — cover `=` anyway).
fn urlencoding_encode(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '=' => "%3D".to_owned(),
            '+' => "%2B".to_owned(),
            '/' => "%2F".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

/// nym_auth issuance end-to-end (design §8.3, rulebook #1): the
/// rulebook-governed mdoc carries the catalog-resolved salt length
/// (vega-mc publishes 32 — resolved from the circuit manifest, not
/// hand-copied), the ssc commitment at its configured path
/// (sha-256 over the HKDF opening from issuing_country +
/// personal_administrative_number), and the response's
/// credential_metadata.auxiliary_data carries the opening (the
/// auxiliary-data extension). Oracles: the document's ssc element
/// hashes from the returned opening; the salt length came from the
/// catalog (not the default sizing); the opening is the same one the
/// document commits.
#[tokio::test]
async fn nym_auth_rulebook_issuance_resolves_salt_and_commitments_from_config() {
    use base64::Engine as _;

    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(31),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let integrator = ec_key();

    // 1. Session over the rulebook credential, subject nested under the
    //    doctype namespace (the derivation inputs are subject claims).
    let (created, _) = create_session(
        &service,
        &integrator,
        json!({
            "credential": "eu.europa.ec.eudi.nym_auth.1",
            "subject": {
                "eu.europa.ec.eudi.nym_auth.1": {
                    "birth_date": "1982-07-12",
                    "birthplace_country": "SE",
                    "issuing_country": "SE",
                    "personal_administrative_number": "18880307-9999",
                }
            }
        }),
    )
    .await;
    let status = created.status();
    let body: Value = created.json().await.unwrap();
    assert!(status.is_success(), "session create: {status} {body}");
    let offer_uri = body["offer_uri"].as_str().unwrap().to_owned();

    let client = reqwest::Client::new();
    let offer: Value = client
        .get(format!(
            "{}{}",
            service.base,
            offer_uri.trim_start_matches(ISSUER_BASE)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned();
    let token: Value = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre-authorized_code", code),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // 2. Attestation proof (the mdoc proof type for this credential).
    let attestation_key: jose_rs::jwk::Jwk = serde_json::from_str(
        r#"{"kty":"EC","x":"ktT77AqMntawPyU772lBg8nd7cwENrYyOL_KWbYN8Jc","y":"67lPXEq5gJdimDYD0AacxLfRfIm2-fSNd3HBqyXXvBI","crv":"P-256","d":"KJEKZo2PQq6E40P6HMenViCVBRXoWD2FDyevRsJnlG0","kid":"attestation-1","alg":"ES256","use":"sig"}"#,
    )
    .unwrap();
    let device_jwk: Value = serde_json::from_str(
        r#"{"kty":"EC","x":"_MUU-7kbV7WJXhrXJuDaAhHKqvDBHq-a4NH1ekAqo8I","y":"7JpnjHEJoyGLdjw_HkNBI9KU7CsswTrDTb7RSmLZ5m0","crv":"P-256","kid":"device-1","alg":"ES256","use":"sig"}"#,
    )
    .unwrap();
    let attestation_cert_der = {
        let key = p256::ecdsa::SigningKey::from_slice(
            &siros_issuer_core::sdjwt_issue::b64u_decode(attestation_key.d.as_deref().unwrap())
                .unwrap(),
        )
        .unwrap();
        use p256::pkcs8::EncodePrivateKey;
        let pkcs8 = key.to_pkcs8_der().unwrap();
        let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .unwrap();
        let params =
            rcgen::CertificateParams::new(vec!["attestation.example.org".to_string()]).unwrap();
        params.self_signed(&kp).unwrap().der().to_vec()
    };
    let mut header = jose_rs::JoseHeader::new("ES256");
    header.typ = Some("key-attestation+jwt".to_owned());
    header.x5c = Some(vec![
        base64::engine::general_purpose::STANDARD.encode(attestation_cert_der)
    ]);
    let now = now_unix();
    let attestation = jose_rs::jws::compact::sign_with_jwk_options(
        &attestation_key,
        &serde_json::to_vec(&json!({
            "attested_keys": [device_jwk],
            "nonce": token["c_nonce"],
            "iat": now,
            "exp": now + 300,
        }))
        .unwrap(),
        &header,
        &jose_rs::jws::compact::SignOptions::new().with_key_reference_headers(true),
    )
    .unwrap();

    // 3. Credential.
    let response = client
        .post(format!("{}/credential", service.base))
        .bearer_auth(token["access_token"].as_str().unwrap())
        .json(&json!({
            "credential_configuration_id": "eu.europa.ec.eudi.nym_auth.1",
            "proofs": { "attestation": [attestation] },
        }))
        .send()
        .await
        .unwrap();
    let http_status = response.status();
    let credential: Value = response.json().await.unwrap();
    assert!(
        http_status.is_success(),
        "nym_auth credential: {http_status} {credential}"
    );

    // 4. Oracle: the response carries the opening (the auxiliary-data
    //    extension), type hash_commitment, at the ssc path.
    let aux = &credential["credential_metadata"]["auxiliary_data"];
    let entries: Vec<Value> = serde_json::from_value(aux.clone()).expect("auxiliary_data entries");
    assert_eq!(entries.len(), 1, "one to_wallet entry");
    assert_eq!(entries[0]["type"], "hash_commitment");
    assert_eq!(
        entries[0]["path"],
        json!(["eu.europa.ec.eudi.nym_auth.1", "ssc"])
    );
    assert_eq!(entries[0]["alg"], "sha-256");
    let opening_b64 = entries[0]["opening"].as_str().expect("the opening");
    let opening =
        siros_issuer_core::sdjwt_issue::b64u_decode(opening_b64).expect("opening is base64url");
    // HKDF opening length per the rulebook config: 16 bytes.
    assert_eq!(opening.len(), 16);

    // 5. Oracle: the document's ssc element IS the commitment over that
    //    opening (sha-256, base64url-encoded at the element).
    let issuer_signed_bytes = siros_issuer_core::sdjwt_issue::b64u_decode(
        credential["credentials"][0]["credential"].as_str().unwrap(),
    )
    .expect("base64url IssuerSigned");
    let issuer_signed: ciborium::Value =
        ciborium::from_reader(issuer_signed_bytes.as_slice()).expect("IssuerSigned CBOR");
    let doc_map = issuer_signed
        .as_map()
        .expect("IssuerSigned is a map")
        .clone();
    let get = |key: &str| {
        doc_map
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == key))
            .map(|(_, v)| v.clone())
    };
    let ns = get("nameSpaces")
        .and_then(|v| v.into_map().ok().and_then(|m| m.into_iter().next()))
        .expect("one namespace");
    assert!(
        matches!(ns.0, ciborium::Value::Text(t) if t == "eu.europa.ec.eudi.nym_auth.1"),
        "the doctype namespace"
    );
    let items = ns.1.as_array().expect("namespace items").clone();

    let mut ssc_commitment: Option<Vec<u8>> = None;
    let mut salt_lengths: Vec<usize> = Vec::new();
    for item in &items {
        let inner = match item {
            ciborium::Value::Tag(24, inner) => inner.as_ref().clone(),
            _ => panic!("item not tag24"),
        };
        let bytes = match inner {
            ciborium::Value::Bytes(b) => b,
            _ => panic!("tag24 inner not bytes"),
        };
        let entry: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let map = entry.as_map().expect("item map").clone();
        let find = |key: &str| {
            map.iter()
                .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == key))
                .map(|(_, v)| v.clone())
        };
        let identifier = find("elementIdentifier").and_then(|v| v.as_text().map(str::to_owned));
        let random = find("random")
            .and_then(|v| v.as_bytes().map(|b| b.to_vec()))
            .expect("random salt");
        salt_lengths.push(random.len());
        if identifier.as_deref() == Some("ssc") {
            let value = find("elementValue").expect("elementValue");
            let commitment_text = match &value {
                ciborium::Value::Text(s) => s.clone(),
                _ => panic!("ssc commitment is text (base64url-encoded)"),
            };
            ssc_commitment = Some(
                siros_issuer_core::sdjwt_issue::b64u_decode(&commitment_text)
                    .expect("commitment is base64url text"),
            );
        }
    }
    // 4+1 elements: the four subject claims + the ssc commitment.
    assert_eq!(items.len(), 5, "subject claims + ssc, items: {items:?}");
    // vega-mc's catalog constraint: every salt 32 bytes — resolved from
    // the circuit manifest, NOT the default sizing (16).
    assert!(
        salt_lengths.iter().all(|len| *len == 32),
        "catalog-resolved vega salt lengths: {salt_lengths:?}"
    );
    let expected = siros_issuer_core::zk::hash_commitment("sha-256", &opening).unwrap();
    assert_eq!(
        ssc_commitment.expect("the ssc commitment"),
        expected,
        "the document commits sha-256(opening)"
    );
}

/// Signed-metadata content negotiation (OID4VCI 1.0 Final §12.2.2):
/// `Accept: application/jwt` answers the metadata document as a compact
/// ES256 JWS with `typ: openidvci-issuer-metadata+jwt` and the public
/// signing key in the header `jwk` (never `d`), as `application/jwt`;
/// without it, the plain JSON document. Oracles: the JWS verifies under
/// the header key AND that key is the JWKS key AND the payload is the
/// plain JSON document (what a wallet parses after verifying is what the
/// issuer would have said unsigned) — and the plain path still serves
/// JSON.
#[tokio::test]
async fn signed_metadata_content_negotiation_round_trips() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(41),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator, test_signer()).await;
    let client = reqwest::Client::new();

    // The plain document.
    let plain: Value = client
        .get(format!(
            "{}/.well-known/openid-credential-issuer",
            service.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // The JWS document.
    let jws_response = client
        .get(format!(
            "{}/.well-known/openid-credential-issuer",
            service.base
        ))
        .header("Accept", "application/jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(jws_response.status(), reqwest::StatusCode::OK);
    let content_type = jws_response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        content_type.starts_with("application/jwt"),
        "content-type: {content_type}"
    );
    let jws = jjs_text(jws_response).await;

    // Oracle 1: the header carries the type and the public key (no d).
    let header_b64 = jws.split('.').next().unwrap();
    let header: Value =
        serde_json::from_slice(&siros_issuer_core::sdjwt_issue::b64u_decode(header_b64).unwrap())
            .unwrap();
    assert_eq!(header["typ"], "openidvci-issuer-metadata+jwt");
    assert_eq!(header["alg"], "ES256");
    assert!(
        header["jwk"]["d"].is_null(),
        "no private material in the header"
    );

    // Oracle 2: the header key IS the JWKS key (the wallet resolves
    // signature trust through the same published key).
    let jwks: Value = client
        .get(format!("{}/jwks", service.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let header_jwk = header["jwk"].clone();
    assert!(jwks["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .any(|key| key["x"] == header_jwk["x"] && key["y"] == header_jwk["y"]));

    // Oracle 3: the JWS verifies under the header key (jose_rs applies
    // the full JWS binding — the same path the suite's wallet uses).
    let header_jwk_parsed: jose_rs::jwk::Jwk =
        serde_json::from_value(header_jwk).expect("header jwk parses");
    let payload = jose_rs::jws::compact::verify_with_jwk(&header_jwk_parsed, &jws)
        .expect("the metadata JWS verifies under its header key");

    // Oracle 4: the payload is the plain document **merged with the JWT
    // claims** (the suite's VCIDecodeSignedCredentialIssuerMetadata
    // checks `sub` == the configured issuer identifier, then strips
    // iat/exp/iss/sub and runs the standard validation on the rest).
    let payload_value: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(
        payload_value["sub"], plain["credential_issuer"],
        "sub is the issuer identifier (§12.2.3 byte-identity)"
    );
    assert_eq!(payload_value["iss"], plain["credential_issuer"]);
    assert!(payload_value["iat"].is_i64(), "iat present");
    assert!(payload_value["exp"].is_i64(), "exp present");
    let stripped = {
        let mut value = payload_value.clone();
        let object = value.as_object_mut().expect("payload object");
        object.remove("sub");
        object.remove("iss");
        object.remove("iat");
        object.remove("exp");
        value
    };
    assert_eq!(
        stripped, plain,
        "the document (claims stripped) is the plain document"
    );
}

/// Read a text body (named to avoid the `json` shadow above).
async fn jjs_text(response: reqwest::Response) -> String {
    response.text().await.expect("jws text")
}

/// Batch issuance (OID4VCI 1.0 Final §12.2.2): one issuance per proof,
/// over the same session subject — the suite's own batch checks are the
/// oracle here. `VCIEnsureBatchBindingKeysAreDistinct`: distinct keys
/// per entry (a duplicate-proof batch is refused);
/// `VCIEnsureNotMoreCredentialsThanRequestedProofs`: one credential per
/// proof; datasets identical across the batch (same subject);
/// `VCIEnsureBatchSdJwtDisclosureSaltsAreDistinct` /
/// `VCIEnsureBatchStatusListIndicesAreUnpredictable`: salts and status
/// indices distinct per entry.
#[tokio::test]
async fn batch_issuance_one_credential_per_proof_over_the_same_subject() {
    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/x").unwrap(),
        next_index: AtomicU64::new(51),
        updates: Mutex::new(Vec::new()),
    });
    let service = spawn_service(Arc::new(PermitPdp), allocator.clone(), test_signer()).await;
    let integrator = ec_key();
    let client = reqwest::Client::new();

    let (created, _) = create_session(
        &service,
        &integrator,
        json!({"credential": "urn:eudi:pid:1", "subject": {"given_name": "B", "family_name": "Atch"}}),
    )
    .await;
    let body: Value = created.json().await.unwrap();
    let offer_uri = body["offer_uri"].as_str().unwrap().to_owned();
    let offer: Value = client
        .get(format!(
            "{}{}",
            service.base,
            offer_uri.trim_start_matches(ISSUER_BASE)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned();
    let token: Value = client
        .post(format!("{}/token", service.base))
        .form(&token_form(&[
            ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
            ("pre-authorized_code", code),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access_token = token["access_token"].as_str().unwrap().to_owned();
    let c_nonce = token["c_nonce"].as_str().unwrap().to_owned();

    // Two distinct holder keys → two proofs → a batch of two.
    let holder_a = ec_key();
    let mut holder_b = jose_rs::jwk::generate_ec("P-256").unwrap();
    holder_b.alg = Some("ES256".to_owned());
    let base = Url::parse(ISSUER_BASE).unwrap();
    let proof_a = proof_jwt(&holder_a, &base, &c_nonce);
    let proof_b = proof_jwt(&holder_b, &base, &c_nonce);

    // A batch with DUPLICATE keys is refused
    // (VCIEnsureBatchBindingKeysAreDistinct — refuse, never collapse).
    let dup = client
        .post(format!("{}/batch-credential", service.base))
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": "urn:eudi:pid:1",
            "proofs": { "jwt": [proof_a, proof_a] },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), reqwest::StatusCode::BAD_REQUEST);

    // The real batch: two distinct keys.
    let response = client
        .post(format!("{}/batch-credential", service.base))
        .bearer_auth(&access_token)
        .json(&json!({
            "credential_configuration_id": "urn:eudi:pid:1",
            "proofs": { "jwt": [proof_a, proof_b] },
        }))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let batch: Value = response.json().await.unwrap();
    assert!(status.is_success(), "batch: {status} {batch}");
    let entries: &Vec<Value> = batch["credentials"].as_array().expect("credentials[]");
    assert_eq!(entries.len(), 2, "one credential per proof");

    // Oracle: each SD-JWT discloses the SAME dataset (same subject) with
    // DISTINCT disclosure salts, and the two status indices differ
    // (unpredictable allocation).
    let mut salts: Vec<String> = Vec::new();
    let mut indices: Vec<Value> = Vec::new();
    let mut batch_iats: Vec<i64> = Vec::new();
    let mut batch_exps: Vec<i64> = Vec::new();
    let mut disclosed: Vec<Vec<(String, Value)>> = Vec::new();
    for entry in entries {
        assert_eq!(entry["format"], "dc+sd-jwt");
        let sd_jwt = entry["credential"].as_str().unwrap();
        let mut found = Vec::new();
        for part in sd_jwt.split('~').skip(1) {
            if part.is_empty() {
                continue;
            }
            let decoded: Value =
                serde_json::from_slice(&siros_issuer_core::sdjwt_issue::b64u_decode(part).unwrap())
                    .unwrap();
            if decoded.as_array().is_some_and(|array| array.len() == 3) {
                salts.push(part.to_owned());
                found.push((
                    decoded[1].as_str().unwrap_or_default().to_owned(),
                    decoded[2].clone(),
                ));
            }
        }
        // The status claim's idx rides the payload.
        let payload: Value = serde_json::from_slice(
            &siros_issuer_core::sdjwt_issue::b64u_decode(sd_jwt.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        indices.push(payload["status"]["status_list"]["idx"].clone());
        batch_iats.push(payload["iat"].as_i64().expect("iat"));
        batch_exps.push(payload["exp"].as_i64().expect("exp"));
        disclosed.push(found);
    }
    assert_eq!(
        disclosed[0], disclosed[1],
        "identical datasets across the batch"
    );
    let salt_set: std::collections::HashSet<&String> = salts.iter().collect();
    assert_eq!(salt_set.len(), salts.len(), "disclosure salts distinct");
    assert_ne!(indices[0], indices[1], "status indices distinct");

    // Oracle: the batch entries' time claims are 3600-aligned — the
    // suite's VCIEnsureBatchTimeClaimsNotLinkable treats time values
    // shared across a batch as correlatable (PRECISE) unless every value
    // is hour-aligned (its allMatch v % 3600 == 0 acceptance); identical
    // times across a batch are then fine.
    for iat in &batch_iats {
        assert_eq!(
            iat.rem_euclid(3600),
            0,
            "batch iat {iat} is hour-aligned (not the 300 bucket)"
        );
    }
    for exp in &batch_exps {
        assert_eq!(
            exp.rem_euclid(3600),
            0,
            "batch exp {exp} is hour-aligned (iat + 3600 keeps the alignment)"
        );
    }
}

/// The full-issuance HSM proof (design §11.1): the service signs BOTH
/// credential formats with the **PKCS#11 provider** — a real SoftHSM
/// token, not a mock — through the same `signer::Signer` boundary the
/// file key uses; the issuance code cannot tell. Oracles, all under the
/// token's **public** key (`public_jwk()`; the private key never leaves
/// the token): the SD-JWT's SD-JWT verifies in verifier-core
/// (`sdjwt::verify` under `StaticKey`), and the mdoc's issuerAuth
/// COSE_Sign1 Sig_structure verifies under the same key (raw `r || s`).
#[path = "pkcs11_provision.rs"]
mod pkcs11_provision;

#[tokio::test]
async fn hsm_signer_serves_both_credential_formats() {
    use p256::ecdsa::signature::Verifier as _;
    use pkcs11_provision::{provider, provision, public_verifying_key};

    let Some(token) = provision() else {
        eprintln!("skipping: softhsm2-util is not installed (or provisioning failed)");
        return;
    };
    let signer = Arc::new(provider(&token));
    let public = Signer::public_jwk(signer.as_ref()).expect("public jwk");
    // The token key == the imported software key (the oracle base).
    let token_key = public_verifying_key(signer.as_ref());
    assert_eq!(
        token_key.to_encoded_point(false).as_bytes(),
        token.public.to_encoded_point(false).as_bytes()
    );

    let allocator = Arc::new(RecordingAllocator {
        list_url: Url::parse("http://127.0.0.1:9/lists/hsm").unwrap(),
        next_index: AtomicU64::new(99),
        updates: Mutex::new(Vec::new()),
    });

    let svc = spawn_service_dyn(
        Arc::new(PermitPdp),
        allocator,
        signer,
        public.clone(),
        vec![token.cert_der.clone()],
        false,
    )
    .await;
    let client = reqwest::Client::new();
    let integrator = ec_key();
    let base = Url::parse(ISSUER_BASE).unwrap();

    // Both formats over one loop: each an issuance through the service.
    for (configuration_id, expected_format) in [
        ("urn:eudi:pid:1", "dc+sd-jwt"),
        ("eu.europa.ec.eudi.pid.1", "mso_mdoc"),
    ] {
        // Session → offer → token (the integrator asserts; the wallet
        // redeems with a proof).
        let assertion = client_assertion(&integrator, &base);
        let created: Value = client
            .post(format!("{}/api/v1/issuance/sessions", svc.base))
            .header("Authorization", format!("Bearer {assertion}"))
            .json(&json!({
                "credential": configuration_id,
                "subject": if expected_format == "mso_mdoc" {
                    json!({configuration_id: {
                        "given_name": "H", "family_name": "M",
                        "birth_date": "1980-01-01",
                        "place_of_birth": {"country": "SE", "locality": "Stockholm"},
                        "nationality": ["SE"],
                        "issuing_authority": "Skatteverket",
                        "issuing_country": "SE",
                    }})
                } else {
                    json!({"given_name": "H", "family_name": "M"})
                },
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let offer_uri = created["offer_uri"]
            .as_str()
            .expect("offer")
            .replace("http://127.0.0.1:8080", &svc.base);
        let offer: Value = client
            .get(offer_uri)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let code = offer["grants"][GRANT_PRE_AUTHORIZED_CODE]["pre-authorized_code"]
            .as_str()
            .unwrap()
            .to_owned();
        let token_reply: Value = client
            .post(format!("{}/token", svc.base))
            .form(&token_form(&[
                ("grant_type", GRANT_PRE_AUTHORIZED_CODE.to_owned()),
                ("pre_authorized_code", code),
            ]))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let access_token = token_reply["access_token"].as_str().unwrap().to_owned();
        let c_nonce = token_reply["c_nonce"].as_str().unwrap().to_owned();

        // Proof: attestation for mdoc (the suite's proof selection per
        // format), jwt for the SD-JWT — both shapes exercised.
        let credential: Value = if expected_format == "mso_mdoc" {
            let attestation_key: jose_rs::jwk::Jwk = serde_json::from_str(
                r#"{"kty":"EC","x":"ktT77AqMntawPyU772lBg8nd7cwENrYyOL_KWbYN8Jc","y":"67lPXEq5gJdimDYD0AacxLfRfIm2-fSNd3HBqyXXvBI","crv":"P-256","d":"KJEKZo2PQq6E40P6HMenViCVBRXoWD2FDyevRsJnlG0","kid":"attestation-1","alg":"ES256","use":"sig"}"#,
            )
            .unwrap();
            let device_jwk: Value = serde_json::from_str(
                r#"{"kty":"EC","x":"_MUU-7kbV7WJXhrXJuDaAhHKqvDBHq-a4NH1ekAqo8I","y":"7JpnjHEJoyGLdjw_HkNBI9KU7CsswTrDTb7RSmLZ5m0","crv":"P-256","kid":"device-1","alg":"ES256","use":"sig"}"#,
            )
            .unwrap();
            let attestation_cert_der = {
                let key = p256::ecdsa::SigningKey::from_slice(
                    &siros_issuer_core::sdjwt_issue::b64u_decode(
                        attestation_key.d.as_deref().unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap();
                use p256::pkcs8::EncodePrivateKey;
                let pkcs8 = key.to_pkcs8_der().unwrap();
                let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
                    &rustls_pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_bytes()),
                    &rcgen::PKCS_ECDSA_P256_SHA256,
                )
                .unwrap();
                let params =
                    rcgen::CertificateParams::new(vec!["attestation.example.org".to_string()])
                        .unwrap();
                params.self_signed(&kp).unwrap().der().to_vec()
            };
            let now = now_unix();
            let mut header = jose_rs::JoseHeader::new("ES256");
            header.typ = Some("key-attestation+jwt".to_owned());
            header.x5c = Some(vec![base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                attestation_cert_der,
            )]);
            let attestation = jose_rs::jws::compact::sign_with_jwk_options(
                &attestation_key,
                &serde_json::to_vec(&json!({
                    "attested_keys": [device_jwk],
                    "nonce": c_nonce,
                    "iat": now,
                    "exp": now + 300,
                }))
                .unwrap(),
                &header,
                &jose_rs::jws::compact::SignOptions::new().with_key_reference_headers(true),
            )
            .unwrap();
            client
                .post(format!("{}/credential", svc.base))
                .bearer_auth(&access_token)
                .json(&json!({
                    "credential_configuration_id": configuration_id,
                    "proofs": { "attestation": [attestation] },
                }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap()
        } else {
            let holder = ec_key();
            let proof = proof_jwt(&holder, &base, &c_nonce);
            client
                .post(format!("{}/credential", svc.base))
                .bearer_auth(&access_token)
                .json(&json!({
                    "credential_configuration_id": configuration_id,
                    "proofs": { "jwt": [proof] },
                }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap()
        };
        let issued = credential["credentials"][0]["credential"]
            .as_str()
            .expect("the issued credential");
        assert_eq!(credential["credentials"][0]["format"], expected_format);

        // Oracles, under the TOKEN's public key.
        if expected_format == "dc+sd-jwt" {
            let verified = siros_verifier_core::sdjwt::verify(
                issued,
                &siros_verifier_core::sdjwt::StaticKey(public.clone()),
                &siros_verifier_core::sdjwt::VerifyParams::new(
                    now_unix(),
                    siros_verifier_core::sdjwt::HolderBinding::NotRequired,
                ),
            )
            .expect("the HSM-signed SD-JWT verifies in verifier-core");
            assert_eq!(verified.vct, "urn:eudi:pid:1");
        } else {
            // COSE_Sign1: Sig_structure over the MSO, raw `r || s`,
            // verified under the token's public key.
            let issuer_signed_bytes =
                siros_issuer_core::sdjwt_issue::b64u_decode(issued).expect("base64url");
            let issuer_signed: ciborium::Value =
                ciborium::from_reader(issuer_signed_bytes.as_slice()).expect("IssuerSigned CBOR");
            let doc_map = issuer_signed.as_map().expect("map").clone();
            let get = |key: &str| {
                doc_map
                    .iter()
                    .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == key))
                    .map(|(_, v)| v.clone())
            };
            let auth = get("issuerAuth")
                .and_then(|v| v.as_array().cloned())
                .expect("issuerAuth array");
            let protected = auth[0].as_bytes().expect("protected").clone();
            let payload_tagged = auth[2].as_bytes().expect("payload").clone();
            let signature_raw = auth[3].as_bytes().expect("signature").clone();
            let sig_structure = {
                let mut out = Vec::new();
                ciborium::into_writer(
                    &ciborium::Value::Array(vec![
                        ciborium::Value::Text("Signature1".into()),
                        ciborium::Value::Bytes(protected),
                        ciborium::Value::Bytes(Vec::new()),
                        ciborium::Value::Bytes(payload_tagged),
                    ]),
                    &mut out,
                )
                .unwrap();
                out
            };
            let signature = p256::ecdsa::Signature::from_slice(&signature_raw).expect("raw r||s");
            token_key
                .verify(&sig_structure, &signature)
                .expect("the HSM-signed COSE_Sign1 verifies under the token's public key");
        }
    }
}

/// The retention sweeper (design §6.3), all three phases against the real
/// store: (1) a TTL-lapsed session transitions `TtlExpired` through the
/// core state machine (never invented by the backend) and reports its id
/// for the SSE broadcast; (2) a final record still carrying sealed
/// subject data drops it (the notification handler purges immediately —
/// this is the backstop for unnotified finals) while the skeleton
/// survives (status feedback + revocation handle, §9.3); (3) a record
/// final past `retention_after_final_seconds` is hard-deleted, indices
/// and access-token bindings included — while a record inside the
/// window survives untouched.
#[tokio::test]
async fn retention_sweeper_expires_purges_and_hard_deletes() {
    use siros_issuer_core::session::{SessionId, SessionState as St};
    use siros_issuer_service::store::{MemoryStore, SessionRecord};

    let store = Arc::new(MemoryStore::new());
    let now = 1_800_000_000i64;

    let record = |tag: i64, expires: i64| SessionRecord {
        id: SessionId::from_hex(&format!("{tag:032x}")).unwrap(),
        grant: siros_issuer_core::session::GrantKind::PreAuthorized,
        state: St::Offered,
        owner_subject_id: "integrator".to_owned(),
        credential_configuration_id: "urn:eudi:pid:1".to_owned(),
        sealed: Some(vec![1, 2, 3]),
        offer_uuid: Some(format!("offer-{tag}")),
        transaction_id_hash: None,
        pending_holder_jwks: None,
        pre_authorized_code_hash: Some(format!("hash-{tag}")),
        pre_authorized_code_sealed: Some(vec![4, 5, 6]),
        tx_code_hash: None,
        tx_code_spec: None,
        auth: None,
        auth_code_hash: None,
        challenge_jkt: None,
        mode_b: None,
        c_nonce: "n".to_owned(),
        c_nonce_expires_unix: now + 300,
        status_ref: None,
        notification_id: format!("ntf-{tag}"),
        revoked: false,
        created_at_unix: now - 1000,
        expires_at_unix: expires,
        history: Vec::new(),
    };

    // (a) TTL-lapsed, still `offered` — expires this pass.
    let a = record(0xa, now - 10);
    let a_id = a.id.clone();
    let a_offer_uuid = a.offer_uuid.clone().unwrap();
    let _ = a.notification_id.clone();
    store.insert(a).unwrap();

    // (b) `accepted` (final) 10s ago, sealed data still present —
    // REISSUABLE (§13.3): sealed data KEEPS until the hard delete.
    let mut b = record(0xb, now + 3600);
    b.state = St::Accepted;
    b.history.push((now - 10, "accepted".to_owned()));
    let b_id = b.id.clone();
    store.insert(b).unwrap();

    // (e) `failed` (non-reissuable final) 10s ago, sealed — purged this
    // pass; the skeleton survives (inside the window).
    let mut e = record(0xe, now + 3600);
    e.state = St::Failed;
    e.history.push((now - 10, "failed".to_owned()));
    let e_id = e.id.clone();
    store.insert(e).unwrap();

    // (c) `expired` LONG ago (past retention) — hard-deleted, indices
    // included.
    let mut c = record(0xc, now + 3600);
    c.state = St::Expired;
    c.history.push((now - 10 * 86_400, "expired".to_owned()));
    let c_notification = c.notification_id.clone();
    let c_id = c.id.clone();
    store.insert(c).unwrap();

    // (d) Live `offered`, not lapsed — untouched.
    let d = record(0xd, now + 300);
    let d_id = d.id.clone();
    store.insert(d).unwrap();

    let report = store.sweep(now, 86_400).unwrap();
    assert_eq!(report.expired_ids, vec![a_id.as_str().to_owned()]);
    assert_eq!(
        report.purged, 3,
        "a (expired now) + c (past retention) + e (failed, non-reissuable)"
    );
    assert_eq!(report.deleted, 1, "only c is past retention");

    // (a) expired: state machine transition + history + skeleton intact.
    let a = store.get(&a_id).unwrap();
    assert_eq!(a.state, St::Expired);
    assert_eq!(a.history.last().unwrap().1, "expired");
    assert!(a.sealed.is_none(), "sealed data purged on expiry");
    assert!(a.pre_authorized_code_sealed.is_none());
    // The offer index survives the expiry (retention window).
    assert!(store.find_by_offer_uuid(&a_offer_uuid).is_some());

    // (b) accepted: sealed data KEPT (reissuable, §13.3); indices survive.
    let b_record = store.get(&b_id).unwrap();
    assert!(
        b_record.sealed.is_some(),
        "accepted keeps sealed data (§13.3)"
    );
    assert!(store
        .find_by_notification_id(&b_record.notification_id)
        .is_some());

    // (e) failed: purged (non-reissuable); skeleton survives inside the window.
    let e_record = store.get(&e_id).unwrap();
    assert!(e_record.sealed.is_none(), "failed purges");
    assert!(store
        .find_by_notification_id(&e_record.notification_id)
        .is_some());

    // (c) hard-deleted: record AND indices gone.
    assert!(store.get(&c_id).is_none());
    assert!(store.find_by_notification_id(&c_notification).is_none());

    // (d) untouched.
    let d = store.get(&d_id).unwrap();
    assert_eq!(d.state, St::Offered);
    assert!(d.sealed.is_some());

    // A second pass, with the retention window closed (0): everything
    // final hard-deletes.
    let report = store.sweep(now + 10 * 86_400, 86_400).unwrap();
    assert_eq!(
        report.deleted, 3,
        "a + b + e hard-deleted past retention (c went in pass 1)"
    );
    // d stays until ITS ttl lapses.
    assert!(store.get(&d_id).is_some());
}
