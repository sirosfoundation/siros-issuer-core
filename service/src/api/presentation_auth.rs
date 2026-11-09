//! Mode B (design §7.3): authorization via OpenID4VP presentation.
//!
//! The wallet authenticates the subject by presenting an existing
//! credential. Request construction and cryptographic verification are
//! embedded verifier-core library calls (`create_request` /
//! `process_response`) — no OpenID4VP code is re-implemented here. Trust
//! in the *presented* credential is a go-trust AuthZEN decision
//! (`TrustPdp::permit_presentation`), never a local assumption (design
//! §11). The DCQL query is derived from the session's credential
//! configuration — the same catalog metadata that drives issuance drives
//! the request.
//!
//! Flow: PAR creates the session (`awaiting_authorization`); the wallet
//! POSTs `/authorization-challenge` (DPoP-bound) and receives the signed
//! request object whose `response_uri` carries an opaque challenge
//! handle; the wallet presents to `/authorization-challenge/response/…`
//! (`direct_post.jwt`); a verified, trusted presentation's claims become
//! the session's subject data and the authorization code is minted —
//! converging with Mode A at §7.2 steps 4–5 (the code is exchanged at
//! `/token`, where the DPoP key that bound the challenge must re-appear).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use siros_issuer_core::error::code;
use siros_issuer_core::{Error, Result};
use siros_verifier_core::oid4vp::{self, RequestConfig};
use siros_verifier_core::sdjwt::X5cLeaf;

use crate::api::AppState;
use crate::status::now_unix;
use crate::store::ModeBState;
use siros_issuer_core::session::{SessionEvent, SessionState};

type HandlerResult<T> = std::result::Result<T, Response>;

fn err(error: Error) -> Response {
    let status = match error.code {
        code::INVALID_INPUT => StatusCode::BAD_REQUEST,
        code::ILLEGAL_TRANSITION => StatusCode::CONFLICT,
        code::CONFIGURATION => StatusCode::SERVICE_UNAVAILABLE,
        code::PDP_DENIED | code::PDP_UNAVAILABLE => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(json!({"error": error.code, "message": error.message})),
    )
        .into_response()
}

/// Adapt the service's signer (HSM-capable, design §11.1) to kryptering's
/// `Signer` for OpenID4VP request signing: the same ES256 signature
/// path, whatever backs it.
struct KrypteringSignerAdapter {
    inner: std::sync::Arc<dyn siros_issuer_core::signer::Signer>,
}

impl kryptering::Signer for KrypteringSignerAdapter {
    fn algorithm(&self) -> kryptering::SignatureAlgorithm {
        jose_rs::JwsAlgorithm::from_str("ES256")
            .expect("ES256 is a known JWS algorithm")
            .to_crypto()
            .expect("ES256 maps to a crypto algorithm")
    }

    fn sign(&self, data: &[u8]) -> kryptering::error::Result<Vec<u8>> {
        self.inner
            .sign_es256_raw(data)
            .map_err(|e| kryptering::error::Error::Crypto(format!("signing: {e}")))
    }
}

/// Derive the DCQL query from the credential configuration (design §7.3
/// step 1): the catalog's claims become the requested claims, the format
/// and identifier the credential filter. `dc+sd-jwt` filters by
/// `vct_values`, `mso_mdoc` by `doctype_values` (DCQL §5.2).
pub fn derive_dcql(credential: &siros_verifier_core::ts11::CredentialType) -> Result<Value> {
    let claims: Vec<Value> = credential
        .claims
        .iter()
        .map(|claim| json!({ "path": claim.path.iter().map(|seg| json!(seg)).collect::<Vec<_>>() }))
        .collect();
    match credential.format.as_str() {
        "dc+sd-jwt" => Ok(json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [credential.identifier] },
                "claims": claims,
            }]
        })),
        "mso_mdoc" => Ok(json!({
            "credentials": [{
                "id": "pid",
                "format": "mso_mdoc",
                "meta": { "doctype_values": [credential.identifier] },
                "claims": claims,
            }]
        })),
        other => Err(Error::new(
            code::UNSUPPORTED_CREDENTIAL,
            format!("credential format {other} cannot be requested by presentation"),
        )),
    }
}

/// `POST /authorization-challenge` (design §7.3 step 2): DPoP-bound;
/// returns the signed OpenID4VP authorization request object for the
/// session named by `issuer_state`.
#[allow(clippy::result_large_err)]
pub async fn authorization_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> HandlerResult<(StatusCode, Json<Value>)> {
    let issuer_state =
        read_issuer_state(&headers, &body).map_err(|e| err(Error::invalid_input(e)))?;

    let now = now_unix();
    let session_id = siros_issuer_core::session::SessionId::from_hex(&issuer_state)
        .map_err(|_| err(Error::invalid_input("issuer_state is not a session id")))?;
    let record = state
        .sessions
        .get(&session_id)
        .await
        .ok_or_else(|| err(Error::invalid_input("no such authorization request")))?;
    if record.state != SessionState::AwaitingAuthorization {
        return Err(err(Error::illegal_transition(
            "the session is not awaiting authorization",
        )));
    }

    // DPoP binds the challenge (design §7.3; RFC 9449): the proof key is
    // remembered and must re-appear at /token with the code.
    let dpop_proof = headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(Error::invalid_input("a DPoP proof is required (RFC 9449)")))?;
    let htu = state
        .issuer_base
        .join("authorization-challenge")
        .map_err(|e| err(Error::configuration(e.to_string())))?;
    let verified = state
        .dpop
        .validate(dpop_proof, "POST", &htu, now, None)
        .map_err(err)?;

    // The DCQL query: the session's credential configuration — or, for a
    // §6.5 pre-auth binding session, the **presented** credential the
    // deployment configured (the PID), not the one being issued.
    let catalog = state.catalog_snapshot();
    let presentation_configuration_id = match record.grant {
        siros_issuer_core::session::GrantKind::PreAuthorized
            if record.identity_match_sealed.is_some() =>
        {
            state
                .pre_auth_binding
                .as_ref()
                .map(|binding| binding.presentation_credential.clone())
                .ok_or_else(|| {
                    err(Error::configuration(
                        "the session is pre-auth-bound but [authorization.pre_auth_binding] is unset",
                    ))
                })?
        }
        _ => record.credential_configuration_id.clone(),
    };
    let credential = siros_issuer_core::catalog::resolve(&catalog, &presentation_configuration_id)
        .map_err(err)?;
    let dcql_query = derive_dcql(credential).map_err(err)?;

    // The challenge handle rides the response_uri path — the wallet POSTs
    // the presentation back to exactly this URI.
    let challenge_handle = crate::api::random_handle("ch_", 24);
    let response_uri = state
        .issuer_base
        .join(&format!(
            "authorization-challenge/response/{challenge_handle}"
        ))
        .map_err(|e| err(Error::configuration(e.to_string())))?;

    // Signed request object via the embedded verifier-core call; the
    // ephemeral response-encryption key lives inside its Session.
    let signer = KrypteringSignerAdapter {
        inner: state.signer.clone(),
    };
    let (jar, oid4vp_session) = oid4vp::create_request(
        &RequestConfig {
            response_uri: response_uri.as_str().to_owned(),
            dcql_query,
            ttl_secs: 300,
            vp_formats_supported: None,
            client_id: None,
        },
        &signer,
        "ES256",
        &state.cert_chain_der,
        now,
    )
    .map_err(|e| err(Error::new(code::INVALID_INPUT, format!("request: {e}"))))?;

    // Seal the OID4VP session (it carries the ephemeral private key —
    // sealed at rest, design §6.3) and arm the exchange.
    let sealed = state
        .vault
        .seal(
            record.id.as_str(),
            &serde_json::to_value(&oid4vp_session).expect("oid4vp session serializes"),
        )
        .map_err(err)?;
    state
        .sessions
        .set_mode_b(
            &record.id,
            ModeBState {
                challenge_handle,
                sealed_session: sealed,
            },
            Some(verified.jkt),
        )
        .await
        .map_err(err)?;

    Ok((
        StatusCode::OK,
        Json(json!({ "authorization_request": jar })),
    ))
}

/// `POST /authorization-challenge/response/{challenge_handle}`: the
/// request object's `response_uri`. The wallet POSTs the `direct_post.jwt`
/// JWE as the `response` form value. Verification, the trust decision,
/// subject adoption and the code minting — the wallet then exchanges the
/// code at `/token`.
#[allow(clippy::result_large_err)]
pub async fn authorization_challenge_response(
    State(state): State<AppState>,
    Path(challenge_handle): Path<String>,
    body: String,
) -> HandlerResult<(StatusCode, Json<Value>)> {
    let jwe = parse_form_value(&body, "response")
        .ok_or_else(|| err(Error::invalid_input("response is required")))?;

    let now = now_unix();
    let (record, sealed_session) = state
        .sessions
        .take_mode_b(&challenge_handle)
        .await
        .ok_or_else(|| {
            err(Error::invalid_input(
                "no pending authorization challenge for this handle",
            ))
        })?;
    // Unseal the verifier-core OID4VP session (ephemeral key inside).
    let sealed_value = state
        .vault
        .unseal(record.id.as_str(), &sealed_session)
        .map_err(err)?;
    let oid4vp_session: siros_verifier_core::oid4vp::Session = serde_json::from_value(sealed_value)
        .map_err(|e| err(Error::configuration(format!("sealed session: {e}"))))?;

    // Cryptographic verification in-process (design §7.3 step 3): a
    // failure fails the session (stable ErrorOccurred semantics).
    let results = match oid4vp::process_response(&oid4vp_session, &jwe, now, &X5cLeaf) {
        Ok(results) => results,
        Err(e) => {
            let _ = state.step(&record.id, SessionEvent::ErrorOccurred).await;
            return Err(err(Error::new(
                code::INVALID_INPUT,
                format!("presentation: {e}"),
            )));
        }
    };

    // Trust in the presented credential: go-trust decides (design §11).
    for result in &results {
        let query = result.verified.trust_query("issuer", "issuer");
        if let Err(e) = state.pdp.permit_presentation(&query).await {
            let _ = state.step(&record.id, SessionEvent::ErrorOccurred).await;
            return Err(err(e));
        }
    }

    // The verified claims become the session's subject data (§7.3 step 4).
    // v1: exactly one presented credential — multiple results are refused
    // rather than silently merged.
    let [result] = results.as_slice() else {
        let _ = state.step(&record.id, SessionEvent::ErrorOccurred).await;
        return Err(err(Error::invalid_input(
            "exactly one presented credential is supported",
        )));
    };
    let claims = match result.verified.claims() {
        Ok(claims) => claims,
        Err(e) => {
            let _ = state.step(&record.id, SessionEvent::ErrorOccurred).await;
            return Err(err(Error::new(
                code::INVALID_INPUT,
                format!("presented claims: {e}"),
            )));
        }
    };

    // §6.5 v2 — the pre-auth binding branch: the presentation IS the
    // authorization. The session's subject data is the integrator's
    // (push model, sealed at creation — the presentation does not
    // replace it); what the presentation proves is that the wallet
    // holder satisfies the integrator's identity_match rule. On match:
    // the Authorized transition unlocks the pre-authorized code claim
    // (claim requires `offered`). On mismatch: the session fails —
    // stable refusal, never a silent pass.
    if record.grant == siros_issuer_core::session::GrantKind::PreAuthorized {
        let sealed_rule = record.identity_match_sealed.clone().ok_or_else(|| {
            err(Error::illegal_transition(
                "the pre-authorized session carries no identity_match rule",
            ))
        })?;
        let rule_value = state
            .vault
            .unseal(record.id.as_str(), &sealed_rule)
            .map_err(err)?;
        let rule: siros_issuer_core::oid4vci::IdentityMatch = serde_json::from_value(rule_value)
            .map_err(|e| err(Error::configuration(format!("sealed identity_match: {e}"))))?;
        // The presented claims in the credential's own shape: an mdoc
        // presentation's claims nest under the namespace (literal-key
        // lookup first — vc's format-aware path resolution); SD-JWT VC
        // walks nested objects only.
        let presentation_configuration_id = state
            .pre_auth_binding
            .as_ref()
            .map(|binding| binding.presentation_credential.clone())
            .ok_or_else(|| {
                err(Error::configuration(
                    "[authorization.pre_auth_binding] is unset for a bound session",
                ))
            })?;
        let catalog = state.catalog_snapshot();
        let presented_format =
            siros_issuer_core::catalog::resolve(&catalog, &presentation_configuration_id)
                .map_err(err)?
                .format
                .clone();
        let claims_value = serde_json::Value::Object(claims.clone());
        let matched = rule
            .matches(&claims_value, presented_format == "mso_mdoc")
            .map_err(err)?;
        if !matched {
            let _ = state.step(&record.id, SessionEvent::ErrorOccurred).await;
            return Err(err(Error::new(
                code::INVALID_INPUT,
                format!(
                    "identity match failed: the presented credential does not satisfy the rule ({})",
                    rule.claim_paths().join(", ")
                ),
            )));
        }
        if let Err(e) = state.step(&record.id, SessionEvent::Authorized).await {
            let _ = state.step(&record.id, SessionEvent::ErrorOccurred).await;
            return Err(err(e));
        }
        return Ok((StatusCode::OK, Json(json!({ "bound": true }))));
    }

    // Converge with Mode A (§7.2 steps 4–5): seal the subject, mint the
    // code, transition Authorized — the wallet exchanges at /token.
    let sealed = state
        .vault
        .seal(record.id.as_str(), &Value::Object(claims))
        .map_err(err)?;
    let auth_code = crate::api::random_handle("ac_", 24);
    let auth_code_hash = crate::api::backend::hex_sha(&auth_code);
    let binding = record
        .auth
        .clone()
        .ok_or_else(|| err(Error::illegal_transition("the session has no PAR binding")))?;
    state
        .sessions
        .complete_authorization(
            record.offer_uuid.as_deref().unwrap_or_default(),
            sealed,
            binding,
            auth_code_hash,
            now,
        )
        .await
        .map_err(err)?;

    Ok((
        StatusCode::OK,
        Json(json!({ "authorization_code": auth_code })),
    ))
}

/// Read `issuer_state` from a JSON or form-encoded body.
fn read_issuer_state(headers: &HeaderMap, body: &str) -> std::result::Result<String, String> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if content_type.starts_with("application/json") {
        let value: Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
        value
            .get("issuer_state")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "issuer_state is required".to_owned())
    } else {
        parse_form_value(body, "issuer_state").ok_or_else(|| "issuer_state is required".to_owned())
    }
}

/// One value out of an application/x-www-form-urlencoded body.
fn parse_form_value(body: &str, name: &str) -> Option<String> {
    for (key, value) in form_urlencoded::parse(body.as_bytes()) {
        if key == name {
            return Some(value.into_owned());
        }
    }
    None
}
