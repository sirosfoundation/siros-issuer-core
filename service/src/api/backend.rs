//! Backend session API (design §6). The integrating application's surface:
//! create a session with pushed subject data, observe status, revoke,
//! abandon. Auth is a Bearer client-assertion JWT; trust is the PDP's;
//! subject data is sealed in the vault, never logged, never on any GET
//! surface.

use super::{history_json, random_handle, session_id_from_str, AppState};
use crate::auth::{verify_bearer_assertion, IntegratorIdentity};
use crate::status::now_unix;
use crate::store::StateLabel as _;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::Json;
use futures_util::Stream;
use serde_json::{json, Value};
use siros_issuer_core::session::SessionId;
use siros_issuer_core::status_client::Status;
use siros_issuer_core::{Error, Result};

/// Handler result: success or a uniform API error value.
type HandlerResult<T> = std::result::Result<T, (axum::http::StatusCode, Json<Value>)>;

/// A uniform API error shape with the stable refusal code.
pub fn api_error(error: Error) -> (StatusCode, Json<Value>) {
    let status = match error.code {
        "invalid_input" => StatusCode::BAD_REQUEST,
        "unsupported_credential" => StatusCode::NOT_FOUND,
        "illegal_transition" => StatusCode::CONFLICT,
        "pdp_denied" => StatusCode::FORBIDDEN,
        "pdp_unavailable" | "configuration" => StatusCode::SERVICE_UNAVAILABLE,
        "transport" => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(json!({"error": error.code, "message": error.message})),
    )
}

fn bearer(headers: &HeaderMap, state: &AppState) -> Result<IntegratorIdentity> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| Error::invalid_input("missing Bearer client assertion"))?;
    verify_bearer_assertion(token, &state.issuer_base, now_unix(), 60)
}

/// Unknown and foreign sessions are indistinguishable: both refuse.
async fn owned_record(
    state: &AppState,
    id: &str,
    identity: &IntegratorIdentity,
) -> Result<crate::store::SessionRecord> {
    let id = session_id_from_str(id).map_err(|_| Error::invalid_input("no such session"))?;
    let record = state
        .sessions
        .get(&id)
        .await
        .ok_or_else(|| Error::invalid_input("no such session"))?;
    if record.owner_subject_id != identity.subject_id {
        return Err(Error::invalid_input("no such session"));
    }
    Ok(record)
}

fn rand16() -> [u8; 16] {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS randomness");
    buf
}

pub(crate) fn hex_sha(value: &str) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(value.as_bytes()))
}

/// Lowercase hex of a digest (sha2 0.11's array type has no LowerHex).
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Six random digits: a numeric tx_code (OID4VCI ID1 tx_code).
fn tx_code() -> String {
    let mut buf = [0u8; 6];
    getrandom::fill(&mut buf).expect("OS randomness");
    buf.iter().map(|b| (b % 10).to_string()).collect()
}

/// `POST /api/v1/issuance/sessions` (design §6.2): create a session with
/// pushed subject data, behind a PDP permit, with a pre-authorized offer.
pub async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> HandlerResult<(StatusCode, Json<Value>)> {
    let identity = bearer(&headers, &state).map_err(api_error)?;
    let credential_id = body
        .get("credential")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid_input("credential is required"))
        .map_err(api_error)?;

    // Pull-model resolvers arrive with the wallet-initiated work (P2).
    if body.get("data_source").is_some() {
        return Err(api_error(Error::configuration(
            "pull-model data_source lands with P2 (design §6.4)",
        )));
    }

    let catalog = state.catalog_snapshot();
    let credential =
        siros_issuer_core::catalog::resolve(&catalog, credential_id).map_err(api_error)?;
    // The issuable formats (design §8.2): dc+sd-jwt and mso_mdoc. Any
    // other catalog format is refused rather than half-issued.
    if !matches!(credential.format.as_str(), "dc+sd-jwt" | "mso_mdoc") {
        return Err(api_error(Error::new(
            siros_issuer_core::error::code::UNSUPPORTED_CREDENTIAL,
            format!("credential format {} is not issuable", credential.format),
        )));
    }

    // Trust: may this integrator issue this credential type?
    let query = siros_issuer_core::trust::IssuanceTrustQuery::new(
        identity.subject_id.clone(),
        Vec::new(),
        identity.jwk.clone(),
        credential.identifier.clone(),
        body.get("authentic_source")
            .and_then(Value::as_str)
            .map(str::to_owned),
    );
    state.pdp.permit(&query).await.map_err(api_error)?;

    // Schema gate: every mandatory catalog claim must be present (§6.2 —
    // before the offer is minted, never after the wallet redeems).
    let subject = body.get("subject").cloned().unwrap_or_else(|| json!({}));
    for claim in &credential.claims {
        if !claim.mandatory {
            continue;
        }
        let mut cursor = &subject;
        for seg in &claim.path {
            cursor = match seg {
                Some(key) => cursor.get(key.as_str()).unwrap_or(&Value::Null),
                None => &Value::Null,
            };
        }
        if cursor.is_null() {
            return Err(api_error(Error::invalid_input(format!(
                "mandatory claim {:?} missing",
                claim.path
            ))));
        }
    }

    // Mint the pre-authorized offer (single-use, hashed at rest).
    let now = now_unix();
    let ttl = body
        .get("ttl_seconds")
        .and_then(Value::as_i64)
        .unwrap_or(300)
        .clamp(1, 3600);
    let pre_authorized_code = random_handle("pac_", 24);
    // The tx_code value: supplied by the caller when the deployment needs a
    // FIXED code (conformance fixtures pin vci.static_tx_code — the suite
    // redeems its own constant, so a random mint can never match), random
    // otherwise.
    let tx_code_value = match body.pointer("/grant/tx_code/value") {
        Some(Value::String(fixed)) => {
            let value = fixed.clone();
            if value.is_empty() || value.len() > 16 {
                return Err(api_error(Error::invalid_input(
                    "grant.tx_code.value must be 1-16 characters",
                )));
            }
            Some(value)
        }
        _ => body.pointer("/grant/tx_code").map(|_| tx_code()),
    };
    let tx_code_hash = tx_code_value.as_deref().map(hex_sha);
    let tx_code_spec =
        body.pointer("/grant/tx_code")
            .map(|spec| siros_issuer_core::oid4vci::TxCode {
                input_mode: spec
                    .get("input_mode")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                length: spec
                    .get("length")
                    .and_then(Value::as_u64)
                    .map(|l| l as usize),
                description: spec
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            });
    let offer_uuid = random_handle("of_", 16);
    let notification_id = random_handle("ntf_", 16);
    let session_id = SessionId::from_random(rand16());
    let c_nonce = random_handle("n_", 16);

    // §6.5 v2 — the pre-auth grant's strong binding: when the deployment
    // arms it, the integrator MUST supply an identity_match rule (vc
    // `PrepareIssuance`: required, not omittable — an unbound issuance
    // is the plain pre-authorized grant, asked for by name), and the
    // session starts `awaiting_authorization`: the wallet presents the
    // configured credential, the rule matches, and only then does
    // `Authorized` → `offered` unlock the code claim — the one state
    // machine enforcing presentation-before-redemption, no new states.
    // The rule is **subject data** (it names the person the integrator
    // authenticated): sealed in the vault, unsealed only at the check.
    let (binding_state, identity_match_sealed) = match &state.pre_auth_binding {
        Some(_binding) => {
            let rule_value = body.get("identity_match").cloned().ok_or_else(|| {
                api_error(Error::invalid_input(
                    "identity_match is required: this deployment binds pre-authorized issuance to a presented credential (design §6.5)",
                ))
            })?;
            let rule: siros_issuer_core::oid4vci::IdentityMatch =
                serde_json::from_value(rule_value)
                    .map_err(|e| api_error(Error::invalid_input(format!("identity_match: {e}"))))?;
            rule.validate().map_err(api_error)?;
            let sealed = state
                .vault
                .seal(
                    session_id.as_str(),
                    &serde_json::to_value(&rule).expect("rule serializes"),
                )
                .map_err(api_error)?;
            (
                siros_issuer_core::session::SessionState::AwaitingAuthorization,
                Some(sealed),
            )
        }
        None => (siros_issuer_core::session::SessionState::Offered, None),
    };

    let sealed = state
        .vault
        .seal(session_id.as_str(), &subject)
        .map_err(api_error)?;
    let sealed_code = state
        .vault
        .seal(session_id.as_str(), &json!(pre_authorized_code))
        .map_err(api_error)?;
    let record = crate::store::SessionRecord {
        id: session_id.clone(),
        grant: siros_issuer_core::session::GrantKind::PreAuthorized,
        state: binding_state,
        owner_subject_id: identity.subject_id.clone(),
        credential_configuration_id: credential.identifier.clone(),
        sealed: Some(sealed),
        offer_uuid: Some(offer_uuid),
        transaction_id_hash: None,
        pending_holder_jwks: None,
        identity_match_sealed,
        pre_authorized_code_hash: Some(hex_sha(&pre_authorized_code)),
        pre_authorized_code_sealed: Some(sealed_code),
        tx_code_hash,
        tx_code_spec,
        auth: None,
        auth_code_hash: None,
        challenge_jkt: None,
        mode_b: None,
        c_nonce,
        c_nonce_expires_unix: now + state.c_nonce_ttl_seconds,
        status_ref: None,
        notification_id: notification_id.clone(),
        revoked: false,
        created_at_unix: now,
        expires_at_unix: now + ttl,
        history: vec![(now, binding_state.label().to_owned())],
    };
    state.sessions.insert(record).await.map_err(api_error)?;

    let record = state
        .sessions
        .get(&session_id)
        .await
        .ok_or_else(|| Error::illegal_transition("session vanished"))
        .map_err(api_error)?;
    let offer_uri = state
        .issuer_base
        .join(&format!(
            "credential-offer/{}",
            record.offer_uuid.clone().unwrap_or_default()
        ))
        .map_err(|e| api_error(Error::configuration(e.to_string())))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "session_id": session_id.as_str(),
            // The session's state: `awaiting_authorization` when the
            // pre-auth binding is armed (§6.5) — the wallet must present
            // before the code redeems.
            "state": record.state.label(),
            "credential": credential.identifier,
            "offer_uri": offer_uri.as_str(),
            "wallet_redirect": siros_issuer_core::oid4vci::CredentialOffer::deep_link(&offer_uri).as_str(),
            "expires_at_unix": now + ttl,
            "status": format!("/api/v1/issuance/sessions/{}/events", session_id.as_str()),
            "notification_id": notification_id,
            "tx_code": tx_code_value,
        })),
    ))
}

/// `POST /api/v1/issuance/sessions/{issuer_state}/authorize` (design §7.2
/// step 3): the integrator, having authenticated the user, completes a
/// wallet-initiated session — subject data in, single-use authorization
/// code out. The wallet never calls this.
#[allow(clippy::result_large_err)]
pub async fn complete_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(issuer_state): Path<String>,
    Json(body): Json<Value>,
) -> HandlerResult<(StatusCode, Json<Value>)> {
    let identity = bearer(&headers, &state).map_err(api_error)?;
    let record = {
        let id = session_id_from_str(&issuer_state)
            .map_err(|_| api_error(Error::invalid_input("no such session")))?;
        state
            .sessions
            .get(&id)
            .await
            .ok_or_else(|| api_error(Error::invalid_input("no such session")))?
    };
    if record.state != siros_issuer_core::session::SessionState::AwaitingAuthorization {
        return Err(api_error(Error::illegal_transition(
            "authorization request is not awaiting completion",
        )));
    }
    let binding = record
        .auth
        .clone()
        .ok_or_else(|| api_error(Error::illegal_transition("no authorization binding")))?;

    // Same trust + schema gates as session creation (§6.2).
    let credential_id = body
        .get("credential")
        .and_then(Value::as_str)
        .unwrap_or(record.credential_configuration_id.as_str())
        .to_owned();
    let catalog = state.catalog_snapshot();
    let credential =
        siros_issuer_core::catalog::resolve(&catalog, &credential_id).map_err(api_error)?;
    if credential.identifier != record.credential_configuration_id {
        return Err(api_error(Error::invalid_input(
            "credential does not match the authorization request",
        )));
    }
    let query = siros_issuer_core::trust::IssuanceTrustQuery::new(
        identity.subject_id.clone(),
        Vec::new(),
        identity.jwk.clone(),
        credential.identifier.clone(),
        body.get("authentic_source")
            .and_then(Value::as_str)
            .map(str::to_owned),
    );
    state.pdp.permit(&query).await.map_err(api_error)?;

    let subject = body.get("subject").cloned().unwrap_or_else(|| json!({}));
    for claim in &credential.claims {
        if !claim.mandatory {
            continue;
        }
        let mut cursor = &subject;
        for seg in &claim.path {
            cursor = match seg {
                Some(key) => cursor.get(key.as_str()).unwrap_or(&Value::Null),
                None => &Value::Null,
            };
        }
        if cursor.is_null() {
            return Err(api_error(Error::invalid_input(format!(
                "mandatory claim {:?} missing",
                claim.path
            ))));
        }
    }

    let now = now_unix();
    let sealed = state
        .vault
        .seal(record.id.as_str(), &subject)
        .map_err(api_error)?;
    let auth_code = super::random_handle("ac_", 24);
    let auth_code_hash = hex_sha(&auth_code);
    let redirect_uri = binding.redirect_uri.clone();
    let state_param = binding.state.clone();
    state
        .sessions
        .complete_authorization(
            &record.offer_uuid.clone().unwrap_or_default(),
            sealed,
            binding,
            auth_code_hash,
            now,
        )
        .await
        .map_err(api_error)?;
    // The integrator becomes the owner once it completes the flow.
    state
        .sessions
        .set_owner(&record.id, identity.subject_id.clone())
        .await
        .map_err(api_error)?;

    // The wallet redirect: iss + code + state back to the PAR
    // redirect_uri (design §7.2 step 4). `iss` per RFC 9207 — the
    // authorization-response issuer parameter (the suite's
    // RequireIssInAuthorizationResponse enforces it).
    let mut location = url::Url::parse(&redirect_uri)
        .map_err(|e| api_error(Error::configuration(format!("redirect_uri: {e}"))))?;
    {
        let mut pairs = location.query_pairs_mut();
        pairs.append_pair(
            "iss",
            &siros_issuer_core::oid4vci::issuer_identifier(&state.issuer_base),
        );
        pairs.append_pair("code", &auth_code);
        if let Some(state_param) = &state_param {
            pairs.append_pair("state", state_param);
        }
    }
    let _ = state.events_tx.send(super::SessionEventMessage {
        session_id: record.id.as_str().to_owned(),
        state: "offered",
        unix: now,
    });
    Ok((
        StatusCode::OK,
        Json(json!({
            "session_id": record.id.as_str(),
            "state": "offered",
            "redirect": location.as_str(),
        })),
    ))
}

/// `GET /api/v1/issuance/sessions/{id}`: status and offer handle (owner
/// only). Sealed subject data never appears.
pub async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> HandlerResult<Json<Value>> {
    let identity = bearer(&headers, &state).map_err(api_error)?;
    let record = owned_record(&state, &id, &identity)
        .await
        .map_err(api_error)?;
    let offer_uri = state
        .issuer_base
        .join(&format!(
            "credential-offer/{}",
            record.offer_uuid.clone().unwrap_or_default()
        ))
        .map_err(|e| api_error(Error::configuration(e.to_string())))?;
    let mut body = history_json(&record);
    let object = body
        .as_object_mut()
        .ok_or_else(|| api_error(Error::illegal_transition("history is not an object")))?;
    object.insert("offer_uri".to_owned(), json!(offer_uri.as_str()));
    object.insert(
        "wallet_redirect".to_owned(),
        json!(siros_issuer_core::oid4vci::CredentialOffer::deep_link(&offer_uri).as_str()),
    );
    object.insert("revoked".to_owned(), json!(record.revoked));
    object.insert("notification_id".to_owned(), json!(record.notification_id));
    Ok(Json(body))
}

/// `GET /api/v1/issuance/sessions/{id}/events`: SSE of state transitions
/// (decision D2). Poll via the plain GET above; this streams.
pub async fn session_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> HandlerResult<Sse<impl Stream<Item = std::result::Result<Event, axum::Error>>>> {
    let identity = bearer(&headers, &state).map_err(api_error)?;
    let record = owned_record(&state, &id, &identity)
        .await
        .map_err(api_error)?;

    // Current state first, then live transitions.
    let initial =
        Event::default().data(serde_json::to_string(&history_json(&record)).unwrap_or_default());
    let mut rx = state.events_tx.subscribe();
    let session_id = record.id.as_str().to_owned();
    let stream = async_stream::stream! {
        yield Ok(initial);
        loop {
            match rx.recv().await {
                Ok(message) if message.session_id == session_id => {
                    let data = serde_json::json!({
                        "session_id": message.session_id,
                        "state": message.state,
                        "unix": message.unix,
                    });
                    yield Ok(Event::default().data(data.to_string()));
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// `POST /api/v1/issuance/sessions/{id}/revoke` (design §9.3): flip the
/// allocated status bit via siros-status-service. Revocation is by session
/// id only; there is no subject index (decision D5).
pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> HandlerResult<StatusCode> {
    let identity = bearer(&headers, &state).map_err(api_error)?;
    let record = owned_record(&state, &id, &identity)
        .await
        .map_err(api_error)?;

    // May this integrator revoke? A separate decision on the same PDP.
    let query = siros_issuer_core::trust::IssuanceTrustQuery::new(
        identity.subject_id.clone(),
        Vec::new(),
        identity.jwk.clone(),
        record.credential_configuration_id.clone(),
        None,
    );
    state.pdp.permit(&query).await.map_err(api_error)?;

    let status_ref = record
        .status_ref
        .ok_or_else(|| Error::illegal_transition("session has no allocated status index yet"))
        .map_err(api_error)?;
    state
        .allocator
        .update(&status_ref.list_url, status_ref.index, Status::Invalid)
        .await
        .map_err(api_error)?;
    let session_id = session_id_from_str(&id).map_err(api_error)?;
    state
        .sessions
        .set_revoked(&session_id)
        .await
        .map_err(api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/v1/issuance/sessions/{id}`: abandon; purge the sealed
/// subject data immediately (design §6.1). The record skeleton survives
/// for status feedback and the revocation handle.
pub async fn delete_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> HandlerResult<StatusCode> {
    let identity = bearer(&headers, &state).map_err(api_error)?;
    let record = owned_record(&state, &id, &identity)
        .await
        .map_err(api_error)?;
    state
        .sessions
        .purge_subject_data(&record.id)
        .await
        .map_err(api_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/issuance/sessions/{id}/preview`: the catalog claim
/// **names** for this credential (design §6.1, decision D6) — never
/// values; the app renders values from its own data.
pub async fn preview_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> HandlerResult<Json<Value>> {
    let identity = bearer(&headers, &state).map_err(api_error)?;
    let record = owned_record(&state, &id, &identity)
        .await
        .map_err(api_error)?;
    let catalog = state.catalog_snapshot();
    let credential =
        siros_issuer_core::catalog::resolve(&catalog, &record.credential_configuration_id)
            .map_err(api_error)?;
    Ok(Json(json!({
        "credential": credential.identifier,
        "claims": credential.claims.iter().map(|claim| json!({
            "path": claim.path,
            "mandatory": claim.mandatory,
        })).collect::<Vec<_>>(),
    })))
}
