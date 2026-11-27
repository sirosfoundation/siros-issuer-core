//! Wallet-facing endpoints (design §7): OID4VCI metadata (generated from
//! the catalog), the pre-authorized grant end to end (offer → token →
//! credential), notifications into the session state machine, and
//! readiness.

use super::{random_handle, AppState};
use crate::api::backend::hex;
use crate::auth::{verify_attestation_proof_all, verify_jwt_proof};
use crate::status::now_unix;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::response::Response;
use axum::Json;
use serde_json::{json, Value};
use siros_issuer_core::oid4vci::{
    CredentialEntry, CredentialMetadata, CredentialOffer, CredentialRequest, CredentialResponse,
    CredentialResponseEncryption, DeferredCredentialRequest, GrantPreAuthorizedCode,
    NotificationRequest, TokenResponse, GRANT_PRE_AUTHORIZED_CODE, GRANT_REFRESH_TOKEN,
    NOTIFICATION_ACCEPTED, NOTIFICATION_DELETED, NOTIFICATION_FAILURE,
};
use siros_issuer_core::response::encrypt_response;

use siros_issuer_core::session::SessionEvent;
use siros_issuer_core::Error;

/// Handler result: success or a rendered error response. The Err variant
/// is an axum `Response` (128 bytes) — accepted here; boxing every handler
/// buys nothing.
type HandlerResult<T> = std::result::Result<T, Response>;

fn err(error: Error) -> Response {
    use siros_issuer_core::error::code;
    let status = match error.code {
        code::INVALID_INPUT => StatusCode::BAD_REQUEST,
        // A malformed credential request is a 400, never a 500 (issue
        // #24: the engine's Final-shaped offer {jwk, enc} answered
        // 500 invalid_credential_request — a client error class).
        code::INVALID_CREDENTIAL_REQUEST => StatusCode::BAD_REQUEST,
        code::UNSUPPORTED_CREDENTIAL => StatusCode::NOT_FOUND,
        code::ILLEGAL_TRANSITION => StatusCode::CONFLICT,
        code::CONFIGURATION => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(json!({"error": error.code, "message": error.message})),
    )
        .into_response()
}

/// An OID4VCI credential error response (Final §8.3.1): `{error,
/// error_description}` and, per §7.3.2, a **fresh** `c_nonce` whenever the
/// wallet must retry with a new proof (`invalid_proof`, `invalid_nonce`).
/// The conformance suite validates the code against the registered set
/// (`VCIValidateCredentialErrorResponse`) and warns on unknown members.
#[allow(clippy::result_large_err)]
fn credential_err(state: &AppState, error: &Error) -> Response {
    use siros_issuer_core::error::code;
    // 1.0 Final error responses: {error, error_description} (+error_uri);
    // VCIValidateNoUnknownKeysInCredentialErrorResponse closes the set —
    // c_nonce/c_nonce_expires_in are NOT members (the wallet fetches a
    // fresh nonce from the nonce endpoint).
    let _ = state;
    let vci_code = match error.code {
        code::INVALID_PROOF => "invalid_proof",
        code::INVALID_NONCE => "invalid_nonce",
        code::UNSUPPORTED_CREDENTIAL => "unknown_credential_configuration",
        code::UNKNOWN_CREDENTIAL_IDENTIFIER => "unknown_credential_identifier",
        code::INVALID_CREDENTIAL_REQUEST | code::INVALID_INPUT => "invalid_credential_request",
        _ => "invalid_credential_request",
    };
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": vci_code,
            "error_description": error.message,
        })),
    )
        .into_response()
}

/// The OAuth 2.0 error shape (RFC 6749 §5.2 / OID4VCI §8.3.1): token
/// endpoint errors carry `error` + `error_description` — the conformance
/// suite shape-checks these; `message` is not a known member.
/// A client-authentication failure crossing to the OAuth error shape:
/// RFC 6749 §5.2's `invalid_client` class — the verifier's message
/// survives (never values), the code tells the class (issue #6).
fn client_auth_failure(error: Error) -> Error {
    Error::new(
        siros_issuer_core::error::code::INVALID_CLIENT,
        error.message,
    )
}

fn oauth_err(error: Error) -> Response {
    // Issue #9: the status follows the error's class — a server-side
    // configuration fault is a 503 with `temporarily_unavailable` (RFC
    // 6749 §5.2), a client-shaped fault a 400. The previous unconditional
    // 400 surfaced config failures as client errors.
    let status = match error.code {
        siros_issuer_core::error::code::CONFIGURATION => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(json!({
            "error": oauth_error_code(&error),
            "error_description": error.message,
        })),
    )
        .into_response()
}

fn oauth_error_code(error: &Error) -> &'static str {
    match error.code {
        siros_issuer_core::error::code::INVALID_INPUT => "invalid_grant",
        // RFC 6749 §5.2: client-authentication failures — issue #6's
        // misreport (invalid_grant sent the live debugging down the
        // expired/consumed-code path).
        siros_issuer_core::error::code::INVALID_CLIENT => "invalid_client",
        siros_issuer_core::error::code::UNSUPPORTED_CREDENTIAL => "unsupported_credential_format",
        // RFC 6749 §5.2: unknown grants, and the refresh_token grant
        // when the deployment gate is off (gap 1).
        siros_issuer_core::error::code::UNSUPPORTED_GRANT_TYPE => "unsupported_grant_type",
        // RFC 6749 §5.2 (issue #9): a server-side configuration fault is
        // `temporarily_unavailable` — the code a client sees should name
        // the class of failure, because that is all a client sees. A
        // misconfigured issuer answered `invalid_request`, sending the
        // live debugging into the request's shape ("my request is
        // malformed") while the failure was the server's config (the
        // wallet-attestation arm firing on an issuer without
        // [authorization.attestation.wallet] configured).
        siros_issuer_core::error::code::CONFIGURATION => "temporarily_unavailable",
        _ => "invalid_request",
    }
}

/// OpenID4VCI 1.0 ID1 §11.2.1 credential issuer metadata. Trailing-slash
/// variant registered alongside the canonical path (wwWallet compat).
#[allow(clippy::result_large_err)]
/// The credential-issuer metadata with signed-metadata content
/// negotiation (OID4VCI 1.0 Final §12.2.2): `Accept: application/jwt`
/// (any media type token containing `application/jwt`) answers the
/// JWS-signed document as `application/jwt`; anything else answers the
/// plain JSON document. The suite's `metadata-test-signed` module
/// requests the JWT and skips when the answer is JSON.
pub async fn credential_issuer_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let catalog = state.catalog_snapshot();
    let metadata = siros_issuer_core::oid4vci::metadata_from_catalog(
        &state.issuer_base,
        &catalog,
        state.authorization_servers.clone(),
        &state.endpoint_paths,
        &state.auxiliary_data_plans,
        // The deployment's own posture (issue #21): the announced
        // truth, enforced at the endpoint.
        state.response_encryption_required,
        // The ARF disclosure policies (gap 3): per-credential, absent
        // by default (the conformance closed set).
        &state.disclosure_policies,
    )
    .expect("a validated issuer base URL and catalog cannot fail generation");

    let wants_jwt = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| {
            accept
                .split(',')
                .map(str::trim)
                .any(|media| media.starts_with("application/jwt"))
        });
    if wants_jwt {
        let (signer, x5c) = match &state.metadata_signer {
            Some((signer, chain)) => (signer.as_ref(), chain.as_slice()),
            None => (state.signer.as_ref(), state.cert_chain_der.as_slice()),
        };
        let jws = match siros_issuer_core::oid4vci::signed_metadata_jws(
            &metadata,
            crate::status::now_unix(),
            3600,
            signer,
            x5c,
        ) {
            Ok(jws) => jws,
            Err(error) => return err(error),
        };
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/jwt")],
            jws,
        )
            .into_response();
    }
    Json(metadata).into_response()
}

#[allow(clippy::result_large_err)]
pub async fn oauth_authorization_server(
    State(state): State<AppState>,
) -> Json<siros_issuer_core::oid4vci::AuthorizationServerMetadata> {
    let mut metadata =
        siros_issuer_core::oid4vci::authorization_server_metadata(&state.issuer_base)
            .expect("a validated issuer base URL cannot fail generation");
    // RFC 8414's grant_types_supported: the third grant (gap 1) is
    // advertised only when the deployment enables it — never a wider
    // metadata lie (the #4 principle).
    if state.refresh_token.is_some() {
        metadata.grant_types_supported.push(GRANT_REFRESH_TOKEN);
    }
    // The token endpoint's client-auth methods, as `token` accepts them:
    // private_key_jwt only with a registered client to verify against;
    // WIA headers only with the evaluator configured; no client auth
    // only under the pre-authorized grant's `optional` posture (that
    // grant only — see `advertise_public_clients`).
    if !state.clients.is_empty() {
        metadata.advertise_private_key_jwt();
    }
    if state.wallet_attestation.is_some() {
        metadata.advertise_client_attestation();
    }
    if state.pre_authorized_client_auth == crate::config::PreAuthorizedClientAuth::Optional {
        metadata.advertise_public_clients();
    }
    Json(metadata)
}

/// `GET /.well-known/jwt-vc-issuer` (SD-JWT VC §5.3 issuer metadata):
/// the `issuer` id and the `jwks_uri` a verifier/go-trust's whitelist
/// resolves the issuer's keys from — the same discovery path vc's apigw
/// serves, so an sd-jwt issuer registered by URL in a PDP whitelist is
/// resolvable. The OID4VCI metadata serves OID4VCI discovery; this one
/// serves SD-JWT VC key discovery — both are needed.
pub async fn sd_jwt_vc_issuer_metadata(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let Ok(jwks_uri) = state.issuer_base.join("jwks") else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "configuration", "message": "issuer base URL"})),
        );
    };
    (
        StatusCode::OK,
        Json(json!({
            "issuer": siros_issuer_core::oid4vci::issuer_identifier(&state.issuer_base),
            "jwks_uri": jwks_uri.as_str(),
        })),
    )
}

/// The issuer's public signing key(s) (ID1 §11.2.1 `jwks_uri`).
pub async fn jwks(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    // The signer interface cannot fail on a healthy key handle; a broken
    // HSM session surfaces as a 503 with the stable code.
    match state.signer.public_jwk() {
        Ok(mut public) => {
            public.alg = Some(siros_issuer_core::signer::JWS_ALG.to_owned());
            (StatusCode::OK, Json(json!({"keys": [public]})))
        }
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": error.code, "message": error.message
            })),
        ),
    }
}

/// Readiness: process up, catalog loaded, refresh loop healthy.
pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let catalog = state.catalog_snapshot();
    let last_ok = state
        .refresh
        .last_ok_unix
        .load(std::sync::atomic::Ordering::Relaxed);
    let last_error = state
        .refresh
        .last_error
        .read()
        .map(|error| error.clone())
        .unwrap_or_else(|_| Some("refresh status unreadable".to_owned()));
    Json(json!({
        "status": if last_error.is_none() { "ok" } else { "degraded" },
        "catalog_credentials": catalog.credentials.len(),
        "catalog_last_refresh_unix": last_ok,
        "catalog_last_error": last_error,
    }))
}

/// `GET /credential-offer/{uuid}`: the credential offer object (ID1 §4.1)
/// — the fetch form of the deep link. The offer URI is the bearer: the
/// single-use pre-authorized code is sealed in the vault and served here
/// to whoever holds the uuid.
#[allow(clippy::result_large_err)]
pub async fn credential_offer(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> HandlerResult<Json<CredentialOffer>> {
    let record = state
        .sessions
        .find_by_offer_uuid(&uuid)
        .await
        .ok_or_else(|| {
            err(Error::new(
                siros_issuer_core::error::code::UNSUPPORTED_CREDENTIAL,
                "no such credential offer",
            ))
        })
        .map_err(|r: Response| r)?;
    // §6.5 v2: a pre-auth binding session serves its offer while
    // `awaiting_authorization` too — the wallet needs the code to redeem
    // *after* the presentation unlocks it (the claim requires `offered`);
    // withholding the offer would deadlock the flow. Auth-code sessions
    // carry no offer_uuid, so this relaxation only ever reaches the
    // pre-auth grant.
    if record.state != siros_issuer_core::session::SessionState::Offered
        && record.state != siros_issuer_core::session::SessionState::AwaitingAuthorization
    {
        return Err(err(Error::illegal_transition(
            "offer is no longer redeemable",
        )));
    }
    let sealed_code = record
        .pre_authorized_code_sealed
        .clone()
        .ok_or_else(|| err(Error::illegal_transition("offer code purged")))?;
    let code: String = state
        .vault
        .unseal(record.id.as_str(), &sealed_code)
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|e| Error::invalid_input(format!("sealed code: {e}")))
        })
        .map_err(err)?;
    let offer = CredentialOffer {
        credential_issuer: siros_issuer_core::oid4vci::issuer_identifier(&state.issuer_base),
        credential_configuration_ids: vec![record.credential_configuration_id.clone()],
        grants: [(
            GRANT_PRE_AUTHORIZED_CODE.to_owned(),
            serde_json::to_value(GrantPreAuthorizedCode {
                pre_authorized_code: code,
                tx_code: record.tx_code_spec.clone(),
            })
            .expect("offer grant serializes"),
        )]
        .into_iter()
        .collect(),
    };
    Ok(Json(offer))
}

/// `POST /nonce`: rotate and return the session's c_nonce (ID1 §10).
#[allow(clippy::result_large_err)]
pub async fn nonce(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> HandlerResult<(
    StatusCode,
    [(axum::http::HeaderName, String); 2],
    Json<Value>,
)> {
    // OID4VCI 1.0 Final §7.1 (nonce endpoint): a plain POST, no access
    // token — the wallet obtains a c_nonce *before* it can request one.
    // A Bearer token, when presented, still scopes the nonce to that
    // session (proofs bind to the session's current c_nonce).
    let now = now_unix();
    let nonce_value = random_handle("n_", 16);
    if let Some(token_hash) = bearer_token_hash(&headers) {
        if let Some((session_id, _jkt)) = state
            .sessions
            .session_by_access_token(&token_hash, now)
            .await
        {
            let _ = state
                .sessions
                .rotate_c_nonce(
                    &session_id,
                    nonce_value.clone(),
                    now + state.c_nonce_ttl_seconds,
                )
                .await;
        }
    }
    {
        // The ring: every minted nonce lives until the ring is full —
        // concurrent pre-session proofs each bind their own (the
        // step-back review's #3: the single-slot interleave).
        let mut ring = state
            .public_nonces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ring.push_back((nonce_value.clone(), now));
        while ring.len() > state.public_nonce_slots {
            ring.pop_front();
        }
    }
    // RFC 6749 §5.1 / suite CheckCacheControlHeaderContainsNoStore.
    let cache_control = (
        axum::http::HeaderName::from_static("cache-control"),
        "no-store".to_owned(),
    );
    let content_type = (
        axum::http::HeaderName::from_static("content-type"),
        "application/json".to_owned(),
    );
    Ok((
        StatusCode::OK,
        [content_type, cache_control],
        // Final §7.1 nonce endpoint: the response carries c_nonce alone
        // (VCICheckCredentialNonceResponseForUnknownFields closes the
        // set to {c_nonce, attestation_challenge}).
        Json(json!({
            "c_nonce": nonce_value,
        })),
    ))
}

/// `POST /token`: the pre-authorized grant (ID1 §5.2). Accepts both the
/// OAuth form encoding and JSON.
#[allow(clippy::result_large_err)]
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> HandlerResult<Json<TokenResponse>> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let params: Vec<(String, String)> = if content_type.starts_with("application/json") {
        let value: Value =
            serde_json::from_str(&body).map_err(|e| err(Error::invalid_input(e.to_string())))?;
        value
            .as_object()
            .ok_or_else(|| err(Error::invalid_input("token body must be an object")))?
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
            .collect()
    } else {
        form_urlencoded::parse(body.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    };
    let get = |key: &str| {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };

    let grant_type = get("grant_type").unwrap_or_default();
    let now = now_unix();
    let is_pre_auth_flow = grant_type == GRANT_PRE_AUTHORIZED_CODE;

    // Client authentication (design §12.2-resolved + §12.1 WIA/KA): the
    // OIDF issuer plan speaks private_key_jwt — RFC 7523 against the
    // pre-registered set. **Wallet attestation** (draft-ietf-oauth-
    // attestation-based-client-auth) is the second path: headers per
    // draft §3.1 (`OAuth-Client-Attestation` + PoP) or the legacy
    // form-body `client_assertion` (no PoP), vc's token-handler flow —
    // registered clients first, attestation when the client is not (or
    // the attestation headers are present).
    //
    // **The pre-authorized posture (issue #6)**: `required` (the
    // default, the conformance profile) refuses an absent method;
    // `optional` (vc's deployment posture — the wallet ecosystem's
    // de-facto shape on this grant) tolerates ABSENCE only: a method
    // PRESENT is still verified, and a bad one refuses. The
    // authorization_code grant never relaxes — its client was
    // authenticated at PAR.
    let client_auth_optional = is_pre_auth_flow
        && state.pre_authorized_client_auth == crate::config::PreAuthorizedClientAuth::Optional;
    let client_assertion = get("client_assertion");
    let assertion_type = get("client_assertion_type");
    let client_id = get("client_id");
    let attestation_header = headers
        .get("oauth-client-attestation")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let attestation_pop = headers
        .get("oauth-client-attestation-pop")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // The credential scope for tier authorization: the bound code's scope
    // — never a caller-supplied wildcard (vc re-checks against what the
    // PAR/offer authorized).
    let requested_scope = get("scope");
    match (attestation_header.as_deref(), attestation_pop.as_deref()) {
        // Draft §3.1 headers: PoP is REQUIRED with the attestation header.
        (Some(attestation), pop) => {
            let evaluator = state.wallet_attestation.as_ref().ok_or_else(|| {
                oauth_err(Error::configuration(
                    "wallet attestation auth is not configured (authorization.attestation.wallet)",
                ))
            })?;
            let pop = pop.unwrap_or("");
            let scope = requested_scope.as_deref().unwrap_or("");
            evaluator
                .evaluate_with_pop(attestation, pop, scope)
                .await
                .map_err(|e| oauth_err(client_auth_failure(e)))?;
        }
        // No headers: RFC 7523 private_key_jwt against the registry.
        (None, _) => {
            match (assertion_type.as_deref(), client_assertion.as_deref()) {
                (Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), Some(assertion)) => {
                    crate::client_auth::verify_private_key_jwt(
                        &state.clients,
                        assertion,
                        // RFC 7523 §3: client_id may be absent — the client is the
                        // assertion's iss (the suite's token requests omit it).
                        client_id.as_deref(),
                        // The suite signs aud = the issuer identifier.
                        &state.issuer_base,
                        now,
                        60,
                    )
                    .map_err(|e| oauth_err(client_auth_failure(e)))?;
                }
                // Absence: refused under the required posture (RFC 6749
                // §5.2 — invalid_client, never the misdirecting
                // invalid_grant of issue #6); tolerated on the
                // pre-authorized grant when the deployment says
                // optional (vc's posture — the single-use code is the
                // security mechanism).
                _ if client_auth_optional => {}
                _ => {
                    return Err(oauth_err(Error::new(
                        siros_issuer_core::error::code::INVALID_CLIENT,
                        "client authentication required: private_key_jwt (client_assertion) or OAuth-Client-Attestation (WIA)",
                    )))
                }
            }
        }
    }

    // DPoP (RFC 9449): when a DPoP proof accompanies the token request,
    // the minted access token is sender-constrained to the proof key.
    let dpop = match headers.get("dpop").and_then(|v| v.to_str().ok()) {
        Some(proof) => {
            let htu = state
                .issuer_base
                .join("token")
                .map_err(|e| err(Error::configuration(e.to_string())))?;
            let verified = state
                .dpop
                .validate(proof, "POST", &htu, now, None)
                .await
                .map_err(oauth_err)?;
            Some(verified.jkt)
        }
        None => None,
    };

    let record = match grant_type.as_str() {
        GRANT_PRE_AUTHORIZED_CODE => {
            // The grant's code parameter is hyphenated like the grant URN
            // (`pre-authorized_code`); accept the snake spelling too.
            let code = get("pre-authorized_code")
                .or_else(|| get("pre_authorized_code"))
                .ok_or_else(|| err(Error::invalid_input("pre-authorized_code is required")))?;
            let tx = get("tx_code");
            state
                .sessions
                .claim_pre_auth_code(&code, tx.as_deref(), now)
                .await
                .map_err(oauth_err)?
        }
        GRANT_AUTHORIZATION_CODE => {
            // Final §5.1 over PAR: code + redirect + PKCE verifier. The
            // client id comes from the assertion's iss when the form omits
            // it (RFC 7523 §3) — the suite omits it.
            let code = get("code").ok_or_else(|| err(Error::invalid_input("code is required")))?;
            let redirect_uri = get("redirect_uri")
                .ok_or_else(|| err(Error::invalid_input("redirect_uri is required")))?;
            let client_id = get("client_id")
                .or_else(|| client_identity_from_assertion(client_assertion.as_deref()))
                .ok_or_else(|| err(Error::invalid_input("client_id is required")))?;
            let code_verifier = get("code_verifier")
                .ok_or_else(|| err(Error::invalid_input("code_verifier is required (PKCE)")))?;
            // Mode B (design §7.3): the DPoP key that bound the
            // authorization challenge sender-constrains the code — checked
            // BEFORE the single-use claim so a wrong key refuses without
            // burning the code.
            if let Some(record) = state.sessions.peek_auth_code(&code).await {
                if let Some(challenge_jkt) = &record.challenge_jkt {
                    if dpop.as_ref() != Some(challenge_jkt) {
                        return Err(oauth_err(Error::invalid_input(
                            "a DPoP proof matching the authorization challenge key is required",
                        )));
                    }
                }
            }
            state
                .sessions
                .claim_auth_code(&code, &redirect_uri, &client_id, &code_verifier, now)
                .await
                .map_err(oauth_err)?
        }
        GRANT_REFRESH_TOKEN => {
            // RFC 6749 §6 — the third grant (design §12.1, gap 1),
            // vc's reference semantics. Config-gated: off ⇒ the
            // endpoint answers as if the grant did not exist.
            if state.refresh_token.is_none() {
                return Err(oauth_err(Error::new(
                    siros_issuer_core::error::code::UNSUPPORTED_GRANT_TYPE,
                    "refresh_token grant is not enabled",
                )));
            }
            // The OAuth error shape throughout (RFC 6749 §5.2):
            // these are grant-level refusals, invalid_grant class.
            let old = get("refresh_token")
                .ok_or_else(|| Error::invalid_input("refresh_token is required"))
                .map_err(oauth_err)?;
            // Sender-constrained refresh (ARF 3.0 §6.6.6.2.2, vc): the
            // DPoP proof is REQUIRED and must carry the issuance-time
            // key.
            let jkt = dpop
                .clone()
                .ok_or_else(|| {
                    Error::invalid_input("a DPoP proof is required for the refresh_token grant")
                })
                .map_err(oauth_err)?;
            // Peek, never consume: the wrong-key/expiry refusals below
            // must not burn the token — the CAS rotation after the
            // match is the only consuming step.
            let record = state
                .sessions
                .peek_by_refresh_token(&old)
                .await
                .ok_or_else(|| Error::invalid_input("invalid or expired refresh token"))
                .map_err(oauth_err)?;
            if record.refresh_token_expires_unix.unwrap_or_default() < now {
                return Err(oauth_err(Error::invalid_input("refresh token has expired")));
            }
            // Revocation reaches the session machinery (step-back #1):
            // a revoked session rotates nothing — the guard precedes
            // the CAS rotation (no consumption, just refusal).
            if record.revoked {
                return Err(oauth_err(Error::invalid_input("this session is revoked")));
            }
            match &record.refresh_dpop_jkt {
                Some(stored) if stored == &jkt => {}
                None => {
                    return Err(oauth_err(Error::invalid_input(
                        "refresh token is not bound to a DPoP key",
                    )))
                }
                Some(_) => {
                    return Err(oauth_err(Error::invalid_input(
                        "DPoP key does not match the key used at initial token issuance",
                    )))
                }
            }
            record
        }
        other => {
            // RFC 6749 §5.2: an unknown grant answers
            // unsupported_grant_type — never the misdirecting
            // invalid_grant (the same honesty fix as issue #6's class).
            return Err(oauth_err(Error::new(
                siros_issuer_core::error::code::UNSUPPORTED_GRANT_TYPE,
                format!("grant_type {other:?} is not supported"),
            )));
        }
    };

    // Gap 5: the issuance surfaces trace identifiers only (the PII
    // discipline, §13.3's audit): grant type + session id — never the
    // code, proof, or claim material crossing this handler.
    tracing::info_span!("token", grant = %grant_type, session = %record.id.as_str());

    // Mint the access token (hashed at rest) and rotate the c_nonce.
    let access_token = random_handle("at_", 24);
    let c_nonce = random_handle("n_", 16);
    state
        .sessions
        .bind_access_token(
            hex_of(&access_token),
            &record.id,
            now + state.access_token_ttl_seconds,
            // Cloned, not moved: the refresh-token mint below reads the
            // binding jkt.
            dpop.clone(),
        )
        .await
        .map_err(oauth_err)?;
    state
        .sessions
        .rotate_c_nonce(&record.id, c_nonce.clone(), now + state.c_nonce_ttl_seconds)
        .await
        .map_err(oauth_err)?;

    // RFC 6749 §6 (gap 1): the refresh token. Minted at issuance when
    // the deployment enables it AND the access token is DPoP-bound —
    // refresh is sender-constrained, so a token minted on a DPoP-free
    // session could never be used and is never issued. Single-use
    // rotated on the refresh grant: the CAS on the old hash refuses a
    // replay (invalid_grant, "already used" — vc's wording).
    let (refresh_token, refresh_token_expires_in) = match state.refresh_token.as_ref() {
        None => (None, None),
        Some(cfg) => {
            let expires = now + cfg.duration;
            if grant_type == GRANT_REFRESH_TOKEN {
                let old =
                    get("refresh_token").expect("the refresh grant arm validated the parameter");
                let rotated = random_handle("rt_", 32);
                // Raw token in — the store hashes at rest (the same
                // convention as the pre-authorized code).
                state
                    .sessions
                    .rotate_refresh_token(&old, rotated.clone(), expires)
                    .await
                    .map_err(oauth_err)?;
                (Some(rotated), Some(cfg.duration))
            } else if dpop.is_some() {
                let minted = random_handle("rt_", 32);
                state
                    .sessions
                    .set_refresh_token(&record.id, minted.clone(), expires, dpop.clone())
                    .await
                    .map_err(oauth_err)?;
                (Some(minted), Some(cfg.duration))
            } else {
                // DPoP-free issuance (the plain pre-authorized posture):
                // no refresh token — it would be unusable by design.
                (None, None)
            }
        }
    };

    Ok(Json(TokenResponse {
        access_token,
        // RFC 9449 §4.3 (issue #19): a DPoP-bound access token is of
        // type DPoP — the client MUST use the DPoP authentication
        // scheme for it. Announce what was minted: engines branch on
        // this value (siros-wallet-core sends Bearer-with-no-proof for
        // "Bearer", and the issuer's own enforcement then refuses the
        // binding it never announced).
        token_type: if dpop.is_some() { "DPoP" } else { "Bearer" },
        expires_in: state.access_token_ttl_seconds,
        c_nonce,
        c_nonce_expires_in: state.c_nonce_ttl_seconds,
        refresh_token,
        refresh_token_expires_in,
    }))
}

/// `POST /batch-credential` (OID4VCI 1.0 Final §12.2.2 batch issuance):
/// same issuance flow as `/credential` — the batch is the `proofs`
/// carrying multiple keys (one credential per key, capped at the
/// advertised `batch_size`); see `credential_inner`. The suite's batch
/// module POSTs to `/credential`; this route serves wallets that use
/// the advertised dedicated endpoint.
#[allow(clippy::result_large_err)]
pub async fn batch_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> HandlerResult<Response> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let request: CredentialRequest = if content_type.starts_with("application/jwt") {
        let key = state.request_encryption_key.clone().ok_or_else(|| {
            err(Error::configuration(
                "credential_request_encryption is not configured",
            ))
        })?;
        let plaintext = siros_issuer_core::response::decrypt_request(&body, &key).map_err(err)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| err(Error::invalid_credential_request(e.to_string())))?
    } else {
        serde_json::from_str(&body)
            .map_err(|e| err(Error::invalid_credential_request(e.to_string())))?
    };
    credential_inner(state, headers, request).await
}

/// RFC 7638 SHA-256 thumbprint of a JWK — the batch binding-key
/// distinctness check (the suite compares these:
/// VCIEnsureBatchBindingKeysAreDistinct).
#[allow(clippy::result_large_err)]
fn jwk_thumbprint(jwk: &jose_rs::jwk::Jwk) -> HandlerResult<String> {
    jose_rs::jwk::thumbprint::thumbprint_sha256(jwk)
        .map_err(|e| err(Error::invalid_input(format!("jwk thumbprint: {e}"))))
}

#[allow(clippy::result_large_err)]
pub async fn credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> HandlerResult<Response> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let request: CredentialRequest = if content_type.starts_with("application/jwt") {
        // Final §10: the request body is a JWE encrypted to our
        // credential_request_encryption key.
        let key = state.request_encryption_key.clone().ok_or_else(|| {
            err(Error::configuration(
                "credential_request_encryption is not configured",
            ))
        })?;
        let plaintext = siros_issuer_core::response::decrypt_request(&body, &key).map_err(err)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| err(Error::invalid_credential_request(e.to_string())))?
    } else {
        serde_json::from_str(&body)
            .map_err(|e| err(Error::invalid_credential_request(e.to_string())))?
    };
    credential_inner(state, headers, request).await
}

#[allow(clippy::result_large_err)]
async fn credential_inner(
    state: AppState,
    headers: HeaderMap,
    request: CredentialRequest,
) -> HandlerResult<Response> {
    let token_hash = bearer_token_hash(&headers).ok_or_else(|| {
        err(Error::invalid_input(
            "missing access token (Authorization: Bearer or DPoP)",
        ))
    })?;
    let now = now_unix();
    let (session_id, dpop_jkt) = state
        .sessions
        .session_by_access_token(&token_hash, now)
        .await
        .ok_or_else(|| err(Error::invalid_input("unknown or expired access token")))?;
    enforce_sender_constrained_token(&state, &headers, &dpop_jkt, "credential", now).await?;
    // Gap 5: identifiers only (the §13.3 discipline) — the session id
    // and the configuration asked for; never the proof or the claims.
    tracing::info_span!("credential", session = %session_id.as_str());
    let record = state.sessions.get(&session_id).await.ok_or_else(|| {
        credential_err(
            &state,
            &Error::new(
                siros_issuer_core::error::code::UNSUPPORTED_CREDENTIAL,
                "credential_configuration_id does not match the session",
            ),
        )
    })?;
    // Revocation reaches the session machinery (step-back #1): a
    // revoked session issued NOTHING new — the status bit kills the
    // OLD credentials, this guard stops the session minting more.
    if record.revoked {
        return Err(credential_err(
            &state,
            &Error::new(
                siros_issuer_core::error::code::ILLEGAL_TRANSITION,
                "this session is revoked",
            ),
        ));
    }

    // Final §8.2: the credential is selected by configuration id or by
    // identifiers of previously issued credentials. This issuer issues by
    // configuration id (P2); a requested identifier is never one we issued.
    let mut identifiers = request.credential_identifiers.clone().unwrap_or_default();
    if let Some(identifier) = &request.credential_identifier {
        identifiers.push(identifier.clone());
    }
    let configuration_id = match (&request.credential_configuration_id, identifiers.is_empty()) {
        (Some(id), _) => id.clone(),
        (None, false) => {
            return Err(credential_err(
                &state,
                &Error::new(
                    siros_issuer_core::error::code::UNKNOWN_CREDENTIAL_IDENTIFIER,
                    format!("credential identifier {identifiers:?} was not issued by this issuer"),
                ),
            ));
        }
        (None, true) => {
            return Err(credential_err(
                &state,
                &Error::invalid_credential_request(
                    "credential_configuration_id or credential_identifiers is required",
                ),
            ));
        }
    };
    if configuration_id != record.credential_configuration_id {
        return Err(credential_err(
            &state,
            &Error::new(
                siros_issuer_core::error::code::UNSUPPORTED_CREDENTIAL,
                "credential_configuration_id does not match the session",
            ),
        ));
    }

    // The proofs' holder keys become cnf / the DeviceKey per entry.
    // Final §8.2 `proofs` (suite shape) with draft `proof` fallback.
    // **Batch semantics** (Final §12.2.2, vc `Proofs.ExtractAllJWKs`):
    // one credential per key the proofs carry — one per jwt proof, or
    // **all** `attested_keys` of an attestation proof — capped at the
    // advertised `batch_size` (1 = single-issuance only, the current
    // behavior when batch is not advertised). The proof type picks the
    // verifier; the credential format picks the issuance branch. They
    // are deliberately not coupled: a jwt proof (§7.1, key in the jwk
    // header) and an attestation proof (Appendix D.1, keys in
    // attested_keys) both carry holder keys, and the format says nothing
    // about which proof the wallet sends — coupling them masked
    // invalid_nonce with the attestation path's typ refusal
    // (regression-tested in issuance_e2e).
    let proofs = request.jwt_proofs();
    if proofs.is_empty() {
        return Err(credential_err(
            &state,
            &Error::invalid_proof("proofs is required"),
        ));
    }
    let batch_size = state
        .endpoint_paths
        .batch_credential
        .map(|(_, size)| size as usize)
        .unwrap_or(1);
    if now >= record.c_nonce_expires_unix {
        return Err(credential_err(
            &state,
            &Error::invalid_nonce("c_nonce expired; POST /nonce for a fresh one"),
        ));
    }
    // Final §7.1/§7.2.2: each proof's nonce is the one the wallet holds —
    // the session's rotated c_nonce OR the last one minted at the public
    // nonce endpoint (which the suite fetches before its first credential
    // request). Either binds freshness; both are single-use in time.
    let public_nonce = state
        .public_nonces
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .back()
        .map(|(nonce, _)| nonce.clone())
        .unwrap_or_default();
    let session_nonce = record.c_nonce.clone();

    // Extract every holder key the proofs carry, verifying each proof
    // against the session/public nonce.
    let mut holder_jwks: Vec<jose_rs::jwk::Jwk> = Vec::new();
    for (proof_type, jwt) in &proofs {
        let keys = match proof_type.as_str() {
            "jwt" => {
                // Final §7.1/§7.2.2: the proof binds the session's
                // rotated nonce OR any LIVE public nonce (the ring — a
                // concurrent wallet's mint does not kill another's).
                let mut verified =
                    verify_jwt_proof(jwt, &state.issuer_base, &session_nonce, now, 60);
                if verified.is_err() {
                    let ring = state
                        .public_nonces
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    for (nonce, minted_at) in ring.iter() {
                        if now.saturating_sub(*minted_at) > state.c_nonce_ttl_seconds {
                            continue; // stale slot (the ring's soft expiry)
                        }
                        verified = verify_jwt_proof(jwt, &state.issuer_base, nonce, now, 60);
                        if verified.is_ok() {
                            break;
                        }
                    }
                }
                verified.map(|jwk| vec![jwk])
            }
            // Appendix D.1: ALL attested_keys — one credential per key in
            // a batch (vc `ExtractAllJWKs`); the signature is checked
            // against the x5c leaf (self-consistency — trust in the
            // attestation issuer is the policy layer's, mirroring vc).
            "attestation" => {
                verify_attestation_proof_all(jwt, &state.issuer_base, &session_nonce, now, 60)
                    .or_else(|_| {
                        verify_attestation_proof_all(
                            jwt,
                            &state.issuer_base,
                            &public_nonce,
                            now,
                            60,
                        )
                    })
            }
            other => {
                return Err(credential_err(
                    &state,
                    &Error::invalid_proof(format!("unsupported proof_type {other:?}")),
                ));
            }
        }
        .map_err(|e| credential_err(&state, &e))?;
        holder_jwks.extend(keys);
    }
    // One credential per key, capped at the advertised batch_size — more
    // keys than proofs is never possible here, but more than the
    // advertised batch is a refusal (the suite's
    // VCIEnsureNotMoreCredentialsThanRequestedProofs shape).
    if holder_jwks.len() > batch_size {
        return Err(credential_err(
            &state,
            &Error::invalid_proof(format!(
                "{} keys exceed the batch_size {batch_size}",
                holder_jwks.len()
            )),
        ));
    }
    // Distinct binding keys across the batch (the suite's
    // VCIEnsureBatchBindingKeysAreDistinct): a duplicate key is a
    // refusal, never collapsed.
    let mut seen_jkts = std::collections::HashSet::new();
    for jwk in &holder_jwks {
        let jkt = jwk_thumbprint(jwk)?;
        if !seen_jkts.insert(jkt) {
            return Err(credential_err(
                &state,
                &Error::invalid_proof("batch proof keys must be distinct"),
            ));
        }
    }

    // Deferred issuance (design §7.6, Final §9): armed here, issued at
    // poll. The arm carries the verified holder keys (the deferred
    // request carries only `transaction_id`); the session defers into
    // `pending` and the wallet polls `/deferred-credential` until this
    // issuer completes the issuance exactly once.
    if state.endpoint_paths.deferred_credential.is_some() {
        state
            .step(&record.id, SessionEvent::Deferred)
            .await
            .map_err(|e| credential_err(&state, &e))?;
        let transaction_id = fresh_transaction_id()?;
        state
            .sessions
            .set_transaction(
                &record.id,
                hex_of(&transaction_id),
                holder_jwks
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<Result<_, _>>()
                    .map_err(|e| err(Error::invalid_input(format!("holder jwk: {e}"))))?,
            )
            .await
            .map_err(|e| credential_err(&state, &e))?;
        let response = CredentialResponse {
            credentials: Vec::new(),
            transaction_id: Some(transaction_id),
            // Final §9: the poll-interval guidance (vc's `interval`).
            interval: Some(state.deferred_interval_seconds),
            // §8.3: notification_id MUST NOT be present without
            // credentials.
            notification_id: None,
            credential_metadata: None,
        };
        return credential_response(&state, &headers, &response, None);
    }

    let (entries, metadata) = issue_session_entries(&state, &record, &holder_jwks, now).await?;

    let response = CredentialResponse {
        credentials: entries,
        transaction_id: None,
        interval: None,
        notification_id: Some(record.notification_id.clone()),
        credential_metadata: metadata,
    };
    credential_response(
        &state,
        &headers,
        &response,
        request.credential_response_encryption.as_ref(),
    )
}

/// Build the credential response (shared by `/credential` and
/// `/deferred-credential`, Final §8.3/§9): ECDHE-ES encryption when
/// requested (and only the advertised suites) — for the deferred
/// completion, the parameters are the DEFERRED request's (§9.1:
/// "regardless of what was sent in the initial Credential Request").
#[allow(clippy::result_large_err)]
fn credential_response(
    state: &AppState,
    headers: &HeaderMap,
    response: &CredentialResponse,
    encryption: Option<&CredentialResponseEncryption>,
) -> HandlerResult<Response> {
    // The aux-data extension's own rule (issue #21), fail-closed: a
    // to_wallet opening NEVER crosses the wire in the clear. A plain
    // request (no credential_response_encryption) for a credential
    // whose response carries an opening is refused — the engine's
    // wallet-side gate ("auxiliary_data arrived in a plain response;
    // the issuer must encrypt it") and the issuer must agree. This
    // runs BEFORE the encryption branch: the plain path below is
    // unreachable for a secret-carrying response.
    let carries_openings = response
        .credential_metadata
        .as_ref()
        .map(|metadata| {
            metadata
                .auxiliary_data
                .iter()
                .any(|entry| entry.opening.is_some())
        })
        .unwrap_or(false);
    if (carries_openings || state.response_encryption_required) && encryption.is_none() {
        let why = if carries_openings {
            "this credential carries a to_wallet auxiliary-data opening; the response must be encrypted (send credential_response_encryption)"
        } else {
            "this issuer requires encrypted credential responses (send credential_response_encryption)"
        };
        return Err(credential_err(state, &Error::invalid_input(why)));
    }

    let body =
        serde_json::to_vec(response).map_err(|e| err(Error::invalid_input(e.to_string())))?;

    // ECDHE-ES encryption when requested (and only the advertised suites).
    if let Some(encryption) = encryption {
        // Final §7.3 (issue #24): the algorithm is NOT a request member —
        // the offer is {jwk, enc, zip?}. Absent ⇒ the issuer selects from
        // its own alg_values_supported (ECDH-ES — the one it mints with);
        // the draft-era three-member shape is still accepted and validated.
        if encryption
            .alg
            .as_deref()
            .is_some_and(|alg| alg != "ECDH-ES")
            || encryption.enc != "A128GCM"
        {
            return Err(credential_err(
                state,
                &Error::invalid_input("only alg ECDH-ES enc A128GCM are supported (as advertised)"),
            ));
        }
        let recipient: jose_rs::jwk::Jwk = serde_json::from_value(encryption.jwk.clone())
            .map_err(|e| err(Error::invalid_input(format!("response jwk: {e}"))))?;
        let kid = encryption.jwk.get("kid").and_then(Value::as_str);
        let jwe = encrypt_response(
            &recipient,
            &body,
            kid,
            jose_rs::algorithm::JweEncryption::A128GCM,
        )
        .map_err(|e| credential_err(state, &e))?;
        // Vec<(HeaderName, String)>: axum has no IntoResponse for a
        // variable-length header list + body — build the response
        // manually.
        let mut built = Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::from(jwe))
            .expect("static response parts");
        for (name, value) in fapi_headers(headers, "application/jwt") {
            built
                .headers_mut()
                .insert(name, value.parse().expect("header value"));
        }
        return Ok(built);
    }
    let mut built = Response::builder()
        .status(StatusCode::OK)
        .body(axum::body::Body::from(body))
        .expect("static response parts");
    for (name, value) in fapi_headers(headers, "application/json") {
        built
            .headers_mut()
            .insert(name, value.parse().expect("header value"));
    }
    Ok(built)
}

/// Unseal the subject and issue one entry per verified holder key (shared
/// by the immediate and the deferred issuance paths — one issuance
/// routine, two entry points, design §7.6).
///
/// Format-aware: mso_mdoc builds an IssuerSigned (COSE_Sign1 over the
/// MSO, per-element digests, RFC 9901-rounded validityInfo); dc+sd-jwt
/// builds the SD-JWT. One entry per holder key; a distinct unpredictable
/// status index per entry (the suite's
/// VCIEnsureBatchStatusListIndicesAreUnpredictable). Batch entries
/// (more than one key) round their time claims to a 3600 bucket —
/// VCIEnsureBatchTimeClaimsNotLinkable treats time values shared across
/// a batch as correlatable unless hour-aligned; a single issuance keeps
/// the 300 bucket (VCIEnsureCredentialTimeClaimsNotLinkable).
#[allow(clippy::result_large_err)]
async fn issue_session_entries(
    state: &AppState,
    record: &crate::store::SessionRecord,
    holder_jwks: &[jose_rs::jwk::Jwk],
    now: i64,
) -> HandlerResult<(Vec<CredentialEntry>, Option<CredentialMetadata>)> {
    let is_mdoc =
        catalog_format(state, &record.credential_configuration_id).as_deref() == Some("mso_mdoc");
    // Unseal the subject once: every entry in the batch is issued over
    // the same session subject data (identical datasets — the suite
    // compares them, ignoring digestID/random/validity/device key).
    let sealed = record
        .sealed
        .clone()
        .ok_or_else(|| err(Error::illegal_transition("session subject data was purged")))?;
    let subject = state
        .vault
        .unseal(record.id.as_str(), &sealed)
        .map_err(|e| credential_err(state, &e))?;

    let time_bucket_secs: i64 = if holder_jwks.len() > 1 { 3600 } else { 300 };
    let mut entries = Vec::with_capacity(holder_jwks.len());
    let mut metadata = None;
    for holder_jwk in holder_jwks {
        if is_mdoc {
            let (mdoc_entries, mdoc_metadata) = issue_mdoc_entries(
                state,
                record.clone(),
                subject.clone(),
                holder_jwk.clone(),
                now,
                time_bucket_secs,
            )
            .await?;
            entries.extend(mdoc_entries);
            metadata = metadata.or(mdoc_metadata);
        } else {
            let status_ref = state
                .allocator
                .allocate(None)
                .await
                .map_err(|e| credential_err(state, &e))?;
            entries.push(
                issue_sdjwt_entry(
                    state,
                    record.clone(),
                    &subject,
                    holder_jwk.clone(),
                    status_ref,
                    now,
                    time_bucket_secs,
                )
                .await?,
            );
        }
    }
    // Issue #41: the display members ride the response credential_metadata
    // when the deployment opted in (`issuance.emit_credential_metadata_
    // on_response`, vc's `Delivery.EmitCredentialMetadataOnResponse`):
    // the TS11 catalog document's display content, mapped to the
    // vc-issuer's wire shape — `display` and `claims` around the
    // auxiliary-data carrier. The knob ADDS members around the carrier;
    // it never gates it (the openings ride `credential_metadata`
    // whatever the knob says — the rulebook's contract, unchanged). A
    // document without display content adds nothing, and an empty
    // credential_metadata object never reaches the wire.
    if state.emit_credential_metadata_on_response {
        if let Ok(credential) = siros_issuer_core::catalog::resolve(
            &state.catalog_snapshot(),
            &record.credential_configuration_id,
        ) {
            let (display, claims) = siros_issuer_core::catalog::display_members(credential);
            if !display.is_empty() || !claims.is_empty() {
                let metadata = metadata.get_or_insert_with(|| {
                    siros_issuer_core::oid4vci::CredentialMetadata {
                        display: Vec::new(),
                        claims: Vec::new(),
                        auxiliary_data: Vec::new(),
                    }
                });
                metadata.display = display;
                metadata.claims = claims;
            }
        }
    }
    Ok((entries, metadata))
}

/// `POST /notification` (ID1 §11.3): wallet feedback into the state
/// machine (design §7.7).
pub async fn notification(
    State(state): State<AppState>,
    Json(request): Json<NotificationRequest>,
) -> StatusCode {
    let record = match state
        .sessions
        .find_by_notification_id(&request.notification_id)
        .await
    {
        Some(record) => record,
        None => return StatusCode::NOT_FOUND,
    };
    let event = match request.event.as_str() {
        NOTIFICATION_ACCEPTED => SessionEvent::WalletAccepted,
        NOTIFICATION_FAILURE => SessionEvent::WalletFailed,
        NOTIFICATION_DELETED => SessionEvent::WalletDeleted,
        _ => return StatusCode::BAD_REQUEST,
    };
    match state.step(&record.id, event).await {
        // No immediate purge here: `accepted` and `deleted` sessions stay
        // re-issuable (§13.3 multiple accesses — the suite's
        // additional-requests module re-issues after credential_accepted).
        // The retention sweeper enforces §6.3's bounded data lifetime
        // (failed/expired purge, hard delete past retention) on its
        // interval; the DELETE endpoint purges immediately.
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::CONFLICT,
    }
}

/// The access token out of the Authorization header, either scheme:
/// RFC 9449 §4.3 (issue #19) — the client uses the DPoP scheme for a
/// DPoP-bound token (`Authorization: DPoP <token>` + the DPoP proof
/// header); a Bearer-announced token rides Bearer. The issuer
/// announced which at /token and accepts both here.
fn authorization_access_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("DPoP "))
}

fn bearer_token_hash(headers: &HeaderMap) -> Option<String> {
    Some(hex_of(authorization_access_token(headers)?))
}

fn hex_of(value: &str) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(value.as_bytes()))
}

/// RFC 9449 §4: a DPoP-bound access token demands a fresh proof whose
/// `ath` is this token's hash and whose key thumbprint matches the
/// binding minted at /token. Enforced identically at `/credential`
/// and `/deferred-credential` (Final §9 — the same access token).
#[allow(clippy::result_large_err)]
async fn enforce_sender_constrained_token(
    state: &AppState,
    headers: &HeaderMap,
    bound_jkt: &Option<String>,
    endpoint: &str,
    now: i64,
) -> HandlerResult<()> {
    let Some(bound_jkt) = bound_jkt else {
        return Ok(());
    };
    let proof = headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            err(Error::invalid_input(
                "DPoP proof required for this access token",
            ))
        })?;
    let access_token = authorization_access_token(headers).unwrap_or_default();
    let ath = crate::dpop::access_token_hash(access_token);
    let htu = state
        .issuer_base
        .join(endpoint)
        .map_err(|e| err(Error::configuration(e.to_string())))?;
    let verified = state
        .dpop
        .validate(proof, "POST", &htu, now, Some(&ath))
        .await
        .map_err(err)?;
    if &verified.jkt != bound_jkt {
        return Err(err(Error::invalid_input(
            "DPoP key does not match the access token binding",
        )));
    }
    Ok(())
}

/// Final §9 `transaction_id`: unguessable (OS randomness), single-use
/// (the store's arm is compare-and-set), invalidated once the credential
/// is obtained (design §7.6).
#[allow(clippy::result_large_err)]
fn fresh_transaction_id() -> HandlerResult<String> {
    Ok(random_handle("urn:txn:siros:", 32))
}

/// `POST /deferred-credential` (Final §9 Deferred Credential Endpoint,
/// design §7.6): the wallet polls with the `transaction_id` from the
/// pending credential response.
///
/// The transaction's single-use arm is consumed atomically (take under
/// the lock): a concurrent or repeated poll misses — one completion, the
/// session transitions `issued` exactly once, and the second take
/// answers `invalid_transaction_id` (the spec's error for an unknown or
/// already-claimed transaction; §9.2). The issuance itself runs on the
/// ARMED holder keys (the deferred request carries no proofs — §9's
/// body is `transaction_id` alone), over the same one routine as the
/// immediate path (`issue_session_entries` — one issuance routine, two
/// entry points). The response is encrypted per THIS request's
/// `credential_response_encryption` parameters (§9.1: "regardless of
/// what was sent in the initial Credential Request").
#[allow(clippy::result_large_err)]
pub async fn deferred_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> HandlerResult<Response> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let request: DeferredCredentialRequest = if content_type.starts_with("application/jwt") {
        // Final §9.1: the deferred request may be a JWE like the initial
        // Credential Request (§10).
        let key = state.request_encryption_key.clone().ok_or_else(|| {
            err(Error::configuration(
                "credential_request_encryption is not configured",
            ))
        })?;
        let plaintext = siros_issuer_core::response::decrypt_request(&body, &key).map_err(err)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| err(Error::invalid_credential_request(e.to_string())))?
    } else {
        serde_json::from_str(&body)
            .map_err(|e| err(Error::invalid_credential_request(e.to_string())))?
    };
    let now = now_unix();
    // Order of checks, exactly the Mode B discipline: the
    // sender-constraint check is read-only, so it runs FIRST (a wrong
    // key refuses without burning the single-use arm); the arm-claim is
    // second. The deferred request rides the SAME access token as the
    // initial one (Final §9), so the binding enforced here is the
    // token's.
    let token_hash = bearer_token_hash(&headers).ok_or_else(|| {
        err(Error::invalid_input(
            "missing access token (Authorization: Bearer or DPoP)",
        ))
    })?;
    let (session_id, dpop_jkt) = state
        .sessions
        .session_by_access_token(&token_hash, now)
        .await
        .ok_or_else(|| err(Error::invalid_input("unknown or expired access token")))?;
    enforce_sender_constrained_token(&state, &headers, &dpop_jkt, "deferred-credential", now)
        .await?;

    // The single-use arm: atomic consume, session-bound (a mismatched
    // principal's poll never claims). None = unknown, already claimed,
    // or another session's (§9.2 invalid_transaction_id).
    let record = state
        .sessions
        .take_transaction(&hex_of(&request.transaction_id), &session_id)
        .await
        .ok_or_else(|| {
            credential_err(
                &state,
                &Error::new(
                    siros_issuer_core::error::code::INVALID_INPUT,
                    "transaction_id is unknown, expired, or already claimed",
                ),
            )
        })?;
    // The armed holder keys (the deferred request carries no proofs).
    let holder_jwks: Vec<jose_rs::jwk::Jwk> = record
        .pending_holder_jwks
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|v| serde_json::from_value(v.clone()))
        .collect::<Result<_, _>>()
        .map_err(|e| err(Error::invalid_input(format!("armed holder key: {e}"))))?;

    // One issuance routine, two entry points (§7.6): the entries'
    // builders run the `issued` transition internally, exactly as the
    // immediate path does.
    let (entries, metadata) = issue_session_entries(&state, &record, &holder_jwks, now).await?;

    let response = CredentialResponse {
        credentials: entries,
        transaction_id: None,
        interval: None,
        notification_id: Some(record.notification_id.clone()),
        credential_metadata: metadata,
    };
    credential_response(
        &state,
        &headers,
        &response,
        request.credential_response_encryption.as_ref(),
    )
}

// ─── P2: the wallet-initiated authorization-code grant (design §7.2) ─────

use siros_issuer_core::oid4vci::{ParReply, ParRequest, GRANT_AUTHORIZATION_CODE};

/// `POST /op/par` (RFC 9126; ID1 §4.2.2): the wallet pushes its
/// authorization request; the issuer creates a session in
/// AwaitingAuthorization. PKCE is required; the requested credentials ride
/// in `authorization_details` and resolve against the catalog.
/// Accept both RFC 9126 §2.1 form encoding (the suite's shape) and a JSON
/// body, then run the shared validation.
#[allow(clippy::result_large_err)]
pub async fn par(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> HandlerResult<(StatusCode, Json<ParReply>)> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let parsed: std::result::Result<ParRequest, Error> =
        if content_type.starts_with("application/json") {
            serde_json::from_str(&body).map_err(|e| Error::invalid_input(e.to_string()))
        } else {
            // RFC 9126 §2.1 form encoding.
            let params: std::collections::HashMap<String, String> =
                form_urlencoded::parse(body.as_bytes())
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
            serde_json::to_value(&params)
                .map_err(|e| Error::invalid_input(e.to_string()))
                .and_then(|value| {
                    serde_json::from_value(value).map_err(|e| Error::invalid_input(e.to_string()))
                })
        };
    let request = parsed.map_err(err)?;
    par_inner(state, request).await
}

#[allow(clippy::result_large_err)]
async fn par_inner(
    state: AppState,
    request: ParRequest,
) -> HandlerResult<(StatusCode, Json<ParReply>)> {
    if request.response_type != "code" {
        return Err(err(Error::invalid_input(format!(
            "response_type {:?} is not code",
            request.response_type
        ))));
    }
    if request.code_challenge_method != "S256" {
        return Err(err(Error::invalid_input(
            "code_challenge_method must be S256 (PKCE is required)",
        )));
    }
    if request.code_challenge.is_empty() {
        return Err(err(Error::invalid_input("code_challenge is required")));
    }

    // authorization_details (RFC 9396): openid_credential entries naming
    // credential configurations. P2 issues exactly one credential per
    // authorization; more is a refusal, not a guess.
    let mut configuration_ids = Vec::new();
    for detail in &request.authorization_details {
        let typ = detail
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if typ != "openid_credential" {
            return Err(err(Error::invalid_input(format!(
                "authorization_details type {typ:?} is not openid_credential"
            ))));
        }
        let configuration_id = detail
            .get("credential_configuration_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                err(Error::invalid_input(
                    "credential_configuration_id is required",
                ))
            })?;
        configuration_ids.push(configuration_id.to_owned());
    }
    if configuration_ids.is_empty() {
        // §5.1.2: the client requests by scope instead (the OIDF plan's
        // wallet sends scope=pid and no authorization_details).
        let scope = request
            .scope
            .clone()
            .or_else(|| state.scopes_for_client(&request.client_id))
            .ok_or_else(|| {
                err(Error::invalid_input(
                    "neither authorization_details nor a credential scope was given",
                ))
            })?;
        let configuration_id = state.configuration_for_scope(&scope).ok_or_else(|| {
            err(Error::invalid_input(format!(
                "scope {scope:?} maps to no credential configuration"
            )))
        })?;
        configuration_ids.push(configuration_id);
    }
    let [configuration_id] = configuration_ids.as_slice() else {
        return Err(err(Error::invalid_input(
            "exactly one credential per authorization is supported",
        )));
    };

    // Catalog resolution, fail-closed; the issuable formats are dc+sd-jwt
    // and mso_mdoc (design §8.2) — anything else is refused.
    let catalog = state.catalog_snapshot();
    let credential =
        siros_issuer_core::catalog::resolve(&catalog, configuration_id).map_err(err)?;
    if !matches!(credential.format.as_str(), "dc+sd-jwt" | "mso_mdoc") {
        return Err(err(Error::new(
            siros_issuer_core::error::code::UNSUPPORTED_CREDENTIAL,
            format!("credential format {} is not issuable", credential.format),
        )));
    }

    // Registered clients only (design §12.2-resolved): the client_id and
    // redirect_uri must match the registry entry.
    let client = state.clients.client(&request.client_id).map_err(err)?;
    if !client.allow_any_redirect_uri && !client.redirect_uris.contains(&request.redirect_uri) {
        return Err(err(Error::invalid_input(
            "redirect_uri is not registered for this client",
        )));
    }

    // The login URL carries the issuer_state (this session id): only the
    // configured integrator's authorize-complete call completes it.
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS randomness");
    let session_id = siros_issuer_core::session::SessionId::from_random(buf);
    let offer_uuid = random_handle("of_", 16);
    let notification_id = random_handle("ntf_", 16);
    let c_nonce = random_handle("n_", 16);
    let now = now_unix();
    let record = crate::store::SessionRecord {
        id: session_id.clone(),
        grant: siros_issuer_core::session::GrantKind::AuthorizationCode,
        state: siros_issuer_core::session::SessionState::AwaitingAuthorization,
        // Owner is bound by the authorize-complete call (Mode A) or the
        // verified presentation (Mode B) — not by the wallet's PAR.
        owner_subject_id: String::new(),
        credential_configuration_id: credential.identifier.clone(),
        sealed: None,
        offer_uuid: Some(offer_uuid.clone()),
        pre_authorized_code_hash: None,
        transaction_id_hash: None,
        pending_holder_jwks: None,
        identity_match_sealed: None,
        pre_authorized_code_sealed: None,
        tx_code_hash: None,
        tx_code_spec: None,
        auth: Some(crate::store::AuthCodeBinding {
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            code_challenge: request.code_challenge.clone(),
            state: request.state.clone(),
            credential_configuration_ids: configuration_ids.clone(),
        }),
        auth_code_hash: None,
        challenge_jkt: None,
        mode_b: None,
        c_nonce,
        c_nonce_expires_unix: now + state.c_nonce_ttl_seconds,
        status_ref: None,
        notification_id,
        revoked: false,
        created_at_unix: now,
        expires_at_unix: now + 3600,
        refresh_token_hash: None,
        refresh_token_expires_unix: None,
        refresh_dpop_jkt: None,
        history: vec![(now, "awaiting_authorization".to_owned())],
    };
    state
        .sessions
        .insert_par_session(record)
        .await
        .map_err(err)?;

    // RFC 9126 §2.2: 201 Created with request_uri.
    Ok((
        StatusCode::CREATED,
        Json(ParReply {
            request_uri: format!("urn:ietf:params:oauth:request_uri/{offer_uuid}"),
            expires_in: 3600,
        }),
    ))
}

#[derive(Debug, serde::Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub request_uri: String,
}

/// `GET /authorize` (Mode A, design §7.2 step 2): resolve the pushed request,
/// then 302 the browser to the configured integrator login with the
/// issuer_state. An opaque handle is the only thing that crosses.
#[allow(clippy::result_large_err)]
pub async fn authorize(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AuthorizeQuery>,
) -> HandlerResult<Response> {
    let Some(offer_uuid) = query.request_uri.rsplit('/').next() else {
        return Err(err(Error::invalid_input("malformed request_uri")));
    };
    let record = state
        .sessions
        .find_by_offer_uuid(offer_uuid)
        .await
        .ok_or_else(|| err(Error::invalid_input("unknown authorization request")))?;
    let binding = record.auth.clone().ok_or_else(|| {
        err(Error::illegal_transition(
            "session has no authorization binding",
        ))
    })?;
    if binding.client_id != query.client_id {
        return Err(err(Error::invalid_input("client_id mismatch")));
    }
    if record.state != siros_issuer_core::session::SessionState::AwaitingAuthorization {
        return Err(err(Error::illegal_transition(
            "authorization request is not awaiting completion",
        )));
    }

    // 302 to the integrator's login with the issuer_state (design §7.2
    // step 2): an opaque handle is the only thing that crosses.
    let mut login = state
        .login_url
        .clone()
        .ok_or_else(|| err(Error::configuration("no login_url configured for Mode A")))?;
    login
        .query_pairs_mut()
        .append_pair("issuer_state", record.id.as_str());
    Ok((StatusCode::FOUND, [("Location", login.as_str())]).into_response())
}

/// Resource responses echo `x-fapi-interaction-id` when the caller sent
/// one (FAPI2-IMP-2.1.1, folded into the VCI profile's checks — the
/// suite's `EnsureMatchingFAPIInteractionId`).
fn fapi_headers(
    request_headers: &HeaderMap,
    content_type: &'static str,
) -> Vec<(axum::http::HeaderName, String)> {
    let mut headers = vec![(
        axum::http::HeaderName::from_static("content-type"),
        content_type.to_owned(),
    )];
    // FAPI2-IMP-2.1.1: echo x-fapi-interaction-id ONLY when the caller
    // sent one — emitting an empty value makes the suite's
    // skipIfElementMissing treat the present-but-empty key as a value and
    // fail the UUID check.
    if let Some(interaction_id) = request_headers
        .get("x-fapi-interaction-id")
        .and_then(|v| v.to_str().ok())
    {
        headers.push((
            axum::http::HeaderName::from_static("x-fapi-interaction-id"),
            interaction_id.to_owned(),
        ));
    }
    headers
}

/// RFC 7523 §3: the client identifier from the assertion's `iss` claim
/// (no signed `iss` → no identity).
fn client_identity_from_assertion(assertion: Option<&str>) -> Option<String> {
    let assertion = assertion?;
    let payload = assertion.split('.').nth(1)?;
    let claims: Value =
        serde_json::from_slice(&siros_issuer_core::sdjwt_issue::b64u_decode(payload).ok()?).ok()?;
    claims.get("iss")?.as_str().map(str::to_owned)
}

/// Resolve a catalog claim path against the session's subject data
/// (dc+sd-jwt: `[claim]`; mso_mdoc: `[namespace, element]` — the same
/// walk the session-creation schema gate uses, so what was gated is what
/// issues). `None` = the claim is absent (optional claims are skipped).
fn resolve_claim_path<'a>(
    subject: &'a serde_json::Value,
    path: &[Option<String>],
) -> Option<&'a serde_json::Value> {
    let mut cursor = subject;
    for segment in path {
        cursor = cursor.get(segment.as_ref()?.as_str())?;
    }
    Some(cursor)
}

/// Resolve a credential configuration id's format from the live catalog.
fn catalog_format(state: &AppState, configuration_id: &str) -> Option<String> {
    let catalog = state.catalog_snapshot();
    siros_issuer_core::catalog::resolve(&catalog, configuration_id)
        .ok()
        .map(|credential| credential.format.clone())
}

/// mso_mdoc issuance (design §8.2): build the IssuerSigned from the
/// session's subject data (namespace = doctype, elements from the
/// subject's claims), sign the MSO with the issuer key (COSE_Sign1 via
/// One dc+sd-jwt issuance (Final §8.3 `credentials[]` entry): catalog-
/// driven claims, RFC 9901 §10.1 rounded iat/exp (linkability), subject
/// claims concealed unless `sd: "never"`, the status reference recorded and the
/// Issued transition applied. Shared by the single (`/credential`) and
/// batch (`/batch-credential`) endpoints — one call per entry.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
async fn issue_sdjwt_entry(
    state: &AppState,
    record: crate::store::SessionRecord,
    subject: &serde_json::Value,
    holder_jwk: jose_rs::jwk::Jwk,
    status_ref: siros_issuer_core::status_client::StatusRef,
    now: i64,
    time_bucket_secs: i64,
) -> HandlerResult<CredentialEntry> {
    use siros_issuer_core::sdjwt_issue::{issue, IssueSpec, Seg};

    // The catalog credential is the authority on which subject claims
    // become credential claims (design §5: catalog-driven, fail-closed):
    // each claim issues at its own path; anything else in the subject
    // (e.g. a nested mdoc namespace block from a merged integrator
    // payload) never leaks into the credential.
    let catalog = state.catalog_snapshot();
    let credential =
        siros_issuer_core::catalog::resolve(&catalog, &record.credential_configuration_id)
            .map_err(|e| credential_err(state, &e))?;

    // RFC 9901 §10.1: iat/exp MUST be randomized or rounded so that
    // credentials of the same type issued close together cannot be
    // distinguished by their timestamps (the suite's
    // VCIEnsureCredentialTimeClaimsNotLinkable issues twice with a known
    // gap and fails when the embedded times differ by ~that gap). Round
    // down to a bucket; two issuances within one bucket are identical.
    // Batch entries round to a 3600 bucket: the suite's
    // VCIEnsureBatchTimeClaimsNotLinkable treats identical time values
    // shared across a batch as PRECISE (correlatable) unless every
    // value is hour-aligned (its allMatch v % 3600 == 0 acceptance);
    // single issuance keeps the 300 bucket.
    let time_bucket_secs = time_bucket_secs.max(1);
    let iat = now - (now.rem_euclid(time_bucket_secs));
    let exp = iat + state.credential_validity_seconds;
    let mut claims = json!({
        // §12.2.3 byte-identity: the identifier, no empty-path slash.
        "iss": siros_issuer_core::oid4vci::issuer_identifier(&state.issuer_base),
        "iat": iat,
        "exp": exp,
        "vct": record.credential_configuration_id,
        "status": {
            "status_list": {
                "uri": status_ref.list_url.as_str(),
                "idx": status_ref.index,
            },
        },
    });
    // Subject claims are concealed, except those the type metadata declares
    // `sd: "never"` (a rulebook that forbids selective disclosure).
    let subject_claims = siros_issuer_core::catalog::credential_claims(credential, subject);
    let conceal = siros_issuer_core::catalog::concealed_claims(credential, &subject_claims)
        .map_err(|e| credential_err(state, &e))?
        .into_iter()
        .filter(|path| !matches!(path[0].as_str(), "iss" | "iat" | "exp" | "vct" | "status"))
        .map(|path| path.into_iter().map(Seg::Key).collect())
        .collect::<Vec<Vec<Seg>>>();
    claims
        .as_object_mut()
        .expect("claims literal is an object")
        .extend(subject_claims);

    let spec = IssueSpec {
        claims,
        conceal,
        decoys: 0,
        hash: siros_verifier_core::sdjwt::HashAlg::Sha256,
        holder_pub: Some(holder_jwk),
        // The signing chain (leaf first) rides the JWS header: an
        // x5c-resolving verifier (verifier-core's X5cLeaf — the Mode B /
        // flow path) and an entity-keyed trust registry (go-trust's
        // whitelist: the x5c leaf's issuer evidence) resolve the
        // issuer's keys from it. Empty when no signing chain is
        // configured (the StaticKey verification path).
        x5c_der: state.cert_chain_der.clone(),
        typ: "dc+sd-jwt",
    };
    let issued = issue(state.signer.as_ref(), &spec).map_err(|e| credential_err(state, &e))?;

    // Record allocation and the Issued transition.
    state
        .sessions
        .set_status_ref(&record.id, status_ref)
        .await
        .map_err(|e| credential_err(state, &e))?;
    state
        .step(&record.id, SessionEvent::Issued)
        .await
        .map_err(|e| credential_err(state, &e))?;

    Ok(CredentialEntry {
        format: "dc+sd-jwt".to_owned(),
        credential: issued.presentation(),
    })
}

/// the HSM-capable Signer), and answer with the base64url IssuerSigned.
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
async fn issue_mdoc_entries(
    state: &AppState,
    record: crate::store::SessionRecord,
    subject: serde_json::Value,
    device_jwk: jose_rs::jwk::Jwk,
    now: i64,
    time_bucket_secs: i64,
) -> HandlerResult<(
    Vec<CredentialEntry>,
    Option<siros_issuer_core::oid4vci::CredentialMetadata>,
)> {
    use siros_issuer_core::mdoc_issue::{cose_key_p256, MsoBuilder, Validity};
    use siros_issuer_core::zk::SaltPolicy;

    // Fail closed: no revocation handle, no credential (design §9.1) —
    // the allocation happens before any subject data is read. One
    // allocation per entry: batch issuances each get a distinct,
    // unpredictable index (the suite's
    // VCIEnsureBatchStatusListIndicesAreUnpredictable).
    let status_ref = state
        .allocator
        .allocate(None)
        .await
        .map_err(|e| credential_err(state, &e))?;

    // The catalog credential is the authority on namespaces and elements
    // (design §5): mso_mdoc claim paths are [namespace, element]
    // (verifier-core ts11), the subject data nests under the namespace —
    // extra subject keys never leak into the document.
    let catalog = state.catalog_snapshot();
    let credential =
        siros_issuer_core::catalog::resolve(&catalog, &record.credential_configuration_id)
            .map_err(|e| credential_err(state, &e))?;

    // The rulebook (design §8.3 item 5): if this credential is
    // ZK-governed, resolve its salt policy from the circuit catalog
    // (§8.3 item 1 — the catalog is the source of truth for zk issuance
    // parameters; a pin stands in only for a catalog that cannot answer)
    // and derive its auxiliary data. A plain credential has no rulebook.
    let (salt_policy, to_wallet_entries) =
        match state.rulebook_for(&record.credential_configuration_id) {
            Some((name, rulebook)) => {
                let resolution = siros_issuer_core::zk::resolve_salt(
                    state.circuit_manifest.as_deref(),
                    &rulebook.zk_systems,
                    &record.credential_configuration_id,
                    rulebook.pinned_salt_bytes.unwrap_or(0),
                )
                .map_err(|e| credential_err(state, &e))?;
                // A pin must never win quietly (vc `zk_salt.go`):
                if resolution.pin_stood_in_for_unavailable {
                    tracing::error!(
                        rulebook = name,
                        doctype = %record.credential_configuration_id,
                        "zk_circuit_salt_resolution_unavailable_using_pin"
                    );
                }
                if resolution.pin_overrode_catalog {
                    tracing::error!(
                        rulebook = name,
                        doctype = %record.credential_configuration_id,
                        "zk_circuit_salt_pin_disagrees_with_catalog"
                    );
                }
                let entries = derive_to_wallet(&state.zk_seeds, rulebook, &subject)
                    .map_err(|e| credential_err(state, &e))?;
                (resolution.policy, entries)
            }
            None => (SaltPolicy::DefaultSizing, Vec::new()),
        };

    let mut builder = MsoBuilder::new(&record.credential_configuration_id, salt_policy);
    for claim in &credential.claims {
        // Fail closed: a malformed catalog path is refused, never patched.
        let [Some(namespace), Some(element)] = claim.path.as_slice() else {
            return Err(credential_err(
                state,
                &Error::catalog_invalid(format!(
                    "mso_mdoc claim path {:?} is not [namespace, element]",
                    claim.path
                )),
            ));
        };
        // Absent optional claims are skipped; mandatories were gated at
        // session creation.
        let Some(value) = resolve_claim_path(&subject, &claim.path) else {
            continue;
        };
        // ISO 18013-5 element typing for the EUDI PID Rulebook's
        // full-date element: birth_date is `YYYY-MM-DD` under RFC 8943
        // tag 1004 (the suite's fullDate constraint and wallets demand
        // the tag; vc's mdoc.FullDate marshals the same). Everything
        // else takes the JSON→CBOR conversion. Generalizing: element
        // types arrive with MDDL-typed catalog schemas (upstream).
        if element == "birth_date" {
            let Some(date) = value.as_str() else {
                return Err(credential_err(
                    state,
                    &Error::invalid_input("birth_date must be a YYYY-MM-DD string"),
                ));
            };
            builder
                .add_full_date(namespace, element, date)
                .map_err(|e| credential_err(state, &e))?;
        } else {
            builder
                .add_element(namespace, element, value.clone())
                .map_err(|e| credential_err(state, &e))?;
        }
    }
    // The rulebook's commitments become document elements (design §8.3
    // item 3): each to_wallet entry's commitment rides the credential at
    // its path — [namespace, element] for an mdoc rulebook — and the
    // matching opening rides the response (the wallet derives the same
    // opening from its side and verifies the commitment).
    //
    // Issue #43: the claim's CBOR encoding follows the CATALOG's
    // declared value_type — the wire contract the wallets bind. `bstr`
    // carries the raw commitment bytes (the presenter reads ssc as one
    // 32-byte byte string); `tstr` the configured-encoding text; an
    // undeclared or non-carrier type is a REFUSAL at issuance, never a
    // guessed encoding (the leniency that delivered a text ssc past the
    // encoding-aware issuance gate and refused at presentation, after
    // consent).
    for derived in &to_wallet_entries {
        let [namespace, element] = derived.entry.path.as_slice() else {
            return Err(credential_err(
                state,
                &Error::catalog_invalid(format!(
                    "rulebook to_wallet path {:?} is not [namespace, element]",
                    derived.entry.path
                )),
            ));
        };
        let value_type =
            siros_issuer_core::catalog::claim_value_type(credential, namespace, element);
        let form = siros_issuer_core::catalog::commitment_claim_form(
            value_type,
            derived.bytes.clone(),
            derived.text.clone(),
        )
        .map_err(|e| credential_err(state, &e))?;
        match form {
            siros_issuer_core::catalog::CommitmentClaimForm::Bytes(bytes) => {
                builder
                    .add_bytes(namespace, element, bytes)
                    .map_err(|e| credential_err(state, &e))?;
            }
            siros_issuer_core::catalog::CommitmentClaimForm::Text(text) => {
                builder
                    .add_element(namespace, element, serde_json::json!(text))
                    .map_err(|e| credential_err(state, &e))?;
            }
        }
    }
    // The allocated status index rides the response-level credential
    // metadata (the mdoc analogue of the SD-JWT status claim).
    let device_key = cose_key_p256(&device_jwk).map_err(|e| credential_err(state, &e))?;
    // Batch entries: 3600-aligned validityInfo (see issue_sdjwt_entry —
    // the suite's batch time-claim acceptance); single: 300 bucket.
    let validity = Validity::rounded(
        now,
        state.credential_validity_seconds,
        time_bucket_secs.max(1),
    );
    let issuer_signed = builder
        .build(
            state.signer.as_ref(),
            &device_key,
            &state.cert_chain_der,
            validity,
        )
        .map_err(|e| credential_err(state, &e))?;

    // Record allocation + transition, then answer.
    state
        .sessions
        .set_status_ref(
            &record.id,
            siros_issuer_core::status_client::StatusRef {
                list_url: status_ref.list_url.clone(),
                index: status_ref.index,
            },
        )
        .await
        .map_err(|e| credential_err(state, &e))?;
    state
        .step(&record.id, SessionEvent::Issued)
        .await
        .map_err(|e| credential_err(state, &e))?;

    // OID4VCI Appendix A.2: the mso_mdoc credential is the base64url of
    // the IssuerSigned CBOR object.
    let credential_bytes = issuer_signed
        .to_bytes()
        .map_err(|e| credential_err(state, &e))?;
    let credential_b64 = siros_issuer_core::sdjwt_issue::b64u(&credential_bytes);

    // The auxiliary-data extension: openings for the rulebook's
    // commitments (present only for rulebook-governed credentials). The
    // display members (issue #41) attach around this carrier in
    // issue_session_entries when the deployment opted in.
    let metadata =
        (!to_wallet_entries.is_empty()).then(|| siros_issuer_core::oid4vci::CredentialMetadata {
            display: Vec::new(),
            claims: Vec::new(),
            auxiliary_data: to_wallet_entries
                .iter()
                .map(|derived| derived.entry.clone())
                .collect(),
        });
    Ok((
        vec![CredentialEntry {
            format: "mso_mdoc".to_owned(),
            credential: credential_b64,
        }],
        metadata,
    ))
}

/// One derived to_wallet delivery (design §8.3 item 3): the response
/// entry carries the opening, and the commitment rides the credential
/// at the entry's path — in the form the CATALOG's declared
/// `value_type` demands (issue #43): the raw bytes for a `bstr` claim,
/// the configured-encoding text for a `tstr` claim. Which form rides is
/// decided at the write, by the declared type, never here.
pub struct DerivedCommitment {
    pub entry: siros_issuer_core::zk::AuxiliaryDataEntry,
    pub bytes: Vec<u8>,
    pub text: String,
}

/// Derive a rulebook's to_wallet auxiliary data (design §8.3 items 3–4):
/// for each configured entry, derive the opening from the session's
/// subject data (the general derivation vocabulary — HKDF-from-secret,
/// random, claim — chosen by config, not code), compute the commitment
/// (hash_commitment, alg-registered), and hand back both forms: the
/// entry (opening) rides the response; the commitment's credential-claim
/// form is decided at the write by the catalog's declared `value_type`
/// (issue #43 — `bytes` for a `bstr` claim, `text` for a `tstr` claim).
fn derive_to_wallet(
    seeds: &crate::zk_seeds::SeedProviders,
    rulebook: &crate::config::RulebookCfg,
    subject: &serde_json::Value,
) -> siros_issuer_core::Result<Vec<DerivedCommitment>> {
    use siros_issuer_core::zk::{encode_commitment, hash_commitment, AuxiliaryDataEntry, Opening};

    // The derivation inputs are subject claims. mdoc subjects nest
    // under the doctype namespace ({doctype: {claim: value}}); the
    // derivation vocabulary names claims flat. Flatten one level: each
    // top-level object member merges (the namespace subtree for mdoc,
    // the flat claim for dc+sd-jwt) — a nested claim never shadows a
    // flat one carrying the same name.
    let mut claims: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    for (key, value) in subject.as_object().into_iter().flatten() {
        if let Some(nested) = value.as_object() {
            for (name, nested_value) in nested {
                claims.insert(name.clone(), nested_value.clone());
            }
        } else {
            claims.insert(key.clone(), value.clone());
        }
    }

    let mut out = Vec::new();
    for entry in &rulebook.auxiliary_data.to_wallet {
        let opening_cfg = entry.opening.clone().ok_or_else(|| {
            Error::invalid_input("a to_wallet auxiliary entry has no opening configured")
        })?;
        let opening: Opening = match opening_cfg {
            crate::config::OpeningCfg::None => {
                return Err(Error::invalid_input(
                    "a to_wallet auxiliary entry has no opening configured",
                ));
            }
            crate::config::OpeningCfg::Hkdf {
                secret_b64url,
                inputs,
                bytes,
            } => Opening::Hkdf {
                secret_b64url,
                inputs,
                // In-line (vc-shaped) openings carry no domain
                // separation — the fixture vocabulary.
                domain_info: Vec::new(),
                bytes,
            },
            crate::config::OpeningCfg::Random { bytes } => Opening::Random { bytes },
            crate::config::OpeningCfg::Claim { input } => Opening::Claim { input },
            // A SeedProvider ref (§8.3 item 2): the named provider's
            // held secret keys the derivation; `info` (rulebook +
            // credential + transform) rides it with domain separation;
            // `inputs` are the source claims as with an in-line hkdf.
            // Unknown provider = fail-closed, never a default secret.
            crate::config::OpeningCfg::Seed {
                provider,
                info,
                inputs,
                bytes,
            } => Opening::Hkdf {
                secret_b64url: seeds.secret(&provider)?.to_owned(),
                inputs,
                domain_info: info,
                bytes,
            },
        };
        let opening_bytes = opening.open(&claims)?;
        let commitment = hash_commitment(&entry.alg, &opening_bytes)?;
        let encoding = entry.encoding.as_deref().unwrap_or("base64url");
        let commitment_text = encode_commitment(encoding, &commitment)?;
        out.push(DerivedCommitment {
            entry: AuxiliaryDataEntry {
                kind: "hash_commitment".to_owned(),
                alg: entry.alg.clone(),
                path: entry.path.clone(),
                commitment: None,
                opening: Some(siros_issuer_core::sdjwt_issue::b64u(&opening_bytes)),
                required: false,
                // Issue #39: the DELIVERED entry carries only the
                // rulebook's §4.1 type vocabulary — {type, alg, path,
                // opening}; `encoding` is the issuer CONFIG's (and the
                // metadata advertisement's) member, never the response
                // entry's (the opening is base64url by spec fiat). The
                // configured encoding rode the response and every
                // strict wallet refused the receipt check ("the
                // delivered metadata is malformed" — siros-sdk-kotlin's
                // parseDeliveries; the engine's leniency masked it).
                encoding: None,
            },
            bytes: commitment,
            text: commitment_text,
        });
    }
    Ok(out)
}
