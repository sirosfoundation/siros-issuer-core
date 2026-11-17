# SUNET/vc — siros-issuer-core + siros-flow-core gap analysis (issuer aspect)

**Date**: 2026-11-17
**Method**: reconcile vc's **issuer-side** surface (the apigw + the issuer packages)
against the *current* siros-issuer-core + siros-flow-core, per the user's frame:
several apigw features deliberately land in flow-core, so the comparison is vc's
issuer aspect vs **issuer-core + flow-core together**. Each vc feature is placed in
one of four buckets: **COVERED** (with the citation), **DELIBERATE** (out by a
recorded design decision, with the disposition), **FLOW-CORE** (absorbed by the
flow engine rather than the issuer library), or **GAP** (neither covered nor
dispositioned — the actual deltas).

The issuer-core design doc §3.2/§3.3 recorded the v1 scope guards; this document is
the *current-state* reconciliation after every landing (v2 session API, deferred §7.6,
pre-auth strong binding §6.5, the embedded-issuer mode, the wallet drill fixes) and
after flow-core's P-bw1–P-bw3 + notify + the carriers.

---

## A. OID4VCI protocol core — COVERED

| vc | ours | Evidence |
|---|---|---|
| Offers (pre-authorized, auth-code), offer QR/URI pages | Session API → `{offer_uri, deep_link, qr_svg}`; the npm module renders the QR | design §7, P1; `issuance-flow/` |
| `/token` (both grants, PKCE S256, DPoP) | Same | P2; conformance green both grants |
| `/credential`, `/deferred_credential` | Same (deferred = §7.6, single-use arm) | conformance: deferred module PASSED |
| `/nonce` (public nonce) | Same | conformance |
| `/notification` (signed notifications) | Same | P1 |
| Batch issuance (`/batch`, `batch_size`) | Same — the suite's `issuer-batch-issuance` module PASSED on CI (run 43451126802) | conformance |
| `tx_code` | Same | `handlers_oauth_txcode_test` ↔ session store |
| Credential request/response encryption (ECDH-ES) | Same | P1; conformance plain+dpop×encrypted |
| Deferred + grant-type metadata, signed metadata negotiation | Same | conformance `metadata-test-signed` now PASSES |
| Auxiliary data extension (the response's `credential_metadata.auxiliary_data`) | Same (P3/P4, §8.3) | nym_auth e2e |

## B. Authorization-server surface

| vc | ours | Bucket |
|---|---|---|
| PAR, `/authorize`, Mode A login handoff, Mode B `authorization-challenge` (DPoP-bound, jkt enforced at token) | Same — Mode A §7.2 (the redirect handoff), Mode B §7.3 (embedded verifier-core; `presentation_auth.rs`) | **COVERED** |
| **`refresh_token` grant** (RFC 6749 §6, DPoP-bound re-issuance; `handlers_oauth.go:1063`, `openid4vci/token.go`) | Absent. v1 AS = PAR + authorize + token, two grants; §12.1 lists v2 AS hardening without naming refresh | **GAP** — the one AS-surface delta. Recommend: file as the v2 AS item (§12.1 gains it explicitly); scope = a third grant on the existing session machine (the §12.1 discipline: a mode on the state machine, never a parallel path). The realeyes-style deployments that never re-issue don't need it; OIDF-suite coverage exists (the wallet plan's refresh module). |
| AS-wide DPoP | Mode B challenge-endpoint DPoP only; §12.1 (v2) | **DELIBERATE** |
| Wallet-attestation (TS12) *enforcement* on PAR/token | Attestation client-auth exists (WIA headers + `WildcardRulesPolicy`); the PDP-enforced TS12 *policy* gate = §12.1 v2 | **DELIBERATE** (v2) |

## C. Proofs and client auth — COVERED

| vc | ours |
|---|---|
| jwt proofs (ES256), attestation proofs (Appendix D.1, all `attested_keys`) | Same — and the §4 fix now *advertises* both proof types for mdoc (the wallet-engine planning gap found live on realeyes) |
| WIA / key attestation client auth (`oauth-client-attestation` headers) | Same (`verify_attestation_proof_all`, WildcardRulesPolicy) |
| RFC 7523 private_key_jwt client auth | Same (the integrator registry; the gdc live run proved the entity-keyed shape) |

## D. Credential formats

| vc | ours | Bucket |
|---|---|---|
| SD-JWT VC (draft 13 → Final §5.3 incl. `/.well-known/jwt-vc-issuer`) | Same | **COVERED** |
| mso_mdoc (DS cert profile, CRL, tag-1004, x5chain) | Same | **COVERED** |
| W3C VC 2.0 / ECDSA-SD-2023 (`pkg/vc20`, ADR-14, BBS tests) | — | **DELIBERATE**: out for v1 *and likely v2* (§3.2); SD-JWT + mdoc cover the EUDI-relevant formats. vc remains the reference for W3C-VC deployments. |
| BBS / JWP | — | **DELIBERATE**: v2 on the ZK capability layer (§12.2 — a rulebook entry + BBS signing, no parallel subsystem) |

## E. Status and revocation

| vc | ours | Bucket |
|---|---|---|
| Token Status List **JWT** (`pkg/tokenstatuslist`) | draft-ietf-oauth-status-list: the local in-process list (dev) + the deployed siros-status-service contract | **COVERED** |
| Token Status List **CWT** (`pkg/tokenstatuslist/cwt.go`) — the mdoc status form the ARF specifies | The local list is JWT-only (`statuslist+jwt`, flow-core's `local_status.rs`; the StatusRef shape itself is format-agnostic) | **GAP** — the mdoc credentials should carry the CWT status form. Recommend: v2 status item; the `StatusRef {list_url, index}` already carries it, so the work is the CWT *producer* (local list + status-service) and nothing in the issuance path changes. Check verifier-core's CWT status checking for the read side. |
| Registry service (Mongo status store) | Replaced by siros-status-service | **DELIBERATE** (§3.3) |
| TSL checker (`TSL_CHECKER_PLAN.md`) | Trust service lists | **GAP (unexamined)** — vc plans TSL checking as a trust-input hardening; ours has no TSL story on the issuer side. Likely belongs with go-trust (a registry), not the issuer. File for triage rather than close. |

## F. The integrator/backend API — the shape change, largely deliberate

| vc | ours | Bucket |
|---|---|---|
| `POST /api/v1/datastore/preauth_offer`, `/issuance/prepare` (the portal mints an offer from a scope) | `POST /api/v1/issuance/sessions` — the caller supplies the *subject* (claims), PDP-gated, RFC 7523-authenticated | **COVERED** (the §6 session API is the deliberate replacement) |
| Identity mapping (`/mapping`, `/resolve`, `/search`, `/bulk`; the mini-oidc namespace) | Not ported — the caller *has* the claims (it authenticated the user) | **DELIBERATE** (§3.3: "replaced by per-flow subject data"). Note the deployment reality: gdc still runs vc's datastore for the *vc* stack; issuer-core deployments (gdc flow-core, realeyes) resolve nothing — the integrator does. This is the documented complexity reduction. |
| Datastore CRUD (`/api/v1/datastore`, identity PUT/DELETE/list/search) | — | **DELIBERATE** (same) |
| `POST /api/v1/issuance/sessions` with `IdentityMatch` (the §6.5 pre-auth strong binding) | Same — the rule-match-on-names plugin, config-gated | **COVERED** |
| Edu-API (the SIS data-source integration, `EDUAPI_INTEGRATION_PLAN.md`) | — | **FLOW-CORE**: this is the `fetch` step's class (an outbound read-only data pull feeding the issuance subject) — the http-json provider is the general mechanism; an Edu-API-specific provider (its auth + mapping) would be flow-core plugin code. Not started. |
| User lookup / authentic-source resolution (`/user/authentic_source/lookup`) | — | **FLOW-CORE** (same class: a `fetch` provider) |

## G. Auth providers and UIs — DELIBERATE

| vc | disposition (§3.2/§3.3) |
|---|---|
| SAML SP | Integrating application's job; the §7.2 handoff (the live gdc auth-code leg *proves* the pattern: apigw → mini-oidc → consent → back) |
| OIDC RP (`/oidcrp/initiate`, `/oidcrp/callback`) | Same — the login is the caller's redirect |
| Consent pages, admin/dashboard UIs, embedded Alpine.js | Replaced by the npm module + session API |
| WebAuthn login/user management | Wallet-stack/portal concern (in gdc: the wallet-proxy's auth server), never the issuer's |
| Kafka event publishing (`event_publisher.go`) | Not ported (§3.2); SSE/poll; v2 may add streaming behind the same state machine |
| gRPC mTLS surface | Not ported — vc internal infra; ours is the HTTP session API |
| OpenTelemetry | **GAP (minor)** — no tracing story on the service; worth a v2 infra item |
| OpenID Federation (`handlers_openidfederation`) | **DELIBERATE** — v2 (§12.2); vc remains the reference |

## H. Flow composition — absorbed by flow-core (the user's frame)

| vc (apigw glue) | flow-core | Evidence |
|---|---|---|
| Mode B inside the apigw (challenge → present → token) — exactly one hardcoded shape | The `presentation` step (verifier-core in-process) + `bind` + `issuance`, any shape — preauth-pid-issue, ehic-pid-presentation, company-sca (PID+PoA one transaction), token-sourced-attestation (IdP assertion + PID) | flow-core design §6, §13 evidence |
| TS12 payment SCA (the apigw's SCA glue, `TS12_PAYMENT_SCA.md`) | The `payment-receipt` fixture: present PoA + SCA → issue the receipt — data, not code | flows/payment-receipt.yaml |
| The apigw's per-portal orchestration glue | The step vocabulary: `token`/`fetch` (plugin providers), `store`, `notify` (SSE), carriers (deeplink, dc_api, wmp at P-bw4) | flow-core §6.4–6.7 |
| Presentation trust decisions | The PDP at both boundaries (the AuthZEN `issue`/`issuer` actions) — proven live on gdc | the drill; go-trust#245's live repro |

**Note**: the DC API is *ours alone* on the issuer side (vc has it verifier-only); no gap.

## I. ZK / nym_auth — COVERED

| vc | ours |
|---|---|
| ZK salts (`zk_salt.go` precedence), circuit catalog, seeds, openings | `zk/circuit.rs` + `resolve_salt` (vc's precedence verbatim, 18 direction tests), SeedProvider, HKDF commitments, rulebooks as config — nym_auth issues e2e from catalog-resolved salts |
| Native provers (Longfellow/Vega) | Not issuer-side (wallet/verifier; `siros-verifier-zkp`) — **DELIBERATE** (§3.3) |

## J. Infrastructure

| vc | ours | Bucket |
|---|---|---|
| PKCS#11 / HSM signing | `[signing.pkcs11]` (P5, SoftHSM-proven incl. full issuance both formats) | **COVERED** |
| MongoDB session store | `mongo` feature (P5, CAS single-use claims vs real mongod) | **COVERED** |
| Rate limiting | Ported verbatim (vc windows/defaults; 429 + fail-closed 503) | **COVERED** |
| Vault-sealed subject data | The clear/sealed split + PII-flow audit (P5 exit) | **COVERED** (stronger than vc) |
| OpenTelemetry | — | **GAP (minor)** (see G) |

---

## The gap list (the actual deltas)

1. **`refresh_token` grant** — vc has it (DPoP-bound, RFC 6749 §6); ours has neither code nor an explicit v2 line item. → Add to §12.1 as the third-grant item (a mode on the session machine); OIDF wallet-plan coverage exists for the oracle.
   **CLOSED (2026-11-17): implemented** — `[authorization.refresh_token] duration`, vc's semantics (sender-constrained to the issuance-time DPoP jkt, single-use CAS rotation, c_nonce rotation, no-burn ordering, `unsupported_grant_type` when off); §12.1 carries the item and the one documented deviation (the pre-refresh access token lapses at its TTL rather than dying at rotation, as vc's cache swap does). 7 tests; the wallet-plan refresh module remains the future oracle.
2. **CWT status lists for mdoc** — vc produces both JWT and CWT lists; our local list and status-service contract are JWT-only. The ARF form for mdoc. → v2 status item; `StatusRef` already carries it; the work is the CWT producer + the verifier-core read side.
3. **ARF `disclosure_policy` metadata member** — vc embeds `disclosure_policy` (authorized-relying-parties / specific-root-of-trust) in issuer metadata; ours cannot (the suite schema's `unevaluatedProperties:false` warns it). → Needs an ARF-conformance decision: extension member + suite-schema check, or accept the warning. Small, deliberate-todo.
4. **TSL checking** — vc plans it as a trust-input hardening; no story on ours. → triage toward go-trust (a registry), not the issuer.
5. **OpenTelemetry** — no tracing on the service. → v2 infra.

**Not gaps** (verified): W3C VC 2.0, BBS, SAML SP, OIDC RP, consent/dashboards, datastore/identity mapping, Kafka, federation, the registry service — each carries a recorded §3.2/§3.3 disposition that the live deployments (gdc's flow-core, realeyes) have now *exercised* as sufficient: the auth-code leg runs through the caller's login (mini-oidc), the session API supplies the subject, status goes to the status service, and the flow engine composes what the apigw's glue used to.

**The frame confirmed**: the apigw features that were *flow-shaped* (Mode B's presentation-then-issue, payment SCA, per-portal orchestration, data-source pulls) are not issuer-library gaps at all — they landed in flow-core's vocabulary, per the user's framing; the two real protocol deltas (refresh, CWT status) are grant/status hardening on the issuer library itself.
