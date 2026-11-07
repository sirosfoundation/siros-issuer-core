# siros-issuer-core — Design Document

**Status:** Draft — conformance COMPLETE (§16.3): the OIDF OID4VCI issuer
suite passes fully on all four variants (both credential formats × both
grants), and Mode B authorization is implemented and e2e-verified.
**Date:** 2026-11-05
**Owner:** SIROS Foundation / SUNET
**Sponsor input:** Integration feedback on SUNET/vc issuer; verifier experience from siros-verifier-core

---

## 1. Summary

siros-issuer-core is a headless, UI-free credential **issuer** built in Rust, mirroring the
architecture of [siros-verifier-core](https://github.com/sirosfoundation/siros-verifier-core):
sans-I/O core crates, a thin deployable service, and a dependency-free browser module for the
user-experience surface. It replaces the issuance half of the SUNET/vc monorepo for deployments
where that integration pattern has proven too complex — apigw's auth-provider machinery,
central datastore pre-provisioning, and embedded server-rendered UIs.

The defining design decision is a **two-surface integration model**:

1. A **server-to-server issuance session API** — the primary integration surface. The
   integrating application (which has already authenticated the user and holds the claims)
   creates a session, feeds the subject data, and receives an offer handle plus a status
   endpoint. **No personal data ever transits the browser.**
2. A **JS/TS module** (`@sirosfoundation/issuance-flow`) — the UX surface only. It renders
   QR codes, deep links, and W3C Digital Credentials API handovers from opaque handles, and
   polls issuance status. Its entire vocabulary is session IDs, offer URIs, and state
   transitions.

Ecosystem services are composed, not re-implemented:

- **Revocation / status lists** → [siros-status-service](https://github.com/sirosfoundation/siros-status-service)
  (`POST /allocate`, `PATCH /status/{id}/{n}`, `GET /lists/{id}`)
- **Trust decisions** → go-trust PDP over AuthZEN (same pattern as siros-verifier-core and
  siros-status-service's AS)
- **Credential definitions** → TS11 catalog, dynamically resolved (no per-type code)
- **Presentation-based identity binding (v2)** → siros-verifier-core receipts

v1 scope: `dc+sd-jwt` and `mso_mdoc` issuance — including a **general ZK capability layer**
(seed generation/derivation, commitments, circuit-catalog-driven issuance parameters, and a
rulebook abstraction of which `nym_auth` is the first instance) — plus **both issuance
grants**: pre-authorized offers (issuer-initiated) *and* the wallet-initiated
authorization-code grant, whose authorization is one of two modes: an integrator-mediated
login handoff (§7.2) or **wallet authentication via OpenID4VP presentation of an existing
credential** (§7.3, verified in-process by embedded siros-verifier-core crates). Deferred
issuance, status feedback, and full TS11 catalog drive round out v1. BBS/JWP (a ZK-capable
format that will ride the same layer), wallet-attestation enforcement, and federation
remain v2. W3C VC 2.0 is out of scope indefinitely.

**Effort estimate:** ~19–27k LOC Rust + ~2–3k LOC TypeScript; **6–8 person-months** for one
spec-fluent developer, with interop/conformance testing budgeted at parity with development.

---

## 2. Background and motivation

### 2.1 What the "issuer" in SUNET/vc actually is

The issuance functionality in SUNET/vc (≈305k LOC Go, ~900+ PRs, under daily active
development) is smeared across four services:

| Component | LOC | Role |
|---|---|---|
| `internal/apigw` | ~48,600 | OAuth2 AS (PAR, authorize, challenge endpoint, token, DPoP), SAML SP + OIDC RP auth providers, consent/admin/dashboard UIs (embedded Alpine.js), datastore & identity mapping, Kafka events |
| `internal/issuer` | ~7,100 | Thin gRPC signing service (`MakeSDJWT`, `MakeMDoc`, `MakeVC20`, `MakeJWP`, `JWKS`, `GetIACAs`) |
| `internal/registry` + `pkg/tokenstatuslist` + `pkg/status` | ~7,400 | Status list allocation/update/serve; subject↔index registry (Mongo) |
| `pkg/openid4vci` | ~9,000 | OID4VCI protocol: metadata, offers, token, credential, deferred, notification, proofs, ECDHE-ES response encryption |

Plus format code: `pkg/sdjwtvc` (~13.8k), `pkg/mdoc` (~29.2k, much of it ZK machinery),
`pkg/vc20` (~13.5k, W3C), `pkg/model` (~13.3k config incl. TS11 client hookup).

Two structural facts drive this design:

1. **The signing issuer is already thin.** All interesting issuance logic — sessions, offers,
   grants, feedback — lives in apigw, entangled with IAM machinery.
2. **The bulk of apigw is authorization plumbing and UI** — exactly the parts an integrating
   application can own itself.

### 2.2 Integration feedback

Field feedback on the vc issuer integration pattern: *it is complex*. Concretely, an
integrator wanting issuer-initiated issuance must today:

1. Bulk-upload documents into apigw's datastore (`DatastoreBulkUpload`),
2. Maintain identity mappings (`DatastoreAddIdentity`: authentic_source + scope + document_id ↔ person),
3. Get API auth configured on apigw,
4. Mint offers via `preauth_offer` / `PrepareIssuance`,
5. Rely on the registry keeping subject↔status-index rows for later revocation
   (`SaveCredentialSubject`).

That is "operate a mini-IAM before you can issue anything." For the verifier, prioritizing
IAM integration worked and replacing it with a JS/TS interface (`@sirosfoundation/presentation-flow`)
is straightforward for most applications. **For the issuer it is not acceptable to send
sensitive subject data through a browser JS/TS interface** — hence the backend session API
is the primary integration surface, and the JS module is deliberately data-free.

---

## 3. Goals and non-goals

### 3.1 Goals (v1)

- **G1 — Simplified issuance.** Headless issuance driven by a single server-to-server
  session API; the integrating application owns end-user authentication.
- **G2 — Status feedback.** A unified session state machine fed from both the wallet side
  (OID4VCI `/notification`) and the backend side (session status endpoint), consumable by
  the embedding page (poll or SSE).
- **G3 — Externalized status lists.** All revocation state lives in siros-status-service;
  no local status-list service, no subject registry.
- **G4 — UI-free.** No server-rendered UI. A small npm ES module handles QR / deep link /
  DC-API handover and status display from opaque handles.
- **G5 — Catalog-driven credential definitions.** Fully dynamic, TS11-catalog-driven
  credential configurations: adding a (non-rulebook) credential type requires no code
  change. ZK credentials add a small rulebook module on the capability layer (§8.3).
- **G6 — Formats.** `dc+sd-jwt` (SD-JWT VC) and `mso_mdoc` (ISO/IEC 18013-5), including
  a **general ZK capability layer** (§8.3): seeds, commitments, circuit-catalog-driven
  issuance parameters, and a rulebook abstraction — `nym_auth` is the first rulebook,
  not a special case in the code.
- **G7 — Both grants, both authorization modes.** Pre-authorized offers (issuer-initiated
  via the session API, optional `tx_code`) *and* wallet-initiated issuance over the
  authorization-code grant (PAR → authorize → token, PKCE). Authorization for the latter
  is either the integrator login handoff (§7.2) or wallet authentication via OpenID4VP
  presentation of an existing credential (§7.3) — verified by embedded siros-verifier-core
  crates, with trust decided by go-trust. Deferred issuance for slow resolvers.
- **G8 — Trust via PDP.** Trust decisions (which integrators, which credentials, which
  authentic sources) delegated to go-trust over AuthZEN — same boundary as the verifier.
- **G9 — HSM-capable signing.** Credential signing and the status-service client
  assertion go through a signer effect interface; no code path requires private key
  material in memory. An HSM-resident key must be usable for all issuer signatures.

### 3.2 Non-goals (v1)

- **End-user authentication by the issuer.** No SAML SP, no OIDC RP internals, no consent
  pages, no credential store. Subject authentication happens one of two ways: the
  integrating application (§7.2 handoff) or the wallet itself, by presenting an existing
  credential over OpenID4VP (§7.3).
- **OpenID4VP re-implementation.** None: presentation-based authorization (§7.3) embeds
  the siros-verifier-core crates in-process; trust in what was presented is a go-trust
  AuthZEN decision, not a local assumption.
- **AS machinery beyond the two grants/modes.** Wallet-attestation (TS12) enforcement,
  OpenID Federation publishing, and AS-wide DPoP are v2 (§12.1). The v1 AS surface is
  PAR + authorize (handoff or OpenID4VP challenge) + token.
- **W3C VC 2.0.** Out of scope for v1 and likely v2; SD-JWT VC + mdoc cover the
  EUDI-relevant formats.
- **BBS / JWP.** Deferred to v2 — but deliberately designed *for* in v1: BBS is a
  ZK-capable format that will ride the same capability layer (§8.3) — seeds, commitments,
  circuit parameters, rulebook registry — adding only its own signing, not a parallel
  subsystem.
- **Admin GUI, dashboards, embedded UIs.** Replaced by the npm module + the session API.
- **Out-of-process verification services.** v1 does not require a deployed
  siros-verifier-service for issuance authorization — the crates are embedded directly
  (§7.3). A deployed-verifier receipt composition remains possible later (§16).
- **Kafka/event bus.** Status feedback is pull-based (poll/SSE) in v1; event streaming can
  be added behind the same state machine.
- **OpenID Federation publishing.** v2 at the earliest; vc's apigw remains the reference
  for federation-enabled deployments.

### 3.3 Explicit scope guards

The following vc components are deliberately **not** ported. Each is either delegated to the
integrating application, replaced by an ecosystem service, or dropped:

| vc component | Disposition |
|---|---|
| SAML SP, OIDC RP auth providers, consent UI, sessions | Integrating application's job — even in the wallet-initiated grant, login is a redirect handoff to it (§7.2) |
| Datastore pre-provisioning, identity mapping tables | Replaced by per-flow subject data in the session API (§6) |
| Registry service + token status list (Mongo) | Replaced by siros-status-service client (~300 LOC) |
| W3C VC 2.0 (`pkg/vc20`) | Out of scope |
| BBS/JWP | v2 |
| ZK native provers (Longfellow/Vega), circuits, zkvegaworker | Not issuer-side work — wallet/verifier only; already in `siros-verifier-zkp` |
| Kafka inbound/outbound | Not ported |
| Admin GUI, dashboard, embedded Alpine pages | Replaced by npm module |

---

## 4. Architecture

### 4.1 Component overview

```
┌────────────────────┐   session API (S2S, client-assertion + PDP)   ┌──────────────────┐
│ Integrating app    │ ─────────────────────────────────────────────► │ siros-issuer-    │
│ (portal; owns      │ ◄────────────────────────────────────────────── │ service          │
│  user auth, has    │      { session_id, offer_uri, status_url }      │ (Rust, axum)     │
│  the claims)       │                                                └────┬─────────┬──┘
└─────────┬──────────┘                                    OID4VCI (wallet)│         │
          │ embed handle + poll status                                    │         │
┌─────────▼──────────┐                                                     ▼         ▼
│ Browser            │                                          ┌──────────────┐ ┌────────────────┐
│ @sirosfoundation/  │   QR / deep-link / DC-API handover        │    Wallet    │ │siros-status-  │
│ issuance-flow      │ ────────────────────────────────────────►│              │ │service        │
│ (PII-free)         │                                          └──────────────┘ └────────────────┘
└────────────────────┘
                                                        External services also used:
                                                        • go-trust PDP (AuthZEN)
                                                        • TS11 catalog (+ circuit catalog)
```

### 4.2 Crate / package layout

Mirroring siros-verifier-core's workspace discipline (sans-I/O core, thin service, npm module):

```
siros-issuer-core/
├── src/                      # core crates (sans-I/O at protocol boundaries)
│   ├── oid4vci.rs            # OID4VCI data model: metadata, offers, proofs,
│   │                         #   ECDHE-ES response encryption, notification
│   ├── sdjwt_issue.rs        # SD-JWT VC issuance (disclosures, kb constraints)
│   ├── mdoc_issue.rs         # mdoc issuance: COSE_Sign1, digests, device binding,
│   │                         #   validity, MDDL-driven mapping
│   ├── zk/                   # ZK capability layer (§8.3) — general, rulebook-driven
│   │   ├── params.rs         #   circuit-catalog issuance parameters (fail-closed)
│   │   ├── seeds.rs          #   SeedProvider: seed generation + HKDF derivation
│   │   ├── commitments.rs    #   hash_commitment + auxiliary-data machinery
│   │   ├── transforms.rs     #   config-driven derivation transforms + registry
│   │   └── rulebook.rs       #   ZkRulebook abstraction; nym_auth = rulebook #1
│   ├── status_client.rs      # siros-status-service HTTP client (~300 LOC)
│   ├── ts11.rs               # catalog client + config resolution (reuses
│   │                         #   siros-verifier-core ts11.rs vocabulary)
│   ├── session.rs            # issuance session state machine (pure)
│   ├── presentation_auth.rs  # Mode B: OpenID4VP authorization — DCQL request
│   │                         #   construction + presentation verification, embedding
│   │                         #   siros-verifier-core crates (§7.3)
│   └── trust.rs              # AuthZEN query construction (mirrors verifier-core)
├── service/                  # siros-issuer-service (axum; HTTP + storage)
│   ├── api_backend.rs        # §6 session API
│   ├── api_wallet.rs         # §7 OID4VCI wallet surface
│   ├── vault.rs              # sealed subject-data storage, bounded retention
│   ├── store/                # in-memory + optional MongoDB (verifier-core pattern)
│   └── main.rs
├── issuance-flow/            # @sirosfoundation/issuance-flow (npm, dependency-free ES module)
├── ffi/                      # (later) bindings if needed
└── docs/
```

Shared code with siros-verifier-core is consumed, not forked: JOSE stack, SD-JWT disclosure
digest logic, status-list token format, TS 119 602 / VCTM / MDDL schema parsing (`ts11.rs`),
mdoc namespace/element models, and the `siros-verifier-zkp` crate as the canonical wire-format
vocabulary for auxiliary data and circuit-catalog semantics.

### 4.3 Configuration model

Credential definitions come from the TS11 catalog (§8). The service's static configuration is
deliberately small:

```yaml
issuer:
  issuer_url: "https://issuer.example.org"
  signing:
    sdjwt: { key_ref: "sdjwt-issuer-key" }        # secret-manager refs
    mdoc:  { key_ref: "mdoc-issuer-key", iaca_chain_ref: "iaca-chain" }
  catalog:
    registries:
      - mirrors: ["https://catalog.siros.org"]     # ordered, mirrors raced
    refresh: "5m"
  zk:                                          # §8.3 — general capability layer config
    circuits:
      sources: ["https://circuits.siros.org"]   # empty ⇒ fail-closed per-schema
    seeds:                                      # rulebook-scoped, secret-manager backed;
      nym_auth: { key_ref: "seed-nym-auth" }    # long-lived seeds only when a rulebook
                                                # requires cross-issuance continuity
  authorization:                                  # wallet-initiated grant (§7.2, §7.3)
    login_url: "https://portal.example.org/login" # Mode A: integrator handoff target
    issuer_state_ttl: "5m"                       # single-use, unguessable
    pkce: required                               # OAuth 2.1 posture
    openid4vp:                                   # Mode B: wallet presents a credential
      enabled: true                              #   embeds siros-verifier-core (§7.3);
      dpop: required                            #   challenge endpoint is DPoP-bound
  status_service:
    as_url: "https://auth.t.status.siros.org"      # client-assertion AS
    ingestion_url: "https://api.t.status.siros.org"
  pdp:
    url: "https://trust.siros.org"                # go-trust, AuthZEN; fail-closed
  resolvers:                                       # §6.4 pull-model resolvers
    eduapi-x:
      type: http
      url: "https://authsource.example.org/claims"
  session:
    default_ttl: "5m"
    max_ttl: "1h"
    retention_after_final: "24h"                  # bounded, then hard delete
  storage:
    type: mongodb                              # production; in-memory for tests/dev
    uri: "mongodb://mongo:27017"
    database: "issuer_tenant_x"                # deployment isolation, purely from config
```

---

## 5. The issuance session

The session is the central abstraction: it ties together one issuance intent, its subject
data, its offer, its wallet redemption, its status-list index, and its feedback state.

### 5.1 State machine

```
 PRE-AUTH grant (issuer-initiated)     WALLET-INITIATED grant (authorization code)
 session API create (§6.2); offer      PAR → authorize: Mode A — integrator login
 minted immediately                   handoff (§7.2); Mode B — OpenID4VP
                                      presentation (§7.3); session waits
        │                                       │
        ▼                                       ▼
 ┌──────────┐                          ┌──────────────────┐   TTL expiry
 │ offered  │                          │ awaiting_        │────────────► expired
 └────┬─────┘                          │ authorization    │
      │                                └────────┬─────────┘
      │   authorization completes (Mode A call §7.2, or Mode B verified
      │◄── presentation §7.3): subject data settled, code minted, wallet redirected
      │
      │  wallet redeems at /token (pre-auth code | authorization code + PKCE)
      ▼
 ┌──────────┐   slow/async resolver   ┌──────────┐
 │ redeeming│─────────────────────────►│ pending  │
 └────┬─────┘                          │(deferred)│
      │ claims assembled, credential   └────┬─────┘
      │ signed; status index allocated     │ deferred credential completed
      ▼                                    │
 ┌──────────┐ ◄────────────────────────────┘
 │ issued   │
 └────┬─────┘
      │ /notification (credential_accepted | credential_failure | credential_deleted)
      ▼
 ┌──────────┐
 │ accepted │ / failed
 └──────────┘

Any non-final state ──error──► failed   (error class recorded)
Session holds (status_list_id, index) until retention window closes.
```

Transitions are emitted by both surfaces and are the single source of truth for feedback:
the wallet-facing OID4VCI endpoints drive `redeemed → issued → accepted`, the backend-facing
status endpoint exposes the current state. Every transition is logged with a
correlation-safe session handle (no subject data in logs).

### 5.2 Session record

```rust
struct Session {
    id: SessionId,                     // opaque, 128-bit random, unguessable
    credential_config_id: String,       // resolved from catalog
    subject_data: Sealed<SubjectData>,  // encrypted at rest; §6.3
    resolver: Option<ResolverBinding>, // pull-model, §6.4
    grant: GrantKind,                  // PreAuth | AuthorizationCode
    offer: OfferHandle,                // pre-auth code | authorization code (stored
                                       //   hashed), tx_code opt, PKCE challenge,
                                       //   redirect_uri, expiry
    auth: Option<AuthHandoff>,         // wallet-initiated only. Mode A: issuer_state
                                        //   handed to the integrator's login (§7.2).
                                        //   Mode B: OpenID4VP request (DCQL, nonce,
                                        //   DPoP key) + verified presented claims (§7.3)
    status: SessionState,
    status_list: Option<(ListId, u64)>,// filled at issuance
    events: Vec<Event>,                // bounded ring of state transitions
    created_at, expires_at, ..,
}
```

Storage: **pluggable behind the `SessionStore` trait** (`service/src/store.rs`) —
an async trait carrying the full session contract: single-use and atomic
offer/authorization-code/challenge-handle claims, state-machine delegation
(backends store transitions, never invent them), hashed handles, purge
semantics that keep revocation and status feedback alive after the subject
data dies. **MongoDB is the production backend** (`service/src/mongo_store.rs`,
behind the **`mongo` cargo feature** — bson's unconditional
serde_json/preserve_order would change every JSON serialization via feature
unification, so the production backend is opt-in at build time; a build
without the feature refuses a `[storage.mongodb]` config rather than
silently falling back): CAS `find_one_and_update` single-use claims across
replicas, TTL-indexed retention (`retain_at` = final_at + retention,
MongoDB expires natively), nested `record` documents with index-copy
fields, per-op `max_time` bounds — verifier-core `mongo_store.rs` house
style. **`MemoryStore` is the in-memory backend** for tests and
single-process dev, and the reference implementation of the trait. The
binary is single-tenant; deployment/tenant isolation is clean
MongoDB database separation, purely from config (`storage.database`). Multi-replica offer
redemption uses atomic compare-and-set on the pre-authorized code, identical in spirit to
verifier-core's "atomic flow claims." Mongo-suite tests (6) run against a
real mongod (`--features mongo`, skip without one): concurrent-claim
single-use, PKCE refusal+burn, atomic mode-B takes, sweeper phases,
machine delegation, binding expiry.

---

## 6. Backend session API (primary integration surface)

**Audience:** the integrating application's backend. **Auth:** RFC 7523 client assertion
(embedded `jwk` or `x5c`, exactly as siros-status-service's AS accepts — no pre-registration)
with the go-trust PDP deciding whether that key/tenant may issue the requested credential.
Fail-closed on PDP errors.

### 6.1 Endpoints

| Method & path | Purpose |
|---|---|
| `POST /api/v1/issuance/sessions` | Create session (push or pull data; §6.2) |
| `POST /api/v1/issuance/sessions/{issuer_state}/authorize` | Complete a wallet-initiated session after login (§7.2) — same body as §6.2 |
| `GET  /api/v1/issuance/sessions/{id}` | Session status + offer handle (owner only) |
| `GET  /api/v1/issuance/sessions/{id}/events` | SSE stream of state transitions |
| `POST /api/v1/issuance/sessions/{id}/revoke` | Revoke the issued credential (§9.3) |
| `DELETE /api/v1/issuance/sessions/{id}` | Abandon; purge subject data immediately |
| `GET  /api/v1/issuance/sessions/{id}/preview` | Claim **names** from schema — not values |

### 6.2 Create session

```json
POST /api/v1/issuance/sessions
{
  "credential": "urn:eudi:ehic:1",          // vct / doctype / config id; catalog-resolved
  "subject": {                               // PUSH model (default)
    "given_name": "Anna",
    "family_name": "Andersson",
    "birth_date": "1982-07-12",
    "...": "..."
  },
  // ── OR ──
  "data_source": {                            // PULL model (§6.4)
    "resolver": "eduapi-x",
    "ref": "student-90210",
    "on_demand": true                         // false ⇒ resolve eagerly; true ⇒ deferred
  },
  "identity": {                               // optional; correlation for the integrator
    "subject_ref": "user-1234"                // opaque echo metadata; never indexed for
  },                                          // lookup — integrator keeps the mapping
  "grant": {                                  // optional pre-auth tuning
    "tx_code": { "length": 6, "input_mode": "numeric" },
    "ttl_seconds": 300
  },
  "metadata": { "integration_ref": "..." }    // echoed in events; correlation
}
```

Response:

```json
{
  "session_id": "s_9f86d081...",
  "state": "offered",
  "offer_uri": "https://issuer.example.org/credential-offer/of_7c3a...",
  "qr_svg": "data:image/svg+xml;base64,...",       // rendered by the service, or by the module
  "wallet_redirect": "openid-credential-offer://?credential_offer_uri=...",
  "expires_at": "2026-11-05T12:35:00Z",
  "status": "/api/v1/issuance/sessions/s_9f86d081.../events"
}
```

Validation: `credential` resolves against the TS11 catalog **and** is permitted for this
caller by the PDP (the AuthZEN query covers tenant × credential × authentic-source triple,
mirroring vc's `authentic_source` authorization lesson). `subject` claims are validated
against the catalog schema before the offer is minted — never after the wallet redeems.

### 6.3 Subject-data vault (push model)

- Claims arrive over the authenticated S2S channel and are **sealed** (authenticated
  encryption with a service-held key) before touching storage.
- Deleted on `failed`, `expired`, `DELETE`, or after `retention_after_final`.
  Bounded retention is enforced by a sweeper — the same discipline as verifier-core's
  sealed one-time results (`SessionStore::sweep`, a background interval in the
  service). `accepted`/`deleted` sessions KEEP their sealed data until the hard
  delete: they stay **re-issuable** (§13.3 multiple accesses — the suite's
  additional-requests module re-issues after `credential_accepted`; reconciled
  with §6.3 by letting retention, not the acceptance event, end re-issuance).
  Failed/expired purge immediately (non-reissuable finals). The record skeleton —
  status feedback, revocation handle — survives every purge and dies only at the
  hard delete.
- Subject claims are **never** logged, never included in wallet responses beyond the
  credential itself, and never exposed on any GET surface. The preview endpoint returns
  the schema's claim **names** only, for consent-style UX if the integrating app wants it.

### 6.4 Pull-model resolvers

```rust
#[async_trait]
pub trait Resolver: Send + Sync {
    fn id(&self) -> &str;
    async fn resolve(&self, subject_ref: &str, credential: &CredentialType)
        -> Result<SubjectData>;
}
```

- v1 ships an HTTP resolver: the issuer calls the configured endpoint with a signed request
  (client assertion of the issuer's own key), receiving claims scoped to the requested
  credential type. This is where EduAPI-style external authentic sources attach, per
  deployment — replacing vc's central datastore pre-provisioning.
- `on_demand: true` produces a session in `offered` state with data resolved at wallet
  redemption; a slow resolver naturally yields the **deferred** issuance path (§7.6).
- Resolver failure classification: transient (session → `pending`, wallet told to retry) vs
  permanent (session → `failed`, wallet told `unsupported_credential_format`-style terminal
  error per OID4VCI §7.6 semantics).

### 6.5 Identity binding (who may redeem)

- **v1, pre-auth grant:** short-TTL one-time pre-authorized code (default 5 minutes,
  single-use, atomic claim), optional `tx_code`. The offer *is* the authorization; TTL +
  single-use bounds abuse.
- **v1, authorization-code grant, Mode A:** the session is bound by the integrator's
  completed login handoff (§7.2) — the integrator asserts who the credential is about at
  the authorize-complete call, and the code is PKCE-bound to the wallet that
  PAR-requested it. Binding strength equals the integrator's own login strength.
- **v1, authorization-code grant, Mode B:** the strongest v1 binding — the redeeming
  wallet has cryptographically presented a trusted credential about the subject
  (verified in-process, trusted via go-trust, §7.3). No identity_match ceremony is needed
  because the presentation *is* the binding.
- **v2:** strong binding for the *pre-auth* grant — require a PID presentation (vc's
  `PrepareIssuance.identity_match` semantics: required, not omittable) before token
  issuance, via the embedded verifier-core crates or a deployed verifier receipt.

---

## 7. OID4VCI wallet surface

The wallet-facing HTTP surface (all served by siros-issuer-service):

| Endpoint | Notes |
|---|---|
| `GET /.well-known/openid-credential-issuer` | Generated **entirely from catalog** (§8); includes `credential_configurations_supported`, display, encryption, pre-auth grant |
| `GET /.well-known/oauth-authorization-server` | v1: pre-auth + authorization_code (PAR, PKCE); challenge endpoint is v2 |
| `GET /jwks` | SD-JWT + status-token-usage JWKS |
| `GET /iacas` | mdoc IACA chain(s) |
| `GET /type-metadata/{scope}` | Serves VCTM per TS 119 602 with SRI validation |
| `GET /credential-offer/{uuid}` | Offer-by-URI for QR flows (vc-compatible path) |
| `POST /nonce` | OID4VCI c_nonce endpoint |
| `POST /op/par` | Pushed Authorization Requests (wallet-initiated grant) |
| `GET /authorize` | Mode A: 302 to the integrator's `login_url` with `issuer_state` (§7.2) |
| `POST /authorization-challenge` | Mode B: OpenID4VP-based authorization, DPoP-bound (§7.3) |
| `POST /token` | Both grants; PKCE required for authorization_code |
| `POST /credential` | Immediate issuance |
| `POST /deferred_credential` | Deferred issuance (§7.6) |
| `POST /notification` | `credential_accepted` / `credential_failure` / `credential_deleted` → session state machine |

### 7.1 Grants (v1)

Both OID4VCI grants are supported:

- **Pre-authorized code** (issuer-initiated): minted at session creation, stored hashed,
  single-use, atomically claimed, bound to the session. `tx_code` optional, constant-time
  compared.
- **Authorization code** (wallet-initiated): the wallet PAR-requests, then authorizes —
  via the integrator login handoff (Mode A, §7.2) or an OpenID4VP presentation
  (Mode B, §7.3). Codes are single-use, short-TTL, PKCE-bound, and redirect-bound.

(vc registers both `credential_offer` trailing-slash variants and wwWallet compatibility —
port those details; they're cheap.)

### 7.2 Wallet-initiated grant, Mode A: the login handoff

The AS surface is deliberately minimal — no auth-provider plugins, no consent pages.
Subject authentication happens one of two ways: the integrator login handoff (Mode A, this
section) or an OpenID4VP presentation by the wallet (Mode B, §7.3). The "IdP" in Mode A is
the integrating application:

1. Wallet → `POST /op/par` (`client_id`, `authorization_details` naming credential
   configurations, `redirect_uri`, PKCE challenge). The issuer creates a session in
   `awaiting_authorization` and returns a `request_uri`.
2. Wallet → `GET /authorize?client_id&request_uri`. The issuer 302s to the deployment's
   configured `login_url` with a one-time `issuer_state` — an opaque handle is the only
   thing that crosses this boundary.
3. The integrating application authenticates the user however it already does, then
   calls (S2S, client assertion + PDP):
   `POST /api/v1/issuance/sessions/{issuer_state}/authorize` with the same body shape as
   §6.2 (push or pull subject data). This call is where "who the credential is about"
   is asserted.
4. The issuer mints the single-use authorization code and returns the wallet redirect
   URL; the integrator 302s the browser to `redirect_uri?code=...&state=...`.
5. Wallet → `POST /token` (code + PKCE verifier) → access token + `c_nonce`; then
   `POST /credential` exactly as in the pre-auth flow.

Properties:

- `issuer_state` is unguessable, single-use, short-TTL (default 5 min), rate-limited.
- PAR and token are rate-limited per endpoint (port vc's defaults).
- PKCE required for all clients (OAuth 2.1 posture); DPoP binds the Mode B challenge
  endpoint (§7.3) and is v2 elsewhere (§12.1).
- Both grants converge on the **one** session state machine — the handoff is simply the
  wallet-initiated way a session acquires subject data, mirroring §6.2 for
  issuer-initiated flows.
- Consent, where a deployment needs it, is rendered by the integrating application in
  step 3 (it may call the §6.1 preview endpoint for claim names); the issuer never
  renders consent UI.

### 7.3 Wallet-initiated grant, Mode B: authorization via OpenID4VP presentation

The wallet must also be able to authenticate the subject *itself* by presenting an
existing credential — the vc "Path 2" pattern (`auth_provider: openid4vp` plus its
authorization-challenge endpoint), and the natural issuance path for derived credentials
(e.g., nym_auth derived from a presented PID, §8.3).

Mode selection is catalog-driven: each credential configuration lists its accepted
authorization modes (`handoff`, `openid4vp`), generalizing vc's per-scope `auth_provider`.

1. Wallet → `POST /op/par`; the issuer creates a session in `awaiting_authorization`
   and derives a **DCQL query from the credential configuration's required claims** —
   the same catalog metadata that drives issuance drives the request.
2. Wallet → `POST /authorization-challenge`, DPoP-bound (port vc's
   `handlers_oauth_challenge.go` semantics): the issuer returns a signed OpenID4VP
   authorization request (redirect or same-device direct_post).
3. The wallet presents the credential (e.g., PID). The issuer verifies the presentation
   **in-process via the embedded siros-verifier-core crates** — request construction,
   SD-JWT VC / mdoc cryptographic verification, and status-list checks are library
   calls; **trust in the presented credential is a go-trust AuthZEN decision**, never a
   local assumption. No OpenID4VP code is re-implemented.
4. Verified presented claims become the session's subject data (optionally merged with
   resolver output keyed on presented identity). The issuer mints the authorization
   code and the flow converges with Mode A at steps 4–5 of §7.2.

Mode B is the strongest v1 identity binding (§6.5) and the path that lets a deployment
run fully wallet-facing: a credential whose claims derive entirely from presented
credentials needs no integrating application mid-flow at all — the portal remains only
the initiator and status observer.

### 7.4 Proof handling

- JWT proof (ES256) with `nonce` binding, `aud` = credential issuer, `iat` skew window.
- mdoc attestation proofs (`proof_type=attestation`) for mso_mdoc configurations.
- v2 adds DIVP/`proof_attestation` per vc's `proof_divp.go`/`proof_attestation.go`.
- All nonce/token stores are replay-protected (single-use c_nonce, bounded lifetimes),
  mirroring vc's `nonce.go`/`token.go` semantics.

### 7.5 Response encryption

ECDHE-ES (`credential_response_encryption` in metadata; `alg=ECDH-ES`, `enc=A128GCM`
default). **On the DC-API path the browser only ever brokers ciphertext** — the credential
response is end-to-end encrypted to the wallet key from the proof. This is a load-bearing
privacy property for the "sensitive data must not transit the page" requirement; the JS
module never sees claims even in encrypted handovers, and we state this in the module docs.

### 7.6 Deferred issuance

- Session in `pending` state returns a `transaction_id` per OID4VCI §9; the wallet polls
  `deferred_credential`; completion transitions the session to `issued` exactly once.
- `transaction_id` is unguessable, single-issuance, atomic (compare-and-set), with the
  same `interval` guidance vc emits.

### 7.7 Notification → feedback

`/notification` events map onto the session state machine (`credential_accepted` →
`accepted`; `credential_failure` → `failed`; `credential_deleted` → recorded, index kept for
retention). The embedding page observes the same transitions through §6.1 — **one state
machine, two audiences.**

---

## 8. Credential definitions: TS11 catalog drive

### 8.1 Resolution pipeline

```
TS11 catalog (mirrors, raced)                    circuit catalog (zk_circuits.sources)
   │  SchemaPage → RegistryDocument                │  per zk_system/doctype
   ▼                                               ▼
CredentialType (vct / doctype) ◄─── reused parsing from siros-verifier-core ts11.rs
   │
   ├─ sd-jwt vc  → VCTM (TS 119 602) → claim map, display, SRI-verified
   ├─ mso_mdoc   → MDDL           → namespaces, elements, mdoc display, IACA ref
   └─ zk systems → zk_systems + zk_salt_bytes (schema pin) OR catalog resolution (§8.3)
   ▼
CredentialConfiguration (OID4VCI metadata entry)  ← generated, cached, SRI-checked
   ▼
Claims mapping: subject_data → claims (schema-ordered, type-checked)
```

- Catalog is refreshed on a timer and on-demand per session creation; SRI verification
  (already implemented in Rust) validates schema bodies.
- A credential absent from the catalog cannot be issued — **fail closed**.
- Adding a credential type = adding it to the catalog. No deployment change, no code.

### 8.2 Formats v1

**dc+sd-jwt (SD-JWT VC).** Issuance: claim flattening/structuring per VCTM, selective
disclosure digest list (SHA-256, reusing verifier-core's disclosure logic in reverse),
`kb` constraints, `status` block referencing the siros-status-service list URL + index.
~1–2k LOC.

**mso_mdoc (ISO/IEC 18013-5).** COSE_Sign1 (ES256) with `x5chain`, `IssuerSigned` digest
computation with per-element salts, `DeviceKeyInfo` binding, `validityInfo`, MDDL-driven
namespace/element mapping, status reference embedding. Salt policy: **random salts for
non-ZK doctypes; catalog-pinned lengths for ZK doctypes — one code path, two policies.**
~3–5k LOC; round-trip cross-checked against verifier-core's mdoc parser in tests.

### 8.3 ZK capability layer (general) — v1; nym_auth is the first rulebook

ZK support is **not** an nym_auth feature. nym_auth is one rulebook on top of a general
capability layer that must support a wide range of ZK credentials and rulebooks — including
a future BBS implementation. The issuer never proves anything; native Longfellow/Vega
machinery is wallet/verifier-side (already in `siros-verifier-zkp`). The issuer-side
capabilities:

1. **Circuit-catalog issuance parameters** (vc's `internal/issuer/apiv1/zk_salt.go`
   semantics, generalized): any schema may declare `zk_systems`; the circuit catalog is
   the source of truth for the issuance parameters those systems require — today the
   `IssuerSignedItem` salt length, tomorrow whatever a new system publishes. The
   fail-closed/pin-override order is ported **verbatim**:
   - No `zk_systems` in schema → schema's `zk_salt_bytes` (normally 0) used as-is.
   - `zk_systems` declared → catalog resolves. Catalog unreachable or system unknown →
     the schema's **pinned** value may stand in (logged at error).
   - Catalog reachable and authoritative but refusing (withdrawn circuit, constraint
     violation, malformed metadata) → **refuse issuance**; a pin never overrides a live
     refusal. A credential minted with a wrong salt length fails opaquely in the wallet's
     hands at presentation time — vc learned this the hard way ("a fleet of credentials
     came to fail Vega verification on every claim") and the port must preserve it.
   Resolution is a per-`zk_system` lookup keyed by (system, doctype); new systems and new
   published parameters extend the catalog, not the code.

2. **Seed capability** (`SeedProvider`): generation and derivation of the secrets
   rulebooks need. vc's two existing shapes — `pseudonym_seed` (a random seed attached as
   a claim) and rulebook seed *files* (`secret_path` + HKDF over `inputs`) — generalize to:
   - `generate(scope) -> Seed`: random seed per session, subject, or tenant; optionally
     attached as a claim (pseudonym seeds) or used only as an HKDF secret.
   - `derive(ref, info, inputs, bytes) -> bytes`: HKDF with **domain separation** (`info`
     binds rulebook + credential + transform), backed by secret-manager refs for
     rulebooks requiring cross-issuance continuity, or ephemeral in-session seeds sealed
     with the subject vault (§6.3) otherwise.
   - Rotation and key separation are part of the trait contract; seeds are never logged.

3. **Commitment / auxiliary-data capability**: general `hash_commitment` issuance —
   alg-registry (sha-256 today), commitments placed in the credential, openings returned
   out-of-band with issuance per the auxiliary-data extension (vc
   `pkg/openid4vci/auxiliary_data.go`). A **rulebook** decides *which* claims are
   committed, at which paths, with which algs and openings; the mechanism itself is
   rulebook-agnostic. Wire formats are pinned per rulebook with `siros-verifier-zkp` as
   arbiter.

4. **Derivation engine** (vc `presentation.derivations` generalized): config-driven
   transforms over session subject data — `copy` and `hash_commitment` (HKDF-from-seed
   openings) today, behind a **pluggable transform registry** so rulebooks can register
   new primitives without core changes.

5. **Rulebook abstraction** (`ZkRulebook`): the bundle that makes a credential
   ZK-provable — credential type(s), `zk_systems`, commitment/auxiliary-data entries,
   derivations, seed usage, and presentation-time expectations. **nym_auth is rulebook
   #1:** `eu.europa.ec.eudi.nym_auth.1` doctype, birthdate/country/PAN derivations
   (copy + hash_commitment/HKDF) — whose inputs arrive, in wallet-initiated Mode B, as
   verified presented-PID claims (§7.3), the vc-shaped path — plus `ssc`/`psc`
   commitments, the digestid wire extension (vc `ZK_VEGA_DIGESTID_WIRE_EXTENSION.md`),
   `pseudonym_seed`.

   A rulebook is **data conceptually but code in substance**: it ships as a small,
   well-typed Rust module implementing the capability traits above, plus whatever config
   and catalog schema entries it needs. The catalog remains purely about schemas from the
   point of view of the code; where rulebook definitions are governed is therefore not
   this design's concern — a rulebook translates to code and sometimes config, or both.
   The exit criterion for the abstraction is that a *second* rulebook requires only a new
   module against the capability traits, touching no capability code.

BBS (v2) targets this layer by design: a ZK-capable format whose issuance needs the same
seeds, commitments, and catalog-parameter capabilities, plus BBS-specific signing — an
entry in the rulebook/format registry, not a parallel subsystem.

**Implementation status (P3):** the layer is built and green. `zk/circuit.rs` is the
general circuit catalog (camelCase catalog JSON; resolution per system×doctype with
every refusal direction tested); `resolve_salt` is vc's `zk_salt.go` precedence verbatim
— the pin direction included: a pin stands in only for a catalog that cannot answer,
wins but logs against a live disagreement, and never overrides a live refusal. Rulebooks
are general `[zk.rulebooks.<name>]` config data (credentials, `zk_systems`, optional pin,
auxiliary-data plan with the `hkdf`/`random`/`claim` derivation vocabulary); a second
rulebook needs no code changes unless it needs a new derivation primitive — the exit
criterion above, met by construction. nym_auth (rulebook #1) issues end-to-end with
vega-mc's 32-byte salt resolved from the catalog fixture and the ssc commitment/opening
pair verified in CI. Deferred: `auxiliary_data_supported` in the issuer metadata (the
OIDF schema branch has no room; the openings ride the response's
`credential_metadata.auxiliary_data`), the `SeedProvider` generalization (the fixture
seed is in-line config, production rulebooks want secret-manager refs), and `to_issuer`
entries (wallet commitments from proofs) — all v2-line items. The storage layer is
pluggable behind the async `SessionStore` trait (§4.3), `MemoryStore` the reference
implementation.

### 8.4 Out of scope formats

W3C VC 2.0 (indefinitely). BBS/JWP is v2, implemented **on** the ZK capability layer
(§8.3); vc's `MakeJWP` is the signing reference.

---

## 9. Status lists and revocation

### 9.1 Allocation

At credential-signing time the issuer calls siros-status-service:

```
POST {ingestion}/allocate            (client assertion → AS token; §14 auth)
→ { "list_url": ".../lists/<id>", "index": <n>, "exp": "..." }
```

The `(list_url, index, exp)` triple is stored on the session and embedded in the credential
(`status` block for SD-JWT; mdoc equivalent as vc does today). **Credential validity is
aligned with the allocated index's `exp`** — the status service's `MAX_EXPIRY` is the outer
bound on credential lifetime.

### 9.2 Why this replaces the vc registry

vc's registry (~7.4k LOC Go + Mongo + gRPC) exists to allocate/serve status lists and keep
`SaveCredentialSubject` rows mapping subject → (section, index). Here: allocation is an API
call (~300 LOC client), list serving is the status-service's job, and the **session record
replaces the subject registry** — bounded retention instead of standing PII mappings.

### 9.3 Revocation API

`POST /api/v1/issuance/sessions/{id}/revoke` (owner-only, PDP-checked) issues:

```
PATCH {ingestion}/status/{list_id}/{index}   { "status": "INVALID" }
```

Revocation is **by session id only**. There is deliberately no subject-indexed lookup:
**integrators retain their own session↔subject mapping** — the issuer holds no standing
subject index at all, which keeps the vault strictly per-flow (§6.3). The session's
optional `subject_ref` (§6.2) is echo metadata for correlation, never a lookup key.
Suspension (`SUSPENDED`/`RESUME`) maps to the same call with different status bits.

---

## 10. The JS/TS module: `@sirosfoundation/issuance-flow`

The UX surface — deliberately the *smallest* part of the system, and **PII-free by
construction**.

```ts
import { IssuanceFlow } from "@sirosfoundation/issuance-flow";

const flow = new IssuanceFlow({
  root: document.querySelector("#issuance"),
  getSession: (id) => fetch(`/api/issuance/${id}`).then(r => r.json()),  // backend proxy
  invocations: ["qr", "dc-api", "deep-link"],
  onPreview: (handle) => myApp.renderConsent(handle), // optional callback (§10.2.5)
});
flow.render(handle);   // handle = { session_id, offer_uri, wallet_redirect }
```

### 10.1 Invariants

- Module **never** receives or requests claim values. Input vocabulary:
  `session_id`, `offer_uri`, `wallet_redirect`, `expires_at`, state labels.
- Preview (if the app enables it) shows catalog claim **names** only.
- The browser on DC-API paths brokers ciphertext only (§7.5).
- The module is dependency-free ES module, framework-agnostic, with the same backend-contract
  documentation pattern as the tunnelbana plugin assets.

### 10.2 Responsibilities

1. Offer display: QR (from served SVG or client-side), `openid-credential-offer://` deep
   link, platform wallet links.
2. DC-API invocation: same-device issuance via the **existing `@sirosfoundation` npm
   DC-API shim layer** — used and evolved here, not forked — with graceful fallback to
   QR when the API is unavailable. The shim absorbs cross-browser API variance so
   neither the issuer module nor `presentation-flow` re-implements it.
3. Status: **SSE ships in v1** (decided), with simple polling as the fallback path; render
   the §5.1 state machine's user-visible subset: `offered → (pending) → issued →
   accepted / failed / expired`.
4. Completion UX: success/failure rendering from state labels + error codes only.
5. **Optional preview/consent hook:** the module accepts an optional JS callback
   (`onPreview(handle)`) supplied by the embedding app. The module calls it at the right
   moment; the app renders preview/consent from **its own** data — it holds the claims.
   The module itself still never touches claim values; the issuer's preview endpoint
   (§6.1) supplies claim *names* if the app wants them.

### 10.3 What it does not do

No OID4VCI protocol logic, no crypto, no claim handling, no trust decisions — the backend
is authoritative for all of it, exactly as `presentation-flow` leaves DCQL validation,
request signing, trust and verification to the verifier.

---

## 11. Trust and security boundary

| Concern | Owner |
|---|---|
| End-user authentication | Integrating application |
| Integrator authentication | Client assertion (RFC 7523, `jwk`/`x5c`) at the issuer, verified; no pre-registration |
| Trust decision (may this tenant issue this credential from this source?) | go-trust PDP over AuthZEN — **fail closed** on any PDP error |
| Wallet trust (attestation policy, TS12, etc.) | v2 — delegated to PDP policy inputs, mirroring verifier-core's boundary: *cryptographic validity is not a trust decision* |
| Key management | Secret-manager refs; SD-JWT and mdoc keys distinct; rotation via JWKS `kid`; **signing through the signer interface (§11.1) — HSM-resident keys supported, private material never required in memory** |
| Subject data | Sealed at rest, bounded retention, never logged, never on any GET surface |
| Replay | Single-use pre-auth codes, single-use c_nonces, atomic session claims; atomicity via store CAS (in-memory or Mongo) |
| Rate limiting | Per-endpoint limits on wallet surface (credential/deferred) — port vc's defaults as config |
| Transport | TLS terminated upstream (verifier-core convention); no plaintext issuer_url in production config (startup check) |

**Threat-model notes carried over from vc's hardening:** the session API never reads
authorization-relevant fields from headers (vc's `PrepareIssuance` lesson: header binding
fallback smuggled scope past the auth middleware); the PDP query is built from the exact
fields the handler acts on; pre-auth offers for credentials whose PDP verdict is missing
are refused at session creation, not at redemption.

### 11.1 Signing boundary and HSMs

All issuer signatures — SD-JWT (and later mdoc) credential signing, and the
siros-status-service client assertion — cross one **signer effect interface**:
`sign_es256(header, payload) → compact JWT` plus `public_jwk()`. Two rules follow:

1. **No code path may require private key material in memory.** The core and
   service code against the trait only; an HSM-resident key must be usable for
   every issuer signature without export. Public keys (JWKS, PDP evidence,
   thumbprints) are public material and may be held or configured in the clear.
2. **Providers, not flags.** The in-memory JWK signer is one provider (dev,
   tests, and deployments using key files); the production provider is PKCS#11
   via kryptering's `cryptoki` feature — the same stack verifier-core uses for
   ReaderAuth with the host's long-term key. Selecting a provider is
   configuration; nothing else changes.

Consequences for the design's other pieces: `kid`s are configured or read from
the HSM's public handle (never derived from private material); key rotation
stays a JWKS `kid` rotation; the signer interface is part of the core's stable
surface (`src/signer.rs`), so the PKCS#11 provider can land in P5 without
touching issuance code. The interface lands with the P1 signing work —
retrofitting an in-memory key assumption out of a live protocol is the
expensive way to do this.

---

## 12. v2 and beyond

### 12.1 Advanced AS features

Both grants and both authorization modes (§7.2, §7.3) are v1. What remains v2 is the
hardening around them: wallet-attestation (TS12) enforcement on PAR and token
(PDP-enforced); AS-wide DPoP beyond the Mode B challenge endpoint; OpenID Federation
publishing; and the strong-binding requirement for the *pre-auth* grant (§6.5). These are
additive policies on the same AS surface, not new flows. The discipline that keeps this
tractable — vc-apigw's 48.6k LOC lives mostly in auth-provider *plugins* (SAML SP, OIDC RP,
consent, session machinery), and the v1 design has exactly two modes and no plugins —
must survive v2: new auth capability enters as a mode on the existing session state
machine, never as a parallel path.

### 12.2 Other v2 items

- BBS/JWP issuance — as a ZK-capable format **on** the capability layer (§8.3): a new
  rulebook entry plus BBS-specific signing (`MakeJWP` reference), reusing seeds,
  commitments, and catalog parameters.
- Strong binding for the *pre-auth* grant (§6.5): require a PID presentation before token
  issuance — via the already-embedded verifier-core crates (§7.3), so the marginal cost
  is policy, not code.
- OpenID Federation entity statements (federation-enabled deployments use vc meanwhile).
- Wallet attestation policy on token issuance (TS12; PDP-enforced).
- Event streaming (Kafka) behind the state machine for observability-only consumers.
- Per-tenant catalog overrides (vc's ordered logical-registries semantics).
- UniFFI bindings if native embedding is requested.

---

## 13. Effort, phasing, and testing

### 13.1 Phasing

| Phase | Content | Exit criterion |
|---|---|---|
| **P0 — Skeleton** (2–3 wks) | Workspace, service shell, session store (memory), client-assertion auth + PDP wiring, TS11 catalog load, metadata generation | `/.well-known/openid-credential-issuer` served from live catalog |
| **P1 — SD-JWT VC, pre-auth grant** (3–4 wks) | Pre-auth grant, offers, nonce, proofs, credential endpoint, ECDHE-ES, status-service integration, session API (push), notification, status/SSE | End-to-end issuer-initiated issuance to a reference wallet; revocation through status-service verified by verifier-core |
| **P2 — Wallet-initiated grants** (4–6 wks) | PAR, Mode A authorize handoff + authorize-complete call, Mode B OpenID4VP challenge (embedded verifier-core), token endpoint, PKCE/DPoP, pull-model resolver, deferred issuance | EUDI reference wallet completes wallet-initiated issuance **both** through a demo-portal login **and** via PID presentation; both modes share the one state machine |
| **P3 — mso_mdoc + ZK capability layer** | `mdoc_issue.rs` (COSE_Sign1 via the Signer trait, MSO builder with **RFC 8943 tag-1004 full-date typing**, digests, RFC 9901-rounded validityInfo) and `zk.rs` (salt policy, HKDF/hash commitments, auxiliary data) built and **oracle-verified** (verifier-core round-trip, plain + nym_auth-rulebook with the pinned 32-byte Vega salt). Service wiring: attestation-proof parsing (Appendix D.1 — ES256-pinned as advertised, `x5c`-leaf self-consistency via jose_rs, `aud` checked only when present: the OIDF suite's attestation carries iat/exp/attested_keys/nonce and no aud), proof dispatch **decoupled from the credential format** (coupling masked `invalid_nonce` with the attestation path's typ refusal — regression-tested), the `issue_mdoc` branch (status allocation, base64url IssuerSigned per Appendix A.2, response encryption, x5chain from `signing.cert_chain_path`), catalog-driven claim/element building for **both** formats (dc+sd-jwt `[claim]`, mso_mdoc `[namespace, element]` — extra subject keys never leak across formats), the rulebook config (`RulebookCfg`/`AuxiliaryDataCfg`/`OpeningCfg`) and `build_auxiliary_data`. mso_mdoc metadata carries **no claims member** (the suite's schema branch accepts only doctype + credential_signing_alg_values_supported — a claims member warns as an unknown extension; the catalog's claims drive issuance, not the metadata). **Mode B (§7.3) implemented**: `presentation_auth.rs` — DPoP-bound `/authorization-challenge` (jkt remembered, enforced at `/token` before the single-use claim), DCQL derived from the credential configuration, verifier-core `create_request`/`process_response` in-process, presented-credential trust via `TrustPdp::permit_presentation` (AuthZEN, fail-closed default), verified claims → subject data → code; e2e-tested end-to-end. **Suite: all four variants fully green (§16.3)** — mdoc issuance conformance-verified (attestation proofs, DS-cert profile, CRL, EUDI Rulebook elements, tag-1004 full-dates). **Rulebook layer COMPLETE (§8.3):** `zk/circuit.rs` — the general circuit catalog (`CircuitManifest`/`CircuitDescriptor`/`SystemConstraints`, camelCase catalog JSON; constraint resolution per system×doctype with every refusal direction tested: unknown-system vs withdrawal vs unreachable distinguished, disagreeing circuits, present-but-unreadable params, constrained+unconstrained mixes, range bounds) and `resolve_salt` — vc's `zk_salt.go` precedence verbatim (pin stands in only for unreachable/not-published, wins-but-logs against disagreement, **never overrides a live refusal**; 18 direction tests). Rulebooks are **general config data** (`[zk.rulebooks.<name>]`: credentials (plural) + `zk_systems` + optional pin + auxiliary-data plan; ambiguity between rulebooks is a startup refusal) — a new rulebook needs no code changes unless it needs a new derivation primitive; the derivation vocabulary (`hkdf`/`random`/`claim`) is config. **Storage pluggable:** `SessionStore` async trait (atomic single-use claims, state-machine delegation; MemoryStore the reference impl; MongoDB next behind the same contract). nym_auth (rulebook #1) issues end-to-end: vega-mc salt 32 resolved from the catalog fixture (`testdata/zkcircuits`), the ssc commitment at `[doctype, ssc]` = sha-256(HKDF(opening over issuing_country + personal_administrative_number)), the opening returned via the response's `credential_metadata.auxiliary_data` (the auxiliary-data extension; metadata advertising of `auxiliary_data_supported` deferred — the OIDF schema branch has no room for it) | 67 tests green (18 circuit-direction, nym_auth e2e with catalog-salt + commitment oracles, signed-metadata negotiation e2e, attestation 9, Mode B e2e); OIDF suite 4/4 variants: 12/14 PASSED (metadata-test-signed now runs), 2 SKIPPED, 0 FAILED |
| **P4 — ZK capability layer** (2–3 wks) | Circuit-catalog parameter resolution, SeedProvider, commitment/aux-data machinery, transform registry, rulebook abstraction; nym_auth implemented **as a rulebook module** on top | nym_auth credential issued from a **Mode B-presented PID**, verified by `siros-verifier-zkp` against a ZK-capable wallet; nym_auth touches no capability code — only traits, catalog entries, and config |
| **P5 — Module + polish** (2–3 wks) | — | **COMPLETE:** retention sweeper (`SessionStore::sweep` — expire/purge/hard-delete, §6.3 reconciled with §13.3 re-issuance; background interval, `sweep_interval_seconds`); **PKCS#11 signer provider** (`service/src/pkcs11.rs`, `[signing.pkcs11]`, kryptering cryptoki — RFC 7515 JWS + RFC 9052 raw Sig_structures, CKA_EC_POINT DER-unwrapped `public_jwk`, SoftHSM-proven incl. **full issuance of both credential formats signed by a real soft-HSM**, skips without softhsm2-util); **Mongo `SessionStore`** (`service/src/mongo_store.rs`, the `mongo` feature — CAS single-use claims, TTL retention, 6 tests vs a real mongod); **`@sirosfoundation/issuance-flow`** (`issuance-flow/` — the §10 module: dependency-free ES module, opaque-handle vocabulary enforced (`validateHandle`), QR (server `qr_svg`) / deep-link / DC-API via the injected `@sirosfoundation/dc-api` shim (`issueCredentialFromOffer`, null→fallback, availability checked before the offer hands over), SSE with polling fallback, `onPreview`/`onState` hooks; 10 node tests); **Rate limiting** (`service/src/rate_limit.rs`, `[rate_limit]` — vc's `httphelpers.RateLimiter` semantics ported: per-endpoint per-client 1-minute windows, vc defaults (offer 20/credential 30/token 20/challenge 20 RPM), 429 `rate_limit_exceeded` no-store + 503 fail-closed on limiter failure; middleware layer, remote from the ConnectInfo extensions); **PII-flow audit COMPLETE** — audited surfaces: GET/sse (`history_json`: ids, states, timestamps only), preview (catalog claim **names** — `path`/`mandatory` — never values), logs (no `tracing`/`println`/`dbg!` carrying subject data anywhere in `src/` or `service/src/`), errors (no request-body/proof/claim interpolation into message strings — messages build from refs/ids), vault (never logs, sealed at rest), module (vocabulary-enforced, `validateHandle` refuses anything claim-shaped); all issuer egress of claims is the credential itself (response-encrypted on request) | |
| **P6 — Interop** (parallel, ≥ dev time) | Wallet interop (SIROS wallet incl. ZK, EUDI reference wallet, wwWallet compat), conformance vs OpenID4VCI 1.0 ID1 (both grants) + OpenID4VP presentation, cross-verification with verifier-core | Interop matrix green; salt-length regression test in CI |

### 13.2 Totals

- Code: ~19–27k LOC Rust + ~2–3k LOC TS.
- Calendar: **6–8 person-months** single spec-fluent developer; interop at parity.
- The analogous prior effort (siros-verifier-core: 5.3k core LOC + service + plugin + npm
  module) is the calibrated reference and succeeded on this shape.

### 13.3 Testing strategy

- Sans-I/O core units fuzzed (parser/proof fuzz targets as in verifier-core).
- Cross-check invariants: issued mdoc parsed by verifier-core `mdoc.rs`; issued SD-JWT
  verified by verifier-core `sdjwt.rs`; nym_auth presentations verified by `siros-verifier-zkp`.
- **Salt-length regression test**: a circuit-catalog revision changing salt length must flip
  issuance behavior in CI (the exact fleet-failure vc documented).
- Wire-level golden tests against vc-produced fixtures where semantics are shared
  (auxiliary data, offer shapes, notification payloads).
- **Grant/mode tests**: both grants against reference wallets; Mode A handoff abuse
  cases (replayed `issuer_state`, TTL, redirect binding, PKCE mismatch); Mode B tested
  against verifier-core presentation fixtures, plus the full stack: presented PID →
  derived nym_auth issuance → ZK presentation verified by `siros-verifier-zkp`.
- Mutation testing + `cargo deny`/audit per verifier-core's script suite.

---

## 14. Risks and mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| **Dual maintenance**: SUNET/vc evolves daily (~900 PRs); a parallel issuer diverges | High | Target a deployment role vc doesn't serve (headless/tenant-embedded); or declare vc's issuer-side retirement path explicitly. Do **not** run both in the same role long-term |
| **Interop is the long pole**, especially ZK: end-to-end nym_auth needs the native-prover wallet | High | P4 cannot exit without siros-wallet interop; budget parity testing time; keep wwWallet/EUDI fixtures in CI |
| **Circuit-catalog semantics are subtle** (fail-closed vs pin-override) | High | Port vc's `zk_salt.go` semantics verbatim (they are exhaustively commented there); CI regression for salt-length changes |
| **Hard dependency on siros-verifier-core releases** (Mode B embeds its crates) | Medium | Pin exact versions in the workspace; the cross-check CI (issued credentials ↔ verifier-core verification) makes drift visible immediately; same-org BSD-2 crates, coordinated release possible |
| Spec churn: DC-API issuance, status-list draft → RFC, OID4VCI maintenance | Medium | Pin to OID4VCI 1.0 ID1 + status-list-21 (status-service pins these); DC-API browser variance is absorbed in the shared `@sirosfoundation` shim (§10.2), version-gated per release |
| mdoc IACA/PKI operational burden | Medium | Reuse vc's PKI tooling for dev; production IACA handling documented as deploy-time concern, not code |
| Sensitive-data handling in session store (incl. Mode B presented claims) | Medium | Sealed vault + bounded retention + PII-flow audit as a P5 exit criterion |
| Scope creep toward "functionally equivalent" (apigw's auth-provider surface) | High — this is the project-killer | §3.3 + §7.2/§7.3 are normative: exactly two authorization modes, no auth-provider plugins, no consent pages; TS12/federation are v2 and must be justified by a concrete deployment, not parity anxiety |

---

## 15. Alternatives considered

1. **Keep SUNET/vc as the only issuer.** Rejected as the answer to the integration feedback:
   the complexity is architectural (datastore pre-provisioning, auth-provider config, UI
   coupling), not fixable by documentation. vc remains the right tool for deployments that
   need its IAM-integrated (SAML/OIDC-RP-embedded), federation-enabled profile.
2. **Refactor vc-apigw into a headless mode.** Rejected: the complexity is not localized —
   datastore, identity mapping, sessions, consent, SAML/OIDC RP are structurally
   entangled; a headless carve-out would still carry the monorepo's operational model
   (Mongo, gRPC mesh, Kafka) and its test surface.
3. **Full functional-equivalence rewrite in Rust (incl. auth providers, W3C VC, BBS,
   federation).** Rejected: multi-quarter, zero functional gain, doubles maintenance.
4. **Rust issuer with the scope defined here.** **Chosen:** ~6–8 person-months, reuses the
   established verifier-core architecture and crates — including *embedding verifier-core
   itself* for Mode B authorization, which no Go implementation could do — replaces
   ~64k LOC of Go (apigw issuance-relevant parts + registry + status packages) with
   ~19–27k LOC Rust + services already running in the ecosystem, and directly answers the
   integration feedback with a one-call backend contract.

---

## 16. Decisions and remaining open questions

### 16.1 Decisions (resolved)

1. **Storage:** pluggable behind the `SessionStore` trait (async, full
   session contract); MongoDB is the production backend, the in-memory
   `MemoryStore` (the reference implementation) is for tests and
   single-process dev. (§4.3, §5.2)
   **Signer:** the PKCS#11 provider (`service/src/pkcs11.rs`,
   `[signing.pkcs11]`) implements `signer::Signer` over a real HSM
   module (kryptering `cryptoki`; SoftHSM for dev/tests) — compact
   ES256 JWS (RFC 7515 signing input), raw RFC 9052 Sig_structures
   (COSE), `public_jwk()` from CKA_EC_POINT (DER-unwrapped). Mutually
   exclusive with the file key (validated at startup; no silent HSM
   fallback). Proven against a real SoftHSM token: the provider
   contract (both signature shapes verified under the token's public
   key) and full issuance of both credential formats through the
   service with the HSM signing, verified under the same public key
   (`service/tests/pkcs11_signer.rs`, `issuance_e2e.rs
   hsm_signer_serves_both_credential_formats` — skips without
   softhsm2-util). (§11.1)
2. **Status feedback transport:** SSE ships in v1; simple polling remains the fallback
   path. (§6.1, §10.2)
3. **DC-API invocation:** use and evolve the existing `@sirosfoundation` npm DC-API
   shim layer — not a fork or fresh implementation. The shim absorbs cross-browser
   variance for both the issuer module and `presentation-flow`. (§10.2)
4. **Tenancy:** single-tenant binary; deployment/tenant isolation is clean MongoDB
   database separation, purely from config (`storage.database`). (§4.3, §5.2)
5. **Session↔subject mapping:** integrators retain it. The issuer holds no standing
   subject index; revocation is by session id only; `subject_ref` is echo metadata,
   never a lookup key. (§6.2, §9.3)
6. **Preview/consent rendering:** the module exposes an optional JS callback
   (`onPreview`) that the embedding app supplies; the app renders from its own data —
   it holds the claims. The issuer's preview endpoint stays claim-names-only. (§6.1,
   §10.2)
7. **Naming:** `siros-issuer-core` (crates), `siros-issuer-service` (binary),
   `@sirosfoundation/issuance-flow` (module) — consistent with the verifier set.
8. **Validity/`exp` interplay:** credential validity is aligned with the allocated
   status index `exp`; the status service's `MAX_EXPIRY` is the outer bound on
   credential lifetime (vc's `credential_validity` tests are the reference). (§9.1)
9. **Rulebooks:** data conceptually, **code in substance** — a rulebook ships as a
   small Rust module implementing the capability traits, sometimes plus config, or
   both. The catalog is about schemas from the point of view of the code; rulebook
   *governance* is therefore not this design's concern. (§8.3)

### 16.2 Remaining open questions

1. **AS client policy — resolved by the OIDF suite (see §12.1):** the deployed
   `oid4vci-1_0-issuer-test-plan` build selects modules only for
   `client_auth_type: private_key_jwt` (probed exhaustively; the FAPI2-SP base excludes
   `none` and `client_secret_basic`). PAR/token clients are therefore **pre-registered
   with configured JWK sets** (client_id → JWK + redirect_uri allowlist in config), and
   the token endpoint verifies RFC 7523 client assertions for both grants.
   Implemented in P2: `service/src/client_auth.rs` (registry + `private_key_jwt`
   verification; `client_id` may be absent — RFC 7523 §3 derives it from the
   assertion `iss`) and the **attestation policy layer** translated from vc's
   `WalletAttestationPolicyEngine` (wildcard rules default-open; PDP provider the
   production path). **DONE (v2): the attestation-JWT verification itself**
   (`service/src/wallet_attestation.rs`, vc's `WalletAttestationEvaluator`
   ported faithfully): etsi x5c / ietf iss-JWKS modes (pinned by
   `[authorization.attestation.wallet] mode`, enforced before any signature
   verification), local signature verification (x5c leaf / jwk header /
   kid+JWKS at iss, https-only), wallet-provider trust via a third PDP
   decision (`TrustPdp::permit_wallet_provider`, action `wallet_provider`
   — vc's RoleWalletProvider; `WalletProviderTrustQuery` in the core), then
   the tier policy. PoP per draft §5.2 (typ oauth-client-attestation-pop+jwt,
   cnf.jwk signature, aud, exp/iat), legacy empty-pop accepted. Token
   endpoint: `OAuth-Client-Attestation`(+`-PoP`) headers or RFC 7523.
   7 tests: both modes end-to-end, mode pinning, untrusted refusal,
   malformed-x5c fail-closed, iss↔cert disagreement, PoP positive/negative
   + legacy. Config absent ⇒ private_key_jwt only (the conformance profile,
   unchanged).
2. **Mode B process topology:** in-process embedding of verifier-core crates is the v1
   default (simplest, single binary). Should a deployment mode that delegates
   presentation verification to a deployed siros-verifier-service (via a signed receipt
   callback) also exist? The session API shape already accommodates it; decide when a
   concrete deployment asks, not before.

### 16.3 Conformance status (P2 + P3 — COMPLETE)

**The OIDF `oid4vci-1_0-issuer-test-plan` issuer suite passes fully** against
siros-issuer-core, all four variants — **both credential formats** (`sd_jwt_vc`
and `mdoc` / mso_mdoc) × **both grants** (pre-authorized_code /
issuer-initiated and authorization_code / wallet-initiated), dpop
sender-constraining, plain encryption: 13/14 modules PASSED, 1 SKIPPED
(profile scope: key attestations not configured; the proof-module pair
splits by variant — the suite's wallet runs the one matching the
variant's `proof_types_supported`, both implemented and each passing in
the variant that selects it; `metadata-test-signed` and
`batch-issuance` run since the implementations below), 0 FAILED,
0 warnings.

**Signed metadata** (OID4VCI 1.0 Final §12.2.2, implemented post-P3):
content negotiation — `Accept: application/jwt` answers the whole metadata
document as a compact ES256 JWS (`typ: openidvci-issuer-metadata+jwt`,
the public signing key in the header `jwk`, never `d`), anything else the
plain JSON. The signature crosses the `signer::Signer` boundary (design
§11.1 — HSM signers serve it identically). Not a `signed_metadata` member
(the draft-era shape): the suite's
`VCIDecodeSignedCredentialIssuerMetadata` verifies the JWS against the
header key, checks `sub` against the configured issuer identifier, strips
the four JWT claims, and runs the full standard metadata validation on
what remains — so the **payload is the document merged with the JWT
claims** (`sub` = `iss` = the credential issuer identifier, §12.2.3
byte-identity; `iat`/`exp` the signing window). E2e-oracled: header
type/key, verification under the header key (= the JWKS key), `sub`
equality, and the document (claims stripped) equal to the plain document.

**Batch issuance** (OID4VCI 1.0 Final §12.2.2, implemented post-P3):
advertised as `batch_credential_issuance: {batch_size}` ONLY (from
`[issuance] batch_size`, validated ≥ 2 at startup; absent = not
supported and omitted — the suite's batch module skips, permitted).
**No `batch_credential_endpoint` member**: the suite's metadata schema
defines none, and 1.0 Final runs batch issuance ON the credential
endpoint (vc's metadata carries only `batch_credential_issuance`); the
`/batch-credential` route remains an unadvertised alias. **The batch is
the `proofs` parameter itself** (vc `Proofs.ExtractAllJWKs` semantics):
one credential per key the proofs carry — one per jwt proof, or **all
`attested_keys`** of an attestation proof — over the same session
subject data, capped at the advertised `batch_size`, distinct binding
keys (RFC 7638 thumbprints; duplicates refused, never collapsed),
distinct unpredictable status indices and salts per entry. **Batch time
claims round to a 3600 bucket, single to 300**: the suite's
`VCIEnsureBatchTimeClaimsNotLinkable` treats time values shared across
a batch as PRECISE (correlatable as a batch) unless every value is
hour-aligned (its `allMatch v % 3600 == 0` acceptance) — the 300 bucket
that satisfies the single-issuance check would fail the batch one.
Herd privacy (`VCIWarnBatchStatusListUrisProvideHerdPrivacy`): a batch
must share one status list URI and differ by index — the allocator
(the status service contract) allocates from one current list, not one
list per credential. PAR's single-credential rule stands unchanged.
Issuance cores (`issue_sdjwt_entry` / `issue_mdoc_entries`) are shared
by every entry — no parallel path. E2e-oracled with the suite's own
check names (incl. hour-aligned iat/exp).

Conformance stack: `siros-conformance/compose/siros-issuer-core.yml`
(issuer + Mode A dev portal + status stub + TLS nginx +
`go-trust`-allow), `specs/conformance/oid4vci-issuer-core.spec.ts`,
`make up-issuer-core` / `make test-issuer-core`. Issuer over TLS as
`issuer.conformance.example.com` (cert from the suite's conformance CA);
the runner mints pre-authorized offers server-to-server for issuer-initiated
modules and drives the Mode A browser handoff (PAR → authorize → portal →
callback) for wallet-initiated ones, once per client.

Issuer fixes driven by the suite (each module-verified):
- OID4VCI **1.0 Final** metadata schema conformance: `vct` at configuration
  level, `cryptographic_binding_methods_supported`/`proof_types_supported`
  co-presence, issuer-level `credential_response_encryption` with
  `encryption_required`, `credential_request_encryption` (public members
  only, no `alg_values_supported`), no issuer-level `jwks_uri`, AS metadata
  advertises both grants + PAR + PKCE + DPoP +
  `authorization_details_types_supported`.
- §12.2.3 byte-identity: `issuer_identifier()` — the identifier, no
  empty-path slash (metadata, offers, `iss`, `aud` comparisons, RFC 9207
  `iss` in the authorization response).
- PAR per RFC 9126: form encoding + 201 Created; scope-based credential
  selection (§5.1.2) with a deployment scope map; registered
  redirect_uri/client validation.
- Credential error responses: registered error codes
  (`invalid_proof`/`invalid_nonce`/`unknown_credential_configuration`/
  `unknown_credential_identifier`), §7.3.2 nonce refresh semantics,
  closed response key set; nonce endpoint public (§7.1 Final) with
  `Cache-Control: no-store`; credential responses carry `credentials[]` +
  `notification_id` only; `proofs` (Final §8.2) accepted alongside draft
  `proof`; `x-fapi-interaction-id` echoed only when sent.
- RFC 9901 §10.1: `iat`/`exp` rounded to a 5-minute bucket
  (linkability — suite `VCIEnsureCredentialTimeClaimsNotLinkable`).
- Re-issuance per §13.3: `Issued` legal from `Issued`/`Accepted`
  (additional-requests); status ref replaceable per issuance.
- RFC 7523 client auth at `/token` (both grants), `client_id` optional
  (derived from assertion `iss`); DPoP (RFC 9449) ath+jkt binding at
  `/credential`, replay cache.

mdoc-variant fixes driven by the suite (each extracted from the suite's
own classes/schema, then module-verified):
- **Key-attestation proofs** (Appendix D.1): the mdoc configurations
  advertise `proof_types_supported: attestation/ES256`, the suite's wallet
  signs `typ: key-attestation+jwt` with `x5c`/`x5t#S256` from
  `vci.key_attestation_jwks`, and claims `iat`/`exp`/`attested_keys`/
  `nonce` — **no `aud`** (checked only when present; alg pinned to ES256
  as advertised; signature via jose_rs, x5c-leaf self-consistency).
  The invalid-attestation-signature module maps to `invalid_proof`.
- **ISO 18013-5 document-signer certificate profile**: CRL distribution
  point (fetched and DER-parsed by the suite), validity ≤ 457 days,
  critical EKU `1.3.6.1.5.5.7.3.36`, non-critical basicConstraints,
  issuerAltName contact, SKI/AKI; the CRL carries an authority key
  identifier and nextUpdate ≤ 90 days.
- **EUDI PID Rulebook mandatory elements**: family_name, given_name,
  birth_date, place_of_birth (`{country, region, locality}`),
  nationality (alpha-2 array), issuing_authority, issuing_country —
  catalog + subject fixtures.
- **RFC 8943 full-date typing**: `birth_date` is CBOR tag-1004 text
  (`MsoBuilder::add_full_date`; vc's `mdoc.FullDate` marshals the same).
- **mso_mdoc metadata carries no `claims` member**: the suite's
  `credential_issuer_metadata-1_0.json` mso_mdoc branch accepts only
  `doctype` + `credential_signing_alg_values_supported`
  (`unevaluatedProperties:false`); the catalog's claims drive issuance
  (schema gate, elements), not the metadata.
**Upstream filed:** siros-verifier-core#13 (catalog index maps stale after
sort), siros-status-service#20 (StatusListToken embedded-jwk `kid` —
local-test status stub in the conformance profile stands in until the fix
deploys).

---

## Appendix A — vc reference inventory (source of ported semantics)

| vc source | Ported to | Fidelity requirement |
|---|---|---|
| `pkg/openid4vci/*` (9.0k) | `oid4vci.rs` | Protocol shapes incl. wwWallet compat quirks (trailing-slash well-knowns) |
| `internal/apigw/apiv1/handlers_oauth.go` + `handlers_oauth_challenge.go` | service `api_wallet.rs` (AS surface) | PAR/token/challenge endpoint semantics, DPoP binding, rate-limit defaults |
| `internal/issuer/apiv1/zk_salt.go` | `zk/params.rs` (generalized) | **Verbatim semantics** — fail-closed/pin-override order, logging |
| `pkg/openid4vci/auxiliary_data.go` | `zk/commitments.rs` (generalized) | Auxiliary-data wire format; per-rulebook details arbitered by zkp crate |
| `pkg/model` derivations (`copy`/`hash_commitment`/HKDF) + seed files (`secret_path`), `pseudonym_seed` | `zk/transforms.rs`, `zk/seeds.rs`, `zk/rulebook.rs` | Config shape preserved; generalized behind registry/traits |
| `pkg/sdjwtvc` issuance subset | `sdjwt_issue.rs` | Verified against verifier-core `sdjwt.rs` |
| `pkg/mdoc` issuance subset | `mdoc_issue.rs` | Round-trip with verifier-core `mdoc.rs` |
| `internal/apigw/apiv1/handlers_issuance_session.go` | Session API v2 identity-match | `identity_match` REQUIRED semantics |
| `docs/ZK_VEGA_DIGESTID_WIRE_EXTENSION.md` | `mdoc_issue.rs` | Rulebook-conformant |
| Rate limits (`apigw.rate_limit`) | service config | Defaults ported as config |

## Appendix B — Effort model (bottom-up)

| Piece | LOC |
|---|---|
| OID4VCI core (metadata/offer/proof/encryption/deferred/notification/session model) | 5–8k |
| OAuth2 AS for both grants (PAR, authorize, token, PKCE, DPoP-bound challenge) | 1.5–2.5k |
| Mode B orchestration (DCQL construction from catalog, presentation intake, verifier-core embedding glue) | 1–2k |
| SD-JWT VC issuance + status refs | 1–2k |
| mso_mdoc issuance | 3–5k |
| ZK capability layer (params, seeds, commitments, transforms, rulebook registry) + nym_auth rulebook | 1.5–2.5k |
| siros-status-service client | ~0.3k |
| TS11 catalog client + config resolution | ~1k |
| Service (axum, vault, store, auth, SSE) | 2–3k |
| Signer interface + in-memory and PKCS#11 providers (§11.1) | 0.5–1k |
| `issuance-flow` TS module | 2–3k |
| **Total** | **~19–28k** |
