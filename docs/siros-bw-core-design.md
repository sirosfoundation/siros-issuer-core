# siros-bw-core — Design Document (DRAFT v0.1 — for iteration)

Status: **draft for discussion.** Nothing here is settled until the open
questions (§14) are worked through. Modeled on the issuer-core design doc;
§-numbers are this document's own.

---

## 1. Summary

bw-core is the **business-wallet orchestration layer**: a component that
runs configurable business logic — flows that involve **authentication,
verification, and issuance** — over a set of primitives, embedding
`siros-issuer-core` and `siros-verifier-core` as libraries.

The term "business wallet" (WE BUILD usage) covers the combined features
of an issuer, a wallet, and a verifier, **plus an orchestration layer** on
top of the three. bw-core is that orchestration layer. A business wallet
also groups multiple wallet instances via WMP; WMP is bw-core's carrier
and its orchestration carrier (§7).

What bw-core is **not**:

- not a general workflow engine — the flow language is deliberately
  **non-Turing-complete** (§5);
- not a second implementation of any protocol — every cryptographic
  verb (present, verify, sign, issue) is a library call into a core;
- not a trust decision point — all trust is go-trust's (§9);
- not a place where subject data transits in plaintext (§10).

---

## 2. Background and motivation

### 2.1 The flows neither core covers

The issuer-core session state machine covers *one credential, one wallet,
one redemption*. The verifier-core request/response covers *one
presentation, one verifier session*. Real business flows compose both,
across roles, with data movement between the steps:

1. **Company-bound SCA:** present a PID **and** a PoA (or EUCC) in one
   transaction; check the PoA is **bound to the PID's subject**; issue an
   SCA bound to the company. Neither core performs the cross-credential
   check, and the issuance subject derives from *two* presentations.
2. **Identity-bound EUCC:** an identity-bound session (the business
   wallet knows who its user is); present a PID; issue an EUCC **only if
   the PID's identity is the same identity the session knows**.
3. **Payment receipt:** present a PoA and an SCA (direct payment); issue
   a Payment Receipt attestation over the payment facts.
4. **Token-sourced attestation:** extract claims from a SAML or OIDC
   token (an enterprise IdP login) to generate an attestation — and
   request a PID presentation as part of the same flow.

Each of these is a *sequence*: request presentation(s) → verify →
cross-check → derive subject data → issue → notify. Sequencing is policy,
not protocol: it belongs in **configuration**, over **primitives**, with
the cryptography in libraries. That is bw-core.

### 2.2 Precedents inside the family

- issuer-core's **Mode B** already embeds verifier-core in-process for a
  presentation-then-issue sequence — but hardcoded to exactly one shape
  (present PID → bind session → mint code). bw-core generalizes the
  *composition*, not the cryptography.
- The **ZK rulebook layer** (issuer-core §8.3) already answers "configure
  behavior with minimal code changes" for derivations: rulebooks are
  TOML data over a derivation vocabulary. bw-core applies the same
  discipline to *flows*: flow definitions are data over a step
  vocabulary (§5–6).
- **pyFF/goFF** answer it for pipelines: a linear sequence of
  closed-vocabulary actions over a working set, with bounded `fork`/`map`
  sub-pipelines, labels, and `end` — fifteen years of federation-ops
  proof that a *small, closed* action vocabulary beats an embedded
  scripting language. bw-core's flow language is that shape (§5).

### 2.3 WE BUILD context

The WE BUILD consortium's BU/PA-group flows are the concrete demand
(complex-flow documentation lives in the `webuild-consortium` BU and PA
repositories; "business wallet" there means exactly issuer+wallet+verifier
plus orchestration). The architecture ADRs relevant here:

- **ADR 002 (identity matching):** cross-border identity matching is
  **deterministic** — mandatory PID `id` + `nonce`, wallet-derived
  RP-scoped stable pseudonyms — and explicitly *rejects* name/dob fuzzy
  matching. This shapes the binding vocabulary (§8): bw-core's
  cross-identity checks are deterministic math, never heuristics.
- The BU/PA rulebooks (attestation-rulebooks-catalog) are the source of
  the concrete credential definitions flows will reference.

---

## 3. Goals and non-goals

### 3.1 Goals

1. **Flows as data over primitives.** A flow definition is a document in
   a non-Turing-complete language (§5) interpreted by a fixed engine.
   Adding a new business flow = writing a flow definition + possibly a
   plugin — not forking the engine.
2. **A closed primitive vocabulary** (§6) that closes over §2.1's flows
   and the obvious near-term extensions, with the same exit criterion as
   the rulebook layer: *a new flow needs no engine changes unless it needs
   a new primitive*.
3. **WMP as carrier and orchestration carrier** (§7): flow steps ride
   WMP messages to wallet instances; the business wallet's
   instance-grouping selects which instance(s) a step addresses.
4. **Deterministic binding checks** (§8) as first-class primitives —
   the cross-credential glue (PoA↔PID, session↔PID) the flows need.
5. **The security disciplines carry up a level unchanged** (§10):
   sealed subject data, PII never in logs/errors, fail-closed trust,
   stable machine-readable refusal codes.

### 3.2 Non-goals

- **No general computation.** No loops, no recursion, no
  expression-language escape hatch. Conditional logic is declarative
  matchers; iteration is bounded `map` over a list known at
  flow-definition time. If a flow needs real computation, it needs a
  plugin (which is code, reviewed as code).
- **No second protocol implementations.** OID4VCI, OID4VP, DCQL, COSE,
  status lists: library calls. bw-core never re-does JOSE.
- **No trust logic.** The PDP owns every allow/refuse (§9); bw-core
  constructs the evidence.
- **No UI.** The business wallet frontend is a separate concern; bw-core
  exposes the same SSE/event surface shape issuer-core does (§8.4), and
  WMP messages.

### 3.3 Explicit scope guards

- A flow definition **cannot** import code, reference files outside its
  plugin allowlist, or call endpoints outside its configured targets.
- A plugin **cannot** be defined in a flow document; plugins are
  deployment config + reviewed code.
- The engine **rejects** unknown step kinds, unknown matchers, unknown
  encodings — fail-closed with stable codes, exactly as the circuit
  catalog does.

---

## 4. Architecture

### 4.1 Component overview

```
                   ┌─────────────────────────────────────────┐
                   │                bw-core                   │
                   │                                         │
 business wallet ──┤  flow language  ──▶ flow engine ──┐      │
 frontend (SSE)    │  (definitions)     (interpreter) │      │
                   │        │                        │      │
                   │  FlowStore (trait)               ▼      │
                   │        │              ┌──────────────┐│
                   │        │              │  primitives   ││
                   │        │              └──────────────┘│
                   │                       │        │       │
                   │        ┌──────────────┘        │       │
                   │        ▼                       ▼       │
                   │  siros-verifier-core    siros-issuer-core
                   │  (present, verify)      (issue, sign, status)
                   │        │                       │       │
                   │        └───────── go-trust ────┘       │
                   │                  (PDP)                │
                   └─────────────────────────────────────────┘
                        ▲                                │
                        │ WMP (carrier)                   │
                   wallet instances (personal/business) ──┘
```

- **Flow engine:** loads definitions, instantiates flows, sequences
  steps, owns flow state, emits events. One engine, many definitions.
- **Primitives:** step-kind implementations (§6), each a small, tested
  unit calling core/PDP/plugin surfaces.
- **FlowStore:** pluggable persistence (§8.3) — in-memory reference,
  MongoDB production; same trait discipline as `SessionStore`.
- **WMP surface:** the wallet-facing carrier (§7).

### 4.2 Repository layout (proposed)

New repo `sirosfoundation/siros-bw-core`:

```
siros-bw-core/
├── docs/siros-bw-core-design.md     # this document
├── src/                             # sans-I/O flow core
│   ├── lib.rs
│   ├── language.rs                  # definition parsing + validation
│   ├── engine.rs                    # the interpreter + flow state machine
│   ├── binding.rs                   # deterministic binding checks (§8)
│   ├── context.rs                   # the working set (§5.3)
│   └── error.rs                     # stable refusal codes
├── service/                         # deployable binary
│   ├── src/
│   │   ├── primitives/              # step-kind impls calling the cores
│   │   ├── plugins/                 # fetch/token/notify provider traits + impls
│   │   ├── wmp.rs                   # carrier adapter (§7)
│   │   ├── store.rs / mongo_store.rs
│   │   └── vault.rs                 # reuse issuer-core vault shape
│   └── tests/
├── flows/                           # reviewed flow definitions (fixtures + shipped)
└── testdata/
```

The sans-I/O split mirrors the issuer-core discipline: the language, the
engine's transition logic, the binding checks, and the context are pure
and testable without I/O; effects cross primitive boundaries only.

### 4.3 Embedding vs deploying the cores

**Recommended: embed in-process** (library calls into both cores), as
Mode B already does. Deployment alternatives (sidecar HTTP to
issuer/verifier services) are config-selected but not the reference path —
in-process keeps subject data off the network between flow steps, which
is a load-bearing privacy property (§10).

---

## 5. The flow language

### 5.1 Shape (pyFF/goFF-inspired)

A flow definition is a **pipeline**: a linear document of steps over a
working set. goFF runs the same pipeline YAML as pyFF — the portability
lesson matters here: the language is small enough to be *stable*, and
definitions are data that outlive engine versions.

```yaml
# flows/company-sca.yaml — §2.1 flow 1, as an illustration
flow: company-sca
description: >
  Present PID + PoA, check the PoA binds to the PID's subject,
  issue a company-bound SCA.

context:
  issuer: https://bw.example.org           # who we act as
  audience:  https://bw.example.org/flows/company-sca

steps:
  - presentation:
      id: pid-and-poa
      request:                             # DCQL; one transaction
        - credential: urn:eudi:pid:1        # PID
        - credential: urn:ewb:poa:1         # PoA
      require: [pid-and-poa.pid, pid-and-poa.poa]

  - binding:
      poa_mandate_holder_is_pid_subject:
        left:  pid-and-poa.poa.subject_key      # the PoA's mandate holder key
        right: pid-and-poa.pid.cnf              # the PID's confirmation key
      policy: same-key | same-pseudonym         # deterministic (§8)

  - issuance:
      credential: urn:ewb:sca:1
      subject:
        from: pid-and-poa.pid                 # base subject = PID claims
        merge:
          company: pid-and-poa.poa.company    # company from the PoA
      notify: [wallet]
```

Read it as: *steps transform a working set; matchers select what a step
sees; nothing computes.* The schema details follow in §5.2–§5.3.

### 5.2 What the goFF/pyFF shape actually teaches

Reading the goFF examples beyond the minimal one: `load` is not a
privileged header — `finalize-aggregate.yaml` interleaves load/select pairs
mid-pipeline, aliasing each source's snapshot (`select as /swamid`) and
selecting from aliases later (`/swamid!//…`); `mdq-server-pipeline.yaml`
scopes the entire pipeline under `when update:` with three sibling `fork:`
bodies each carrying nested sub-pipelines; `fork-idp-sp.yaml` forks twice
and continues after. The pipeline is a **flat sequence of heterogeneous
steps with scoped control wrappers and named working-set snapshots** —
exactly the shape bw-core needs, minus XML:

- **steps interleave freely** — a `presentation` step can appear before
  *and* after an `issuance` step in one flow (present PID → match → issue
  → present the issued credential onward is a real flow shape);
- **`as`-style aliases** name a step's results for later reference
  (`store as /company` ↔ our step-id context keys — same idea, and worth
  keeping the `as` spelling);
- **`when:` wrappers scope** a body by mode/condition (the `when:`
  conditions bw-core needs are match-results and flow modes, not pyFF's
  request-scoped ones — goFF deprecated those);
- **`fork:` runs isolated sub-pipelines** over copies of the context —
  bounded, and the sandbox discipline (changes don't leak out) is
  documented behavior to port.

### 5.3 Language decision (pinned)

**Resolved (2026-11-08):**

- **Flow definitions are YAML.** The goFF/pyFF precedent is decisive:
  the pipeline shape is a *top-level list of heterogeneous maps*
  (`- presentation: …` / `- match: …`), with control wrappers
  (`when:`, `fork:`, `map:`) nesting bodies under a key — natural
  YAML, awkward TOML (`[[steps]]` + dotted-path child tables read
  flat and re-parent painfully). Definitions are human-authored
  *policy documents people argue about*: nesting and inline comments
  win. The YAML footgun class (no/1:30/Norway) is mitigated by the
  strict schema — fail-closed unknown-kind refusals, typed scalars
  (§5.4).
- **Deployment config stays TOML.** Plugins, allowlists, provider
  endpoints, store settings — the family convention
  (`[zk.rulebooks.<name>]` etc.) unchanged.
- **The schema is defined as a JSON tree.** YAML and TOML are two
  frontends to one parsed-document schema; a flow definition parses to
  a typed JSON document which the loader validates against the
  language schema. Future-proofs *generated* definitions (emit JSON or
  YAML), makes the language schema itself a JSON(-Schema-like) artifact,
  and keeps the engine frontend-agnostic (the §5.1 sketch maps 1:1).

### 5.4 Non-Turing-complete by construction

The language offers exactly these control constructs, all bounded:

- **linear steps** — always run in document order;
- **`map:`** — bounded iteration over a *list in the context*, not over
  computed output (goFF's `map` shape: per-item sub-pipeline, isolated
  snapshot, side effects per item);
- **`when:` matchers** — declarative preconditions on a step (string/set
  membership, presence, equality — the same matcher vocabulary everywhere,
  no expressions);
- **`end:`** — early flow-stop (goFF/pyFF `break`/`end`).

Explicitly absent: variables, arithmetic, string interpolation, loops
over runtime-computed collections, recursion, user-defined functions. A
definition that needs any of them is asking for a **plugin primitive**
(§6.7), which is reviewed code with tests — the same boundary the ZK
layer draws ("a rulebook translates to code *and sometimes config*, or
both").

### 5.5 The working set (context)

pyFF's working set is the entity selection; bw-core's is the **flow
context** — a typed document the engine owns:

- **inputs** (fixed at flow start): flow id, initiating session identity
  (when the business wallet knows its user), WMP target instance
  selector, caller-supplied parameters;
- **presentation results**, keyed by step id: each entry carries the
  *verified claims* (as a claims object, format-tagged), the holder key
  (`cnf`/`DeviceKey`), and the credential identifiers presented;
- **derived values** written by steps (`store`, `token`, `fetch`);
- **issuance refs**: session ids / offer URIs created by `issuance`.

Subject-shaped context data is **sealed at rest** the way session data is
(§10); the context object the engine threads is the only plaintext copy,
in memory, never serialized whole.

---

## 6. Primitives (the step-kind vocabulary, v1)

Each kind is a primitive: implemented once, tested against a core-level
oracle, usable in any flow. **Closures over §2.1:**

| kind | does | calls | §2.1 flow |
|---|---|---|---|
| `presentation` | build a DCQL request, send it (WMP carrier), collect + verify responses | verifier-core `create_request`/`process_response` | 1,2,3,4 |
| `binding` | deterministic cross-credential/subject checks (§8) | local (context only) | 1,2 |
| `issuance` | create an issuance session over derived subject data | issuer-core session API (in-process) | all |
| `token` | extract claims from a presented SAML/OIDC token | plugins (§6.7) | 4 |
| `fetch` | call an external API for supplementary data | plugins | 3,4 |
| `store` | write a derived value into the context | local | all |
| `notify` | emit a WMP message / SSE event | WMP adapter | all |

Two rules keep the vocabulary honest:

1. **A primitive never decides trust.** `presentation` verifies
   cryptography; the *acceptability* of a presented credential is a PDP
   call the engine makes on the primitive's evidence (§9). `binding`
   performs *math* on context values — it refuses mismatches, it does not
   consult policy.
2. **A primitive never invents data.** Output shapes are fixed by the
   kind; a step cannot reshape context arbitrarily (`store` writes a
   value under a declared key, with a declared encoding).

### 6.1 `presentation`

- Declares one or more `request` inputs (DCQL input descriptors derived
  from the flow's credential ids, or explicit DCQL for the odd cases).
- One **transaction** per step: multi-input presentations ride one
  OID4VP request/response, so the "PID and PoA presented together"
  guarantee is cryptographic (same transaction) rather than sequential.
  Multiple `presentation` steps in a flow are *separate* transactions —
  flows that need cross-presentation same-party guarantees add a
  `binding` step.
- Verification is verifier-core in-process; trust in each presented
  credential goes to the PDP (`permit_presentation`, the Mode B pattern),
  fail-closed.
- DPoP binding of the challenge rides the WMP request/response the same
  way it rides Mode B's challenge (the sender-constraint semantics are
  unchanged).

### 6.2 `binding` — see §8.

### 6.3 `issuance`

- Creates an **issuer-core session in-process** (the same session
  record, store, and state machine — not a second issuance path).
- Subject data derives **declaratively** from the context: a `from`
  (base presentation) plus a `merge` map (context paths → claim paths).
  No computation, no plugins — a mismatch of shapes is a refusal at
  definition-validation time where checkable, at runtime otherwise.
- The pre-auth offer or authorization challenge rides WMP back to the
  target instance (§7).
- Rate limiting, retention, sweeping: issuer-core's machinery, reused,
  not reimplemented.

### 6.4 `token`

SAML/OIDC token → claims. The token arrives via WMP (a business system
presenting its IdP assertion) or as a flow input. Plugin-verified
(signature, audience, freshness windows — the same checks
`verify_private_key_jwt` performs in issuer-core, generalized), claims
into the context under the step id. **The plugin trait is the reviewed
code; the flow only references the plugin by name.**

### 6.5 `fetch`

External API → context value. Bounded: config-selected provider by name,
timeout, response-size budget, **no subject data out** unless the
provider's config declares it (the PII-flow audit discipline, §10).
Fail-closed on error — a failed fetch fails the flow step, never
silently continues.

### 6.6 `store` / `notify`

`store` writes a context value under a declared key (validated against
the definition's own schema of what steps may read). `notify` emits a
WMP message to the flow's instance selector or a typed SSE event for the
embedding frontend — the "one state machine, two audiences" shape again.

### 6.7 Plugins

`token`, `fetch`, and any future exotic primitives take **plugins**:
`trait FlowPlugin` with a small surface (name → invoke(context) →
value). Plugins are *code*: reviewed, tested, allowlisted in deployment
config. A flow definition referencing a plugin not in the allowlist is a
startup refusal. This is the deliberate Turing-completeness escape
hatch: **code stays code, config stays config** — the same boundary the
ZK rulebook layer draws.

---

## 7. WMP as carrier and orchestration carrier

Resolved in discussion: WMP is **the** wallet-facing carrier, not a
side-channel.

- **Carrier:** each wallet-facing step (presentation requests,
  issuance offers, notifications) rides WMP messages. The wallet
  instances speak WMP already; bw-core does not invent a second
  wallet protocol.
- **Orchestration carrier:** the business wallet groups multiple wallet
  instances (personal wallet of the employee, business instance, etc.) —
  a flow's **instance selector** (a WMP addressing expression in the
  flow input) routes each wallet-facing step to the right instance(s).
  A flow may present to instance A and deliver the issued credential to
  instance B.
- **Flow correlation:** WMP message ids tie responses back to flow
  instances (the engine keys pending steps by challenge handle, exactly
  the Mode B `challenge_handle` pattern, generalized to any
  response-bearing step).

**Open (§14):** which WMP profile/version, and how instance-selector
expressions are typed. The workspace has go-wmp/wmp references; a design
pass over the current spec draft is prerequisite to P-bw4 (§13).

---

## 8. Identity match — the generic concept, matchable primitives

### 8.1 What it is

**Identity match is the generic concept**: *does this presented credential
describe the same subject as this session (or this other credential)?*
The answer is assembled from **match primitives** — small, deterministic,
composable checks the flow language names. Pseudonym-based matching is
**one** way to do that, not the concept: not every credential carries a
pseudonym (non-PID credentials, EUCCs, SCAs), and not every
session-to-credential match can use one (the session may know the subject
only under different attributes, from a different authority).

Mode B has none of this; it is the genuinely new primitive family.

### 8.2 The built-in match vocabulary (v1)

Each primitive is a pure function over the context (presentation claims,
holder keys, session-known data), with a stable refusal code on mismatch:

| primitive | semantics |
|---|---|
| `same-key` | both presentations' holder keys (`cnf.jwk`/`DeviceKey`) are the same key (by thumbprint) — the strongest check when both credentials are key-bound to the same wallet |
| `claim-equals(a, b)` | the claim at context path `a` equals the value at path `b` (or a caller-supplied literal) — exact, format-aware path lookup (mdoc literal-key first, SD-JWT nested), mdoc full-date unwrap |
| `claims-hash` | **hash over a declared subset of the presented credential's claims, matched against data the session knows**: `{claims: [paths], alg, scope}` → the derived digest equals the session-supplied (or derived) value. This is the *generalized pseudonym*: a pseudonym (ADR 002) is the instance `{claims: [id, nonce], alg: sha-256, scope: rp}` — the flow declares the subset and the scope; the engine does not care whether the credential calls the result a pseudonym |
| `rule-match` | a **rule** (claim path → expected value) supplied by the flow's initiating caller, evaluated against one presentation — vc's `IdentityMatch` semantics (§Appendix B), the issuer-core §6.5 port generalized to any flow step |

`pseudonym` ships as a **named recipe** (a preset of `claims-hash` per
ADR 002: PID `id`+`nonce`, RP-scoped derivation), not a separate
primitive — a flow writes `claims-hash` with the ADR-002 parameters
explicitly, or references the recipe by name for readability. Determinism
is mandatory (ADR 002's rejection of fuzzy attribute matching): every
primitive is exact math; **no heuristics in the vocabulary**, and a
primitive that cannot resolve declares mismatch, never best-effort.

### 8.3 User-space hooks (the easy matcher path)

Built-ins never close the space: real deployments match on
attribute-shapes the vocabulary does not know (national identifiers,
organizational ids, derived keys). The flow language therefore has a
**first-class matcher extension point**:

```rust
/// One user-space match primitive (the easy hook).
trait MatchPrimitive {
    /// The name the flow language references (`match: <name>`).
    fn name(&self) -> &'static str;
    /// Evaluate: claims of the presentation(s) + the session-known
    /// data → verdict + recorded evidence (never raw values).
    fn matches(&self, inputs: MatchInputs<'_>) -> Result<MatchVerdict>;
}
```

- **Implementing one is deliberately trivial**: one struct, a name, a
  `matches` over typed inputs (presentation claims by step id, holder
  keys, session data) returning a verdict. No engine internals, no
  lifecycle, no I/O surface — user-space code stays small enough to
  review by inspection.
- Registered by name in deployment config, **allowlisted** per flow
  (a flow referencing an unregistered matcher is a load refusal — the
  plugin-allowlist discipline, §6.7).
- The engine treats a user-space matcher **exactly like a built-in**:
  same evidence recording (verdict + primitive name + parameters, never
  claim values), same refusal codes, same trust placement — a match
  primitive performs *math*, it never decides trust (§9).

### 8.4 Where the check sits in a flow

```yaml
  - match:
      pid-is-session-user:
        primitive: claims-hash      # or a user-space name
        claims: [id, nonce]        # the subset
        alg: sha-256
        scope: rp                  # RP-scoped derivation
        against: session.subject   # the session-known data
```

The step records `matched: true/false` in the context; the following
steps' `when:` matchers consume it. A failed match **fails the flow step**
(refusal, stable code) unless the flow explicitly branches — the default
is fail-closed, branching is opt-in and visible.

### 8.5 Relationship to the issuer-core §6.5 work

The pre-auth PID-present→bind→issue flow is **flow #1 in miniature** and
lands twice, deliberately:

1. **In issuer-core now** (in progress): config-gated, conformance
   profile untouched — the state machine already enforces
   presentation-before-redemption (a bound session starts
   `awaiting_authorization`; `claim_pre_auth_code` requires `offered`).
   No new states; the challenge machinery is reused. The rule shape is
   `rule-match` (vc's `IdentityMatch` port).
2. **Absorbed by bw-core** at P-bw1: the same flow as a
   `presentation → match → issuance` pipeline, with the issuer-core gate
   remaining for pure-issuer deployments.

### 8.6 Flow state machine + store

- One state machine per flow *instance* in the core (`language.rs`/
  `engine.rs`): states `pending → presenting → matching → issuing →
  issued` + `failed/expired`, illegal transitions refused with stable
  codes — the same shape as `session.rs`, new machine, same discipline.
- `FlowStore` trait: `insert`, `get`, `step` (transition), `arm/take`
  per response-bearing step (the `ModeBState`/`transaction` CAS
  discipline), `sweep`. In-memory reference + MongoDB production, behind
  `--features mongo` exactly as issuer-core.
- Events: the SSE stream shape (`(unix, state)` transitions + typed
  payload events) for the embedding frontend, plus WMP notifications.

---

## 9. Trust boundary

Unchanged from the family discipline, stated once:

- **go-trust decides, fail-closed.** Every *acceptability* question —
  may this flow run for this caller, may this presented credential be
  trusted, may this issuance proceed — is an AuthZEN query
  (`IssuanceTrustQuery`, `TrustQuery`, `WalletProviderTrustQuery` — the
  three existing decisions; flows may add evidence fields, not new
  decision bypasses).
- **Bindings are not trust.** `same-key`/`same-pseudonym` are math; the
  PDP never sees them, and they never substitute for a trust decision.
  A deployment wanting *policy over bindings* (e.g. "accept
  same-pseudonym only for MS X") expresses it as PDP rules over the
  binding *result* recorded in the evidence.

---

## 10. Security and PII properties

Carried up from issuer-core, unchanged in spirit:

1. **Subject data is sealed at rest** (vault), including
   `identity-match` rule values and presentation claims at rest.
   Context in memory only; never serialized whole, never logged.
2. **PII never transits error paths or logs** — refusals name paths and
   codes, never values.
3. **No standing subject index** — flow records key on handles, not
   subjects; the operator retains the flow↔subject mapping.
4. **Remote URLs are hostile I/O targets** — `fetch` providers enforce
   scheme/host policy, redirect caps, streaming budgets before
   allocation (verifier-core ts11 discipline).
5. **Stable machine-readable refusal codes** for every engine and
   primitive refusal.
6. **Signing through the Signer interface** — issuance inside flows uses
   issuer-core's signer (HSM-capable); bw-core adds no signing of its own.

---

## 11. Testing strategy

- **Fixture-backed flow definitions** (the goFF model): every shipped
  flow in `flows/` runs in CI against mock-core fixtures (recorded
  presentation responses, PDP doubles, plugin stubs) — a definition
  change is a visible diff against recorded output.
- **Core-level oracles**: presentation steps round-trip through
  verifier-core with real credentials (the wallet-core conformance
  fixtures); issuance rounds into verifier-core verification (the
  issuer-core P1 discipline).
- **Language tests**: every construct positive+negative, unknown-kind
  refusals, non-Turing-completeness guards (a definition with a
  computed `map` source is refused).
- **Conformance**: where WE BUILD publishes test-bed specs (the ITB),
  flow fixtures target them; the interop test bed is the external
  oracle.

---

## 12. Alternatives considered

- **Extend SUNET/vc's apigw instead** — vc's 48.6k LOC lives mostly in
  auth-provider plugins and the session machinery; adding a general flow
  language there couples business logic to a Go codebase we are
  replacing, and its plugin shape (Go interfaces) does not give the
  config/code boundary the ZK layer's exit criterion demands.
- **Temporal/Camunda/etc.** — general engines are Turing-complete by
  design, carry their own state stores and PII surfaces, and make the
  "subject data never transits the engine in plaintext" property
  unprovable. Rejected.
- **Compose via the existing HTTP surfaces (issuer-core +
  verifier-core as services)** — viable deployment mode, kept as a
  config option (§4.3), but in-process is the reference: fewer hops for
  sealed data, single trust boundary.

---

## 13. Phasing (proposal)

| Phase | Scope | Exit criterion |
|---|---|---|
| **P-bw1** | Language + engine + FlowStore + `presentation`/`binding(identity-match)`/`issuance`/`store`; flow #1 (PID→issue) in the language, parity-tested against the issuer-core §6.5 implementation | flow #1 definition-only; engine unchanged by a second flow's *data* |
| **P-bw2** | Multi-input presentations (one transaction, several inputs); `same-key`, `same-pseudonym`, `claim-equals`; flow #1 (company-bound SCA) end-to-end | §2.1 flow 1 in `flows/`, fixture-backed |
| **P-bw3** | `token` + `fetch` plugins, SAML/OIDC extraction; §2.1 flow 4 | plugin allowlist enforcement tested |
| **P-bw4** | WMP carrier integration (real WMP messages, instance selectors, flow correlation); §2.1 flows 2–3 | wallet instance round-trip over WMP |

---

## 14. Open questions (the iteration list)

1. **RESOLVED (2026-11-08, §5.3): the language.** YAML definitions,
   TOML deployment config, schema = JSON tree.
2. **`identity-match` primitives — settled in direction (§8), open in
   details.** The generic concept with built-in primitives
   (`same-key`, `claim-equals`, `claims-hash`, `rule-match`) + the
   `MatchPrimitive` user-space hook is agreed. Open: the exact
   `MatchInputs`/`MatchVerdict` surface (needs the P-bw1 implementation
   to pin), and whether `pseudonym` ships as a named recipe or a
   spelled-out `claims-hash` preset in the first fixtures.
3. **PDP placement in flows.** Explicit `pdp:` step (visible in the flow
   document) vs engine-boundary calls (implicit per primitive)?
   (Lean: engine-boundary — trust is a property of the boundary, not a
   flow authoring step; flows that want *policy gates* express them as
   `when:` over recorded evidence.)
4. **WMP profile/version** for P-bw4; instance-selector expression
   grammar. Needs a pass over the current WMP spec draft.
5. **Repo + naming.** `siros-bw-core` under sirosfoundation? Alternatives
   (`siros-business-wallet-core`?) if WE BUILD terminology should be
   avoided.
6. **issuance in-process vs sidecar** — confirm §4.3 recommendation as
   the reference path.
7. **Flow definition versioning** — definitions are data; how do we
   version their schema? (Lean: semver the language, record
   `language_version` per definition, refuse unknown versions at load —
   the circuit-catalog load discipline.)
8. **Where flows live.** Shipped in-repo (`flows/`, reviewed) vs loaded
   from deployment config (admin action)? Lean: both — in-repo flows are
   tested fixtures *and* installable; deployment-config flows require the
   same validation pass.
9. **`as`-aliasing and `fork:` scope semantics** (§5.2) — port goFF's
   snapshot-alias discipline into the context model, or keep only
   step-id keys? (Lean: step-ids are already stable names; `as` adds a
   second naming layer for copies — defer until a flow needs it.)

---

## Appendix A — the four flows, first-cut in the language

To be developed as the P-bw1/P-bw2 fixtures; kept here as the
vocabulary's acceptance test. Flow #1 draft appears in §5.1; the
remaining three follow the same shape (presentation sets, binding
blocks, declarative issuance subjects) and are exercises for the
definition schema rather than new engine surface.

## Appendix B — vc reference inventory (ported semantics)

- `pkg/openid4vci/identity_match.go` — `IdentityMatch`/`ClaimTest`/
  `Validate`/`ClaimPaths` → `identity-match` binding (§8.2).
- `internal/apigw/apiv1/identity_match.go` — `matchPresentedIdentity`,
  mdoc full-date unwrap → the binding's evaluation.
- `internal/apigw/apiv1/handlers_verifier_presentation.go` —
  `lookupClaimPath` (format-aware path resolution), `claimValueMatches`
  → generalized into `claim-equals` and the identity-match evaluator.