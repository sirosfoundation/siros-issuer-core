# siros-issuer-core

[![CI](https://github.com/sirosfoundation/siros-issuer-core/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-issuer-core/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40sirosfoundation%2Fissuance-flow)](https://www.npmjs.com/package/@sirosfoundation/issuance-flow)
[![License: BSD-2-Clause](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

Reusable Rust building blocks and a deployable service for **issuing** digital
credentials — the issuance-side mirror of
[siros-verifier-core](https://github.com/sirosfoundation/siros-verifier-core).

The core separates OID4VCI metadata generation, the issuance session state
machine, and credential construction from transport, storage, time, key
management, and trust policy. **All issuance trust decisions are delegated to
a tenant-configured policy decision point, normally
[go-trust](https://github.com/sirosfoundation/go-trust), over AuthZEN.** TS 119
602 / TS11 schema parsing and status-list formats come from the pinned
`siros-verifier-core` dependency — issuance never re-implements them. Revocation
state lives in
[siros-status-service](https://github.com/sirosfoundation/siros-status-service).

**OIDF conformance:** the `oid4vci-1_0-issuer-test-plan` issuer suite passes
**13/14 modules on all four variants** (both credential formats × both
grants), 0 failed — the one skip per variant is the suite's own proof-module
selection split.

## Supported issuance flows

| Flow | Functionality |
| --- | --- |
| SD-JWT VC over OpenID4VCI | Both grants (pre-authorized, authorization_code over PAR+PKCE), RFC 7523 client auth, DPoP sender-constraining, request/response encryption, signed metadata, batch issuance |
| ISO/IEC 18013-5 mdoc | COSE_Sign1 issuer authentication, key-attestation proofs (Appendix D.1), full-dates (RFC 8943), ISO 18013-5 DS-certificate profile, batch issuance |
| `nym_auth` ZK credentials | Circuit-catalog salt resolution per proof system×doctype, hash commitments and HKDF derivations, auxiliary-data response extension — nym_auth is rulebook #1 on a generalized capability layer |
| Authorization modes | Mode A: integrator login handoff. Mode B: OpenID4VP presentation (verifier-core embedded in-process) with DPoP sender-constrained codes |

## Choose an integration

### 1. Deploy the issuer service

`siros-issuer-service` serves the wallet-facing OID4VCI surface (both grants,
both modes) and the backend session API for integrating applications, with
TOML configuration, sealed subject-data vault, and SSE session events.

```sh
cargo build --release -p siros-issuer-service

SIROS_ISSUER_CONFIG=config.toml ./target/release/siros-issuer-service
```

Configuration reference: [`config.example.toml`](config.example.toml).
Design document (the normative source for scope and invariants):
[`docs/siros-issuer-core-design.md`](docs/siros-issuer-core-design.md).

The backend session API — the integrating application's one-call contract:

```rust,ignore
POST /api/v1/issuance/sessions            // push subject data (sealed at rest), get an offer URI
POST /api/v1/issuance/sessions/{id}/authorize   // Mode A: your app authenticated the user
GET  /api/v1/issuance/sessions/{id}/events      // SSE of state transitions
POST /api/v1/issuance/sessions/{id}/revoke     // flip the status-list bit
```

### 2. Embed the core

`siros-issuer-core` is the sans-I/O crate: catalog-driven OID4VCI metadata
generation, the session state machine shared by both grants and both
authorization modes, mdoc issuance (MSO builder, COSE_Sign1), the ZK
capability layer, and the `Signer` trait (HSM-resident keys supported — no
code path requires private key material in memory).

### 3. Embed the UX module

[`@sirosfoundation/issuance-flow`](issuance-flow/) is the framework-free
browser module: QR / deep-link / [Digital Credentials
API](https://github.com/sirosfoundation/dc-api) handover, driven by **opaque
handles only** — the module never receives or requests claim values.

```sh
npm install @sirosfoundation/issuance-flow
```

## Storage, signing, and trust

| Concern | Owner |
| --- | --- |
| Session storage | Pluggable `SessionStore`: in-memory (default), MongoDB (`--features mongo`, CAS single-use claims, TTL retention) |
| Signing | The `Signer` trait: in-memory JWK (dev), PKCS#11 HSM (`[signing.pkcs11]`, kryptering/cryptoki) — SoftHSM-proven in CI |
| Trust decisions | go-trust PDP over AuthZEN, fail-closed |
| Subject data | Sealed at rest (vault), bounded retention with a sweeper, never logged, never on any GET surface |
| Revocation | siros-status-service (status-list allocation per credential) |

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace                 # 75 tests
cargo test --locked --features mongo -p siros-issuer-service   # the Mongo backend (needs a mongod)
cd issuance-flow && npm test                     # the UX module
```

Conformance (in [siros-conformance](https://github.com/sirosfoundation/siros-conformance)):
`make up-issuer-core && make test-issuer-core` — the OIDF suite against the
Docker image, all four variants.

## License

BSD-2-Clause