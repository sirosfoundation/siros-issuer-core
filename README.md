# siros-issuer-core

Reusable Rust building blocks and a deployable service for **issuing** digital
credentials — the issuance-side mirror of
[siros-verifier-core](https://github.com/sirosfoundation/siros-verifier-core).

Design document: [`siros-issuer-core-design.md`][] (in the design repo). The
scope, invariants and phase plan live there; this workspace implements them.

## Layout

| Crate | Contents |
|---|---|
| `siros-issuer-core` | Sans-I/O core: OID4VCI metadata generation from the TS11 catalog, the issuance session state machine, go-trust AuthZEN query construction, siros-status-service wire types |
| `siros-issuer-service` | Deployable HTTP service: config (TOML), bounded catalog transport + refresh, wallet-facing well-knowns, readiness |

Verification, TS 119 602 / TS11 schema parsing, and status-list formats come
from `siros-verifier-core` (pinned git rev) — issuance never re-implements
them. Trust decisions are external (go-trust, fail-closed). Revocation state
lives in [siros-status-service](https://github.com/sirosfoundation/siros-status-service).

## Status

**P0 (scaffold)** — catalog-driven `/.well-known/openid-credential-issuer`
generation, catalog load/refresh (live registry or fixture mode), session
state machine, service skeleton.

**P1 (pre-authorized grant)** — implemented and cross-verified in CI.

**P2 (both grants, OIDF conformance COMPLETE)** — the full OIDF
`oid4vci-1_0-issuer-test-plan` issuer suite passes against this issuer,
both variants (11/14 passed, 3 profile-scope skips, 0 failed): pre-authorized
issuance, wallet-initiated issuance over PAR + Mode A login handoff +
PKCE + RFC 7523 private_key_jwt client auth, DPoP sender-constraining,
credential error responses with registered error codes, request/response
encryption, RFC 9207 `iss` authorization responses, RFC 9901 §10.1
timestamp rounding, and the full negative module set. See
`docs/siros-issuer-core-design.md` §16.3 for the complete fix inventory.

**P3 (mso_mdoc + ZK capability layer)** — in progress: the mdoc
issuance core (`mdoc_issue.rs`) and ZK capability primitives (`zk.rs`)
are built and oracle-verified against verifier-core's mdoc verifier
(COSE_Sign1 via the HSM-capable `Signer`, MSO digests, RFC 9901
validityInfo rounding, catalog-pinned salt policy). Remaining: service
wiring, the nym_auth rulebook, Mode B, and the mdoc conformance
variants.

## Run (fixtures, no network)

```sh
cargo run -p siros-issuer-service -- testdata/config.fixtures.toml
curl http://127.0.0.1:8080/.well-known/openid-credential-issuer
```

## Build and test

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

[`siros-issuer-core-design.md`]: https://github.com/sirosfoundation/siros-issuer-core/blob/main/docs/siros-issuer-core-design.md
