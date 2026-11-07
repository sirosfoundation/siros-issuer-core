# Agent guide: siros-issuer-core

## Scope and invariants

This workspace contains the sans-I/O issuance core and the deployable HTTP
service. The authoritative design is `siros-issuer-core-design.md` (§3.3
scope guards and §7.2/§7.3 are normative). Keep changes small and
protocol-specific.

- **The core owns issuance protocol logic.** OID4VCI metadata generation,
  the session state machine, trust-query construction and status wire types
  have one implementation. UI, service plumbing and deployment fixtures must
  not keep a second copy.
- **The core is sans-I/O.** Transport, storage, time and trust verdicts
  belong to the service. Do not hide I/O in protocol code; effects cross
  explicit interfaces.
- **Verification is embedded, not re-implemented.** TS 119 602/TS11 parsing,
  presentation verification (Mode B) and status-list formats come from the
  pinned `siros-verifier-core` dependency. Upgrade it deliberately, pinned
  rev by pinned rev.
- **go-trust makes every trust decision**, fail-closed. The core constructs
  AuthZEN evidence and consumes a permit; it never creates a local trust
  fallback or a development bypass. A missing PDP is `pdp_unavailable`, not
  a permit.
- **The catalog is authoritative and fail-closed.** A schema that does not
  parse, does not verify, or is absent is refused, never patched up. A
  failed refresh keeps the last good catalog; startup without a catalog is
  fatal. Credential resolution is unambiguous or refused.
- **Remote URLs are hostile I/O targets.** Scheme/host policy from
  verifier-core's ts11, redirect caps, streaming byte budgets before
  allocation.
- **Subject data never transits the core's error paths or logs.** Sealed at
  rest in the service, bounded retention, no standing subject index
  (integrators retain the session↔subject mapping, decision D5).
- **Both grants and both authorization modes share one session state
  machine.** Never add a parallel path; new capability enters as an event or
  a mode on the existing machine.
- **ZK is a capability layer; nym_auth is one rulebook.** Rulebooks are
  code against the capability traits (decision D9), sometimes plus config.
  The circuit catalog's fail-closed salt semantics (ported from vc's
  `zk_salt.go`) are verbatim: a pin never overrides a live refusal.
- **Signing goes through the signer interface — HSMs supported.** All issuer
  signatures (credentials, status-service client assertions) cross
  `signer::Signer`; no code path may require private key material in memory.
  The in-memory JWK is one provider (dev/tests); PKCS#11 via kryptering's
  `cryptoki` is the production provider — the verifier-core ReaderAuth
  precedent. Selection is configuration. `kid`s come from configuration or
  the public handle, never derived from private material.
- **Errors and refusals have stable machine-readable codes** and never leak
  subject data, openings or seeds.

## Configuration rules

- Service configuration is TOML (`config.example.toml` is the canonical
  example). Deployment settings never leak into the core.
- `catalog` has exactly one of `static_dir` (fixtures/air-gapped) or
  `mirrors` (live registry); anything else is a startup refusal.
- HTTP is allowed only on loopback (dev). All other URLs must be HTTPS.

## Tests

- New tests live outside the source files, in each crate's `tests/`
  directory, and exercise the public API. No `#[test]` or `#[cfg(test)]`
  under `src/`; do not widen visibility for a test.
- Every test enforces a source of truth outside the code it tests: the
  design document's state machine, OpenID4VCI 1.0 ID1, TS 119 602, or the
  verifier-core catalog contract. Delete a test whose expected value comes
  from the implementation.
- One test per guarantee, positive and negative cases, stable refusal codes.
  Every regression test must fail when its fix is reverted.

## Working rules

- Cite the specification for non-obvious behavior (`OpenID4VCI 1.0 ID1`,
  `TS 119 602`, `draft-ietf-oauth-status-list`, the nym_auth rulebook). Do
  not use another implementation as an unstated specification — vc is the
  reference for *ported semantics*, cited in the design doc's Appendix A.
- Do not run `git commit`, `git push`, `git rebase`, `git reset`, or create
  a tag unless the user explicitly approved that operation.
- Fix every review finding and every instance of the same bug class. Merge
  only reviewed, green PRs.

## Build and test

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```
