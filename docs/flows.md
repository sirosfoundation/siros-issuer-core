# Flows: the orchestration layer

The flow orchestration layer lives in **`sirosfoundation/siros-flow-core`**
— its authoritative design doc, the flow language, the P-bw1 skeleton,
and the reviewed flow definitions (`flows/`), including the definitions
that express this issuer's hard-coded presentation flows:

- `ehic-pid-presentation` — the Mode B shape (§7.3): present a PID,
  issue the EHIC with the subject from the PID's verified claims;
- `preauth-pid-issue` — the §6.5 pre-auth binding's parity target.

The migration question — retiring the hard-coded paths here once
flow-core deployments front them — is the flow-core design doc's §14
Q12. The OIDF conformance profile drives Mode B through this
repository's own surface and is unaffected either way.
