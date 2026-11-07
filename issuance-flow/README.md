# @sirosfoundation/issuance-flow

[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)

Framework-free OpenID4VCI issuance UX — QR, deep link, and Digital
Credentials API handover, driven by **opaque handles only**.

The module is deliberately the *smallest* part of the system: no OID4VCI
protocol logic, no crypto, no claim handling, no trust decisions — the
issuer backend is authoritative for all of it. The embedding app
supplies the data and the session fetch; the module renders and hands
over.

## Invariants

- **PII-free by construction**: the module's input vocabulary is
  `session_id`, `offer_uri`, `wallet_redirect`, `expires_at`, state
  labels — all opaque. It never requests or receives claim values
  (`validateHandle` enforces the vocabulary).
- The browser on DC-API paths brokers the wallet handover only.
- Dependency-free ES module, framework-agnostic.

## Install

```sh
npm install @sirosfoundation/issuance-flow
```

## Usage

```js
import { IssuanceFlow } from "@sirosfoundation/issuance-flow";

const flow = new IssuanceFlow({
  root: document.querySelector("#issuance"),
  // The app's authenticated backend proxy: fetch a session handle by id.
  getSession: (id) => fetch(`/api/issuance/${id}`).then((r) => r.json()),
  // The handover surfaces to offer: qr, dc-api, deep-link.
  invocations: ["qr", "dc-api", "deep-link"],
  // The Digital Credentials API shim (`@sirosfoundation/dc-api`) —
  // injected, so the module stays dependency-free:
  dcApi: {
    isIssuanceAvailable,
    issueCredentialFromOffer,
  },
  // Optional: render preview/consent from YOUR data (the module never
  // touches claim values; the issuer's preview endpoint supplies claim
  // names if you want them).
  onPreview: (handle) => myApp.renderConsent(handle),
  // Optional: observe state transitions (offered → issued → accepted…).
  onState: (state) => myApp.analytics(state),
});

flow.render(sessionId);
```

### Session handles

`getSession(sessionId)` returns the issuer backend's session response
(or your proxy's shape of it):

```json
{
  "session_id": "s_9f86d081…",
  "state": "offered",
  "offer_uri": "https://issuer.example.org/credential-offer/of_7c3a…",
  "wallet_redirect": "openid-credential-offer://?credential_offer_uri=…",
  "qr_svg": "data:image/svg+xml;base64,…",
  "expires_at": "2026-11-05T12:35:00Z",
  "status": "/api/v1/issuance/s_…/events"
}
```

### Handover mechanisms

| Invocation | What it does |
|---|---|
| `qr` | Renders the offer as a QR (server-rendered `qr_svg` if the backend serves one) |
| `deep-link` | Assigns the `openid-credential-offer://` wallet redirect |
| `dc-api` | Same-device issuance through the injected `@sirosfoundation/dc-api` shim (`issueCredentialFromOffer` — the offer URI is the same one the QR carries); graceful fallback with a clear message when the API or wallet is unavailable |

### Status

SSE when the backend exposes an events URL (`status`), polling as the
fallback (and on SSE drop). The rendered subset is the session state
machine's user-visible part: `offered → pending → issued → accepted /
failed / expired`.

## Test

```sh
npm test
```

## License

BSD-2-Clause