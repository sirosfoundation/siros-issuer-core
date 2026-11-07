// A minimal demo page for the issuance-flow module — served statically,
// it needs a session id and a backend proxy. LOCAL DEMO ONLY: the demo
// fixture session contains no real personal data.
//
// Serve: npx serve . (or any static server), then open demo.html.

import { IssuanceFlow } from "./issuance-flow.js";

// A demo getSession returning a fixture handle (no real session, no real
// data — QR rendering needs a QR backend or a library, which the demo
// stubs with a placeholder).
const getSession = async (id) => ({
  session_id: id,
  state: "offered",
  offer_uri: `https://issuer.example.org/credential-offer/of_${id}`,
  wallet_redirect: `openid-credential-offer://?credential_offer_uri=https://issuer.example.org/credential-offer/of_${id}`,
  expires_at: new Date(Date.now() + 300_000).toISOString(),
  status: null, // no SSE in the demo → polling fallback
});

const flow = new IssuanceFlow({
  root: document.querySelector("#issuance"),
  getSession,
  invocations: ["qr", "deep-link"],
  pollMs: 2000,
  onState: (state) => console.log("session state:", state),
});

flow.render("demo-session-1").catch(console.error);