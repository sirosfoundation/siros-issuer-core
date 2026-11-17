// Issuance-flow unit tests (node:test). The DOM is stubbed minimally: the
// module is DOM-thin by design (§10 — no framework, no claims).
//
// Sources of truth: the design invariants — §10.1 (the module's vocabulary
// is opaque handles ONLY), §10.2 (QR / deep-link / DC-API with fallback),
// §10.2.3 (SSE with polling fallback), §10.3 (no protocol logic).

import test from "node:test";
import assert from "node:assert/strict";

import {
  SUPPORTED_INVOCATIONS,
  SUPPORTED_STATES,
  normalizeInvocations,
  validateHandle,
  IssuanceFlow,
} from "./issuance-flow.js";

// The browser stub the module runs against (set BEFORE constructing).
const windowStub = {
  HTMLElement: function HTMLElement() {},
  EventSource: undefined,
  // The browser has no process-exit semantics; node's loop must not be
  // held by a stubbed page timer (the poll loop's pending wake would
  // keep a CI runner alive past the tests). unref: the loop drains.
  setTimeout: (fn, ms, ...args) => setTimeout(fn, ms, ...args).unref(),
  location: { assign: () => {} },
};
globalThis.window = windowStub;
globalThis.document = {
  createElement: () => ({
    children: [],
    dataset: {},
    style: {},
    append(...kids) {
      this.children.push(...kids);
    },
    replaceChildren(...kids) {
      this.children = kids;
    },
    replaceWith() {},
    addEventListener() {},
    setAttribute() {},
    querySelector: () => null,
    textContent: "",
  }),
};

const element = () => {
  const el = Object.create(windowStub.HTMLElement.prototype);
  el.children = [];
  el.dataset = {};
  el.style = {};
  el.append = function (...kids) {
    this.children.push(...kids);
  };
  el.replaceChildren = function (...kids) {
    this.children = kids;
  };
  el.querySelector = () => null;
  return el;
};

// ─── Vocabulary (§10.1) ─────────────────────────────────────────────────────

test("invocations normalize and reject unknowns", () => {
  assert.deepEqual(normalizeInvocations(["qr", "dc-api"]), ["qr", "dc-api"]);
  assert.deepEqual(normalizeInvocations(["qr", "qr"]), ["qr"]);
  assert.throws(() => normalizeInvocations([]), RangeError);
  assert.throws(() => normalizeInvocations(["nfc"]), RangeError);
  assert.throws(() => normalizeInvocations("qr"), TypeError);
});

test("the handle vocabulary is opaque handles only", () => {
  validateHandle({ session_id: "s_1", offer_uri: "https://i.example/o/1", state: "offered" });
  validateHandle({
    session_id: "s_1",
    wallet_redirect: "openid-credential-offer://?credential_offer_uri=https://i.example/o/1",
  });
  // The state labels the module understands (the §5.1 machine's subset).
  for (const state of SUPPORTED_STATES) {
    validateHandle({ session_id: "s", state, offer_uri: "https://i.example/o/1" });
  }
  assert.throws(() => validateHandle(null), TypeError);
  assert.throws(() => validateHandle([]), TypeError);
  assert.throws(() => validateHandle({}), TypeError); // no session_id
  assert.throws(() => validateHandle({ session_id: "" }), TypeError);
  // Neither offer surface: a handle without an offer is unusable.
  assert.throws(() => validateHandle({ session_id: "s" }), TypeError);
  // Unknown state: refuse rather than render a nonsense label — even
  // when an offer IS present (vocabulary precedes usability).
  assert.throws(
    () => validateHandle({ session_id: "s", state: "quantum", offer_uri: "https://i.example/o" }),
    RangeError,
  );
});

test("SUPPORTED_INVOCATIONS is the closed set", () => {
  assert.deepEqual([...SUPPORTED_INVOCATIONS], ["qr", "dc-api", "deep-link"]);
});

test("construct validates its inputs", () => {
  assert.throws(() => new IssuanceFlow({ root: element() }), TypeError); // getSession required
  assert.throws(() => new IssuanceFlow({ root: {}, getSession: async () => ({}) }), TypeError);
  assert.throws(
    () =>
      new IssuanceFlow({
        root: element(),
        getSession: async () => ({}),
        invocations: ["telepathy"],
      }),
    RangeError,
  );
});

// ─── Mechanisms (§10.2) ──────────────────────────────────────────────────────

test("deep-link launch assigns the wallet redirect", async () => {
  let assigned = null;
  const flow = new IssuanceFlow({
    root: element(),
    getSession: async () => ({
      session_id: "s1",
      state: "offered",
      wallet_redirect: "openid-credential-offer://?credential_offer_uri=x",
      offer_uri: "https://i.example/o/1",
    }),
    invocations: ["deep-link"],
  });
  globalThis.window = { ...windowStub, location: { assign: (u) => (assigned = u) } };
  await flow.render("s1");
  await flow.launch("deep-link");
  assert.equal(assigned, "openid-credential-offer://?credential_offer_uri=x");
  globalThis.window = windowStub;
});

test("dc-api falls back with a clear message when the shim is absent", async () => {
  const flow = new IssuanceFlow({
    root: element(),
    getSession: async () => ({ session_id: "s1", state: "offered", offer_uri: "https://i.example/o/1" }),
    invocations: ["dc-api"],
    dcApi: null, // shim absent
    pollMs: 5,
  });
  try {
    await flow.render("s1");
    await assert.rejects(() => flow.launch("dc-api"), /unavailable.*QR/s);
  } finally {
    flow.stop();
  }
});

test("dc-api issues through the shim and reports null as fallback", async () => {
  const calls = [];
  const flow = new IssuanceFlow({
    root: element(),
    getSession: async () => ({ session_id: "s1", state: "offered", offer_uri: "https://i.example/o/1" }),
    invocations: ["dc-api"],
    pollMs: 5,
    dcApi: {
      isIssuanceAvailable: () => true,
      issueCredentialFromOffer: async (offer) => {
        calls.push(offer);
        return null; // no wallet accepted
      },
    },
  });
  try {
    await flow.render("s1");
    await flow.launch("dc-api");
    assert.equal(calls.length, 1);
    assert.equal(calls[0], "https://i.example/o/1");
    assert.match(flow.status?.textContent ?? "", /scan the QR/s);
  } finally {
    flow.stop();
  }
});

test("dc-api availability is checked before the shim is called", async () => {
  let called = false;
  const flow = new IssuanceFlow({
    root: element(),
    getSession: async () => ({ session_id: "s1", state: "offered", offer_uri: "https://i.example/o/1" }),
    invocations: ["dc-api"],
    pollMs: 5,
    dcApi: {
      isIssuanceAvailable: () => false,
      issueCredentialFromOffer: async () => {
        called = true;
      },
    },
  });
  try {
    await flow.render("s1");
    await assert.rejects(() => flow.launch("dc-api"), /cannot issue to a wallet natively/);
    assert.equal(called, false);
  } finally {
    flow.stop();
  }
});

// ─── Status (§10.2.3) ───────────────────────────────────────────────────────

test("polling fallback drives state transitions from re-fetched handles", async () => {
  const states = ["offered", "redeeming", "issued", "accepted"];
  let i = 0;
  const seen = [];
  const flow = new IssuanceFlow({
    root: element(),
    getSession: async () => ({
      session_id: "s1",
      state: states[Math.min(i, states.length - 1)],
      offer_uri: "https://i.example/o/1",
    }),
    invocations: ["qr"],
    pollMs: 1,
    onState: (state) => seen.push(state),
  });
  try {
    await flow.render("s1");
    await new Promise((r) => setTimeout(r, 30));
    i = 3;
    await new Promise((r) => setTimeout(r, 30));
    assert.ok(seen.includes("accepted"), `states: ${seen.join(",")}`);
  } finally {
    flow.stop();
  }
});

test("render emits the current state and the module never fetches beyond the app proxy", async () => {
  const seen = [];
  const flow = new IssuanceFlow({
    root: element(),
    getSession: async (id) => {
      seen.push(id);
      return { id, session_id: id, state: "offered", offer_uri: "https://i.example/o/1" };
    },
    invocations: ["qr"],
  });
  try {
    await flow.render("abc");
    assert.deepEqual(seen, ["abc"]);
    assert.equal(flow.root.children.length, 1); // the section
  } finally {
    flow.stop();
  }
});

// ─── Branded QR (issue #12) ───────────────────────────────────────────────────

// The QR structure walker: the rendered launch section's .qr-code div.
const qrCodeOf = (root) => {
  const find = (node, className) => {
    for (const kid of node.children ?? []) {
      if (kid.className === className) return kid;
      const hit = find(kid, className);
      if (hit) return hit;
    }
    return null;
  };
  return find(root, "qr-code");
};

test("qrLogo validates its inputs", () => {
  const base = { root: element(), getSession: async () => ({}) };
  // string and URL are the source shapes; empty and non-string refuse.
  new IssuanceFlow({ ...base, qrLogo: "/img/logo.png" }); // eslint-disable-line no-new
  new IssuanceFlow({ ...base, qrLogo: new URL("https://i.example/logo.png") }); // eslint-disable-line no-new
  assert.throws(() => new IssuanceFlow({ ...base, qrLogo: "" }), TypeError);
  assert.throws(() => new IssuanceFlow({ ...base, qrLogo: 42 }), TypeError);
  // The size window: the level-H headroom (a plate wider than 30% of the
  // code is not scannable at any level; narrower than 8% is not a badge).
  assert.throws(() => new IssuanceFlow({ ...base, qrLogo: "/l.png", qrLogoSize: 45 }), RangeError);
  assert.throws(() => new IssuanceFlow({ ...base, qrLogo: "/l.png", qrLogoSize: 5 }), RangeError);
  assert.throws(() => new IssuanceFlow({ ...base, qrLogo: "/l.png", qrLogoSize: "big" }), RangeError);
  assert.throws(() => new IssuanceFlow({ ...base, qrLogo: "/l.png", qrLogoAlt: null }), TypeError);
});

test("qrLogo renders the badge overlay on the server SVG — never baked into the matrix", async () => {
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => ({
      session_id: "s1",
      state: "offered",
      offer_uri: "https://i.example/o/1",
      qr_svg: "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
    }),
    invocations: ["qr"],
    qrLogo: "/img/siros-logo.png",
  });
  await flow.render("s1");
  const qr = qrCodeOf(root);
  assert.ok(qr, "the qr-code block renders");
  const wrap = qr.children.find((kid) => kid.className === "qr-logo-wrap");
  assert.ok(wrap, "the overlay wrap renders");
  // The server's SVG, verbatim inside the wrap — the badge is an overlay
  // ON the code, never baked into the matrix.
  assert.equal(wrap.innerHTML, "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>");
  const badge = wrap.children.find((kid) => kid.className === "qr-logo-badge");
  assert.ok(badge, "the badge plate renders");
  const [logo] = badge.children;
  assert.equal(logo.src, "/img/siros-logo.png");
  assert.equal(logo.alt, "Issuer logo");
  // The geometry: absolutely centred, sized in the code's terms (20% of
  // the width at the default), on a white rounded plate.
  assert.equal(badge.style.position, "absolute");
  assert.equal(badge.style.top, "50%");
  assert.equal(badge.style.left, "50%");
  assert.equal(badge.style.transform, "translate(-50%, -50%)");
  assert.equal(badge.style.width, "20%");
  assert.equal(badge.style.background, "#fff");
});

test("a URL qrLogo renders its href; a custom size and alt render", async () => {
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => ({
      session_id: "s1",
      state: "offered",
      offer_uri: "https://i.example/o/1",
      qr_svg: "<svg></svg>",
    }),
    invocations: ["qr"],
    qrLogo: new URL("https://brand.example/logo.svg"),
    qrLogoSize: 30,
    qrLogoAlt: "Brand logo",
  });
  await flow.render("s1");
  const wrap = qrCodeOf(root).children.find((kid) => kid.className === "qr-logo-wrap");
  const badge = wrap.children.find((kid) => kid.className === "qr-logo-badge");
  const [logo] = badge.children;
  assert.equal(logo.src, "https://brand.example/logo.svg");
  assert.equal(logo.alt, "Brand logo");
  assert.equal(badge.style.width, "30%");
});

test("without qrLogo the QR renders exactly as before (server SVG injected, no wrap)", async () => {
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => ({
      session_id: "s1",
      state: "offered",
      offer_uri: "https://i.example/o/1",
      qr_svg: "<svg></svg>",
    }),
    invocations: ["qr"],
  });
  await flow.render("s1");
  const qr = qrCodeOf(root);
  assert.equal(qr.innerHTML, "<svg></svg>", "the SVG injects directly — no overlay");
  assert.ok(!qr.children.some((kid) => kid.className === "qr-logo-wrap"));
});

test("qrLogo with no server SVG keeps the fallback (the badge never renders without a code)", async () => {
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => ({
      session_id: "s1",
      state: "offered",
      offer_uri: "https://i.example/o/1",
    }),
    invocations: ["qr"],
    qrLogo: "/img/logo.png",
  });
  await flow.render("s1");
  const qr = qrCodeOf(root);
  assert.ok(!qr.children.some((kid) => kid.className === "qr-logo-wrap"), "no badge without a code");
});
