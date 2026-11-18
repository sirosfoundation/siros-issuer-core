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
  SUCCESS_STATES,
  FAILURE_STATES,
  OFFER_WINDOW_STATES,
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

// One functional element factory for every stub surface (the document's
// createElement AND the test roots): parent-tracked append and
// replaceWith, so the module's slot swaps (launch → spinner → landing)
// are observable in the tree. The module is DOM-thin; this is the whole
// DOM it gets.
const makeElement = (className = "") => {
  const el = Object.create(windowStub.HTMLElement.prototype);
  el.children = [];
  el.className = className;
  el.dataset = {};
  el.style = {};
  el.textContent = "";
  el.append = function (...kids) {
    for (const kid of kids) if (kid && typeof kid === "object") kid.parent = this;
    this.children.push(...kids);
  };
  el.replaceChildren = function (...kids) {
    this.children = [];
    this.append(...kids);
  };
  el.replaceWith = function (...nodes) {
    const at = this.parent ? this.parent.children.indexOf(this) : -1;
    if (at === -1) return;
    this.parent.children.splice(at, 1, ...nodes);
    for (const node of nodes) node.parent = this.parent;
  };
  el.addEventListener = () => {};
  el.setAttribute = (name, value) => {
    el[name] = value;
  };
  el.querySelector = () => null;
  return el;
};

globalThis.document = { createElement: () => makeElement() };

const element = () => makeElement();

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

// ─── Completion UX (§10.2.4) ─────────────────────────────────────────────────
//
// Sources of truth: design §10.2.3 (the §5.1 machine's user-visible arc —
// offered → redeeming → (pending) → issued → accepted / failed / expired /
// deleted) and §10.2.4 (completion UX: success/failure rendering from
// state labels only; the app's next steps arrive via onTerminal). The
// realeyes issuer proved the arc live (wia-probe: offered → redeeming →
// issued, the credential_accepted notification → accepted).

// The rendered section's row by class name (the state line, the slot).
// The slot's rows carry compound classes (flow-landing flow-success) —
// match by member, not by the whole string.
const rowOf = (root, className) => {
  const section = root.children[0];
  return (
    section?.children.find(
      (kid) => typeof kid.className === "string" && kid.className.split(/\s+/).includes(className),
    ) ?? null
  );
};

test("the terminal classification covers the §5.1 machine's landing states", () => {
  assert.deepEqual([...SUCCESS_STATES], ["issued", "accepted"]);
  assert.deepEqual([...FAILURE_STATES], ["failed", "expired", "deleted"]);
  // issued lands success: the credential was DELIVERED — the
  // accepted notification that may follow refines the backend's
  // record, not the UX.
  for (const state of SUPPORTED_STATES) {
    const flow = new IssuanceFlow({ root: element(), getSession: async () => ({}) });
    const expected = SUCCESS_STATES.includes(state) || FAILURE_STATES.includes(state);
    assert.equal(flow.isTerminal(state), expected, state);
  }
});

test("deleted is part of the state vocabulary (the wallet CAN report removal)", () => {
  assert.ok(SUPPORTED_STATES.includes("deleted"));
  validateHandle({ session_id: "s", state: "deleted", offer_uri: "https://i.example/o/1" });
});

test("the launch surface retires to the spinner when the wallet engages", async () => {
  const states = ["offered", "redeeming"];
  let i = 0;
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => ({
      session_id: "s1",
      state: states[Math.min(i, 1)],
      offer_uri: "https://i.example/o/1",
    }),
    invocations: ["qr"],
    pollMs: 1,
  });
  try {
    await flow.render("s1");
    assert.ok(rowOf(root, "wallet-launch"), "offered renders the launch surface");
    assert.ok(!rowOf(root, "flow-spinner"));
    i = 1;
    await new Promise((r) => setTimeout(r, 30));
    const spinner = rowOf(root, "flow-spinner");
    assert.ok(spinner, "redeeming retires the launch for the spinner");
    assert.ok(!rowOf(root, "wallet-launch"), "the QR and buttons are gone — the offer is spent");
    assert.equal(spinner.role, "status");
    assert.match(spinner.children.at(-1).textContent, /Waiting for your wallet/);
  } finally {
    flow.stop();
  }
});

test("issued lands the success copy, hands the app the landing, and ends the watch", async () => {
  const states = ["offered", "issued"];
  let i = 0;
  let fetches = 0;
  const seen = [];
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => {
      fetches += 1;
      return { session_id: "s1", state: states[Math.min(i, 1)], offer_uri: "https://i.example/o/1" };
    },
    invocations: ["qr"],
    pollMs: 1,
    onState: (state) => seen.push(state),
    onTerminal: (state, handle, landing) => seen.push({ terminal: state, handle, landing }),
  });
  try {
    await flow.render("s1");
    i = 1;
    await new Promise((r) => setTimeout(r, 30));
    const landed = seen.find((s) => typeof s === "object");
    assert.ok(landed, "onTerminal fired");
    assert.equal(landed.terminal, "issued");
    assert.equal(landed.handle.session_id, "s1");
    assert.equal(landed.landing.className, "flow-landing flow-success");
    assert.match(landed.landing.children[0].textContent, /Successfully delivered credential/);
    // The watch ended: no further fetches after the landing.
    const fetchesAtLanding = fetches;
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(fetches, fetchesAtLanding, "terminal ended the watch");
    assert.ok(rowOf(root, "flow-landing"), "the landing holds the slot");
  } finally {
    flow.stop();
  }
});

test("accepted lands the same success (the wallet confirmed receipt)", async () => {
  const states = ["offered", "redeeming", "accepted"];
  let i = 0;
  const seen = [];
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => ({
      session_id: "s1",
      state: states[Math.min(i, 2)],
      offer_uri: "https://i.example/o/1",
    }),
    invocations: ["qr"],
    pollMs: 1,
    onTerminal: (state) => seen.push(state),
  });
  try {
    await flow.render("s1");
    i = 2;
    await new Promise((r) => setTimeout(r, 30));
    assert.deepEqual(seen, ["accepted"]);
    assert.match(rowOf(root, "flow-landing").children[0].textContent, /Successfully delivered credential/);
  } finally {
    flow.stop();
  }
});

test("failure states land the failure copy", async () => {
  for (const [state, copy] of [
    ["failed", /could not be delivered/],
    ["expired", /expired before the wallet redeemed it/],
    ["deleted", /removed the credential/],
  ]) {
    const states = ["offered", state];
    let i = 0;
    const root = element();
    const flow = new IssuanceFlow({
      root,
      getSession: async () => ({
        session_id: "s1",
        state: states[Math.min(i, 1)],
        offer_uri: "https://i.example/o/1",
      }),
      invocations: ["qr"],
      pollMs: 1,
    });
    try {
      await flow.render("s1");
      i = 1;
      await new Promise((r) => setTimeout(r, 30));
      const landing = rowOf(root, "flow-landing");
      assert.equal(landing.className, "flow-landing flow-failure", state);
      assert.match(landing.children[0].textContent, copy);
    } finally {
      flow.stop();
    }
  }
});

test("an already-terminal session renders its landing without watching", async () => {
  let fetches = 0;
  const seen = [];
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => {
      fetches += 1;
      return { session_id: "s1", state: "issued", offer_uri: "https://i.example/o/1" };
    },
    invocations: ["qr"],
    pollMs: 1,
    onTerminal: (state) => seen.push(state),
  });
  try {
    await flow.render("s1");
    assert.deepEqual(seen, ["issued"]);
    assert.ok(rowOf(root, "flow-landing"), "the landing renders immediately");
    assert.ok(!rowOf(root, "wallet-launch"), "no launch surface for a landed session");
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(fetches, 1, "no watch was started");
  } finally {
    flow.stop();
  }
});

test("expires_at_unix renders the expiry (the issuer's session record form)", async () => {
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => ({
      session_id: "s1",
      state: "offered",
      offer_uri: "https://i.example/o/1",
      expires_at_unix: 1795000000,
    }),
    invocations: ["qr"],
  });
  try {
    await flow.render("s1");
    const line = rowOf(root, "flow-state");
    const time = line.children.find((kid) => kid.dateTime !== undefined);
    assert.ok(time, "the expiry renders from the unix form");
    assert.equal(time.dateTime, new Date(1795000000 * 1000).toISOString());
  } finally {
    flow.stop();
  }
});

test("SSE frames drive the same transitions as polling (spinner, then landing)", async () => {
  const instances = [];
  class FakeEventSource {
    constructor(url) {
      this.url = url;
      instances.push(this);
    }
    close() {
      this.closed = true;
    }
  }
  const offered = {
    session_id: "s1",
    state: "offered",
    offer_uri: "https://i.example/o/1",
    status: "/api/v1/issuance/sessions/s1/events",
  };
  const issued = { ...offered, state: "issued", status: undefined };
  let fetches = 0;
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => {
      fetches += 1;
      return fetches === 1 ? offered : issued;
    },
    invocations: ["qr"],
    pollMs: 1,
  });
  globalThis.window = { ...windowStub, EventSource: FakeEventSource };
  try {
    await flow.render("s1");
    const es = instances.at(-1);
    assert.ok(es, "the SSE stream opened on the handle's status URL");
    // The stream's initial full-handle frame repeats the rendered
    // state: a no-op, not a duplicate emission or a slot swap.
    es.onmessage({ data: JSON.stringify(offered) });
    assert.ok(rowOf(root, "wallet-launch"), "the repeated frame changed nothing");
    // Engagement: the spinner replaces the launch.
    es.onmessage({ data: JSON.stringify({ session_id: "s1", state: "redeeming", unix: 1 }) });
    assert.ok(rowOf(root, "flow-spinner"), "an in-flight frame retires the launch");
    // Terminal: the landing needs the full fresh handle — the refresh
    // fetch applies it.
    es.onmessage({ data: JSON.stringify({ session_id: "s1", state: "issued", unix: 2 }) });
    await new Promise((r) => setTimeout(r, 10));
    const landing = rowOf(root, "flow-landing");
    assert.ok(landing, "a terminal frame lands the flow");
    assert.match(landing.children[0].textContent, /Successfully delivered credential/);
    assert.ok(es.closed, "the stream closes at terminal");
    assert.equal(fetches, 2, "the terminal frame triggered exactly one full-handle refresh");
  } finally {
    globalThis.window = windowStub;
    flow.stop();
  }
});

// ─── The offer window's countdown (§10.2.4) ───────────────────────────────────
//
// Source of truth: design §10.2.3 (the handle's expiry is part of the
// vocabulary) + the offer-window classification — the expiry is the
// user's live concern only while the offer is scannable; the countdown
// floors at 0:00 and the backend's expired transition lands the state.

test("OFFER_WINDOW_STATES is the offer-window classification", () => {
  assert.deepEqual([...OFFER_WINDOW_STATES], ["awaiting_authorization", "offered"]);
});

test("the offer window renders a live m:ss countdown (either expiry form)", async () => {
  for (const handle of [
    { session_id: "s1", state: "offered", offer_uri: "https://i.example/o/1", expires_at: new Date(Date.now() + 14 * 60 * 1000).toISOString() },
    { session_id: "s1", state: "offered", offer_uri: "https://i.example/o/1", expires_at_unix: Math.floor(Date.now() / 1000) + 14 * 60 },
  ]) {
    const root = element();
    const flow = new IssuanceFlow({ root, getSession: async () => handle, invocations: ["qr"] });
    try {
      await flow.render("s1");
      const line = rowOf(root, "flow-state");
      const time = line.children.find((kid) => kid.className === "flow-countdown");
      assert.ok(time, "the countdown renders inside the state line");
      assert.match(time.textContent, /^\d{1,2}:\d{2}$/, `m:ss label, got ${time.textContent}`);
      // The machine-readable instant rides the element either way.
      assert.ok(time.dateTime?.startsWith("2"), "dateTime carries the ISO instant");
    } finally {
      flow.stop();
    }
  }
});

test("a countdown over an hour renders h:mm:ss; a past expiry floors at 0:00", async () => {
  const cases = [
    [new Date(Date.now() + 25 * 3600 * 1000).toISOString(), /^\d{1,3}:\d{2}:\d{2}$/],
    [new Date(Date.now() - 60 * 1000).toISOString(), "0:00"],
  ];
  for (const [expiresAt, expected] of cases) {
    const root = element();
    const flow = new IssuanceFlow({
      root,
      getSession: async () => ({ session_id: "s1", state: "offered", offer_uri: "https://i.example/o/1", expires_at: expiresAt }),
      invocations: ["qr"],
    });
    try {
      await flow.render("s1");
      const time = rowOf(root, "flow-state").children.find((kid) => kid.className === "flow-countdown");
      assert.ok(time);
      if (typeof expected === "string") assert.equal(time.textContent, expected);
      else assert.match(time.textContent, expected);
    } finally {
      flow.stop();
    }
  }
});

test("the countdown ticks live (a wide CI margin: two tick windows)", async () => {
  // The ticker is a 1-second chain; a LOADED CI runner can lag a timer
  // by hundreds of ms, so the observation window carries TWO tick
  // opportunities — any lag short of a full missed second still shows
  // the label move.
  const expiresAt = new Date(Date.now() + 5000).toISOString();
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => ({ session_id: "s1", state: "offered", offer_uri: "https://i.example/o/1", expires_at: expiresAt }),
    invocations: ["qr"],
  });
  try {
    await flow.render("s1");
    const time = () => rowOf(root, "flow-state").children.find((kid) => kid.className === "flow-countdown");
    const first = time().textContent;
    assert.match(first, /^0:0[45]$/, `the window opens at ~5s: ${first}`);
    await new Promise((r) => setTimeout(r, 2400)); // two tick windows
    const second = time().textContent;
    assert.ok(second < first, `the label ticked down (${first} -> ${second})`);
  } finally {
    flow.stop();
  }
});

test("the countdown floors at zero and the ticker stops (the backend lands the state)", async () => {
  // The floor check, decoupled from the tick check: a short window,
  // a long settle, and the label pinned at 0:00 — the backend's own
  // expired transition (a poll or frame away) is what lands the state.
  const expiresAt = new Date(Date.now() + 1200).toISOString();
  const root = element();
  const flow = new IssuanceFlow({
    root,
    getSession: async () => ({ session_id: "s1", state: "offered", offer_uri: "https://i.example/o/1", expires_at: expiresAt }),
    invocations: ["qr"],
  });
  try {
    await flow.render("s1");
    const time = () => rowOf(root, "flow-state").children.find((kid) => kid.className === "flow-countdown");
    await new Promise((r) => setTimeout(r, 2600)); // past zero
    assert.equal(time().textContent, "0:00", "floored at zero");
    await new Promise((r) => setTimeout(r, 1300)); // and the ticker stopped
    assert.equal(time().textContent, "0:00", "still 0:00 — the chain self-terminated");
  } finally {
    flow.stop();
  }
});

test("the countdown is scoped to the offer window — engagement and landing drop it", async () => {
  for (const state of ["redeeming", "pending", "issued", "accepted", "failed"]) {
    const root = element();
    const flow = new IssuanceFlow({
      root,
      getSession: async () => ({
        session_id: "s1", state, offer_uri: "https://i.example/o/1",
        expires_at: new Date(Date.now() + 14 * 60 * 1000).toISOString(),
      }),
      invocations: ["qr"],
      pollMs: 1,
    });
    try {
      await flow.render("s1");
      const line = rowOf(root, "flow-state");
      assert.ok(!line.children.some((kid) => kid.className === "flow-countdown"), `${state} carries no countdown`);
      assert.ok(!line.children.some((kid) => typeof kid === "string" && kid.includes("expires")), `${state} carries no expiry text`);
      flow.stop();
    } catch (e) {
      flow.stop();
      throw e;
    }
  }
});
