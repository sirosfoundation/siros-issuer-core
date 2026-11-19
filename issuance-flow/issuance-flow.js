// Reusable, framework-free OpenID4VCI issuance flow — the UX surface only.
//
// The module never receives or requests claim values (design §10.1): its
// input vocabulary is `session_id`, `offer_uri`, `wallet_redirect`,
// `expires_at`, and state labels — all opaque handles the issuer's backend
// served. The embedding app supplies `getSession(id)` (a backend proxy it
// authenticates); the module calls it and renders.
//
// Invocation vocabulary (§10.2): "qr" (offer URI QR), "deep-link"
// (`openid-credential-offer://`), "dc-api" (same-device issuance via the
// `@sirosfoundation/dc-api` shim — used, not forked; graceful fallback to
// QR when the API is unavailable). Status: SSE when the backend offers it,
// polling as the fallback; the rendered subset is the §5.1 machine's
// user-visible arc `offered → redeeming → (pending) → issued → accepted /
// failed / expired / deleted`.
//
// Completion UX (§10.2.4): the launch surface (the QR and the buttons)
// retires the moment the wallet engages (redeeming/pending — the offer is
// spent; a waiting spinner takes its place) and the flow LANDS on the
// terminal states: success (issued — the credential was delivered;
// accepted — the wallet confirmed receipt) renders the delivery
// confirmation, failure (failed/expired/deleted) renders the failure copy,
// and the app-supplied `onTerminal(state, handle, landing)` appends its
// own next steps (the verifier link, the restart) to the landing node.
// Terminal ends the watch — `issued` is the UX's success; the
// credential_accepted notification that may follow is the backend's
// record refinement, not a further UX state.
//
// No OID4VCI protocol logic, no crypto, no claim handling, no trust
// decisions live here — the backend is authoritative for all of it.

export const SUPPORTED_INVOCATIONS = Object.freeze(["qr", "dc-api", "deep-link"]);

export const SUPPORTED_STATES = Object.freeze([
  "awaiting_authorization",
  "offered",
  "redeeming",
  "pending",
  "issued",
  "accepted",
  "failed",
  "expired",
  "deleted",
]);

// The completion UX's classification of the §5.1 machine (§10.2.3–§10.2.4):
// in-flight states retire the launch surface for the spinner; success and
// failure states land the flow. The rest (awaiting_authorization, offered)
// shows the launch surface.
const IN_FLIGHT_STATES = Object.freeze(["redeeming", "pending"]);
export const SUCCESS_STATES = Object.freeze(["issued", "accepted"]);
export const FAILURE_STATES = Object.freeze(["failed", "expired", "deleted"]);

// The offer window: the states where the session's expiry is the user's
// live concern (scan before the window closes). Past engagement the
// expiry is no longer decision-relevant — the spinner and the landing
// own the screen, and the session's expiry is not the credential's
// validity. Exported: the app's own offer affordances (a deep-link
// block outside the module's root) retire on the same classification —
// `onState` + this is the contract for hiding them.
export const OFFER_WINDOW_STATES = Object.freeze(["awaiting_authorization", "offered"]);

// The countdown label for an expiry instant: `m:ss` (or `h:mm:ss` over an
// hour), floored at `0:00` — the backend's own expired transition (the
// next poll or SSE frame away) is what lands the state line.
function countdownLabel(expiresAt) {
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (!Number.isFinite(ms) || ms <= 0) return "0:00";
  const secs = Math.ceil(ms / 1000);
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const two = (n) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${two(m)}:${two(s)}` : `${m}:${two(s)}`;
}

export function normalizeInvocations(values) {
  if (!Array.isArray(values)) throw new TypeError("invocations must be an array");
  const result = [...new Set(values)];
  if (!result.length || result.some((v) => !SUPPORTED_INVOCATIONS.includes(v))) {
    throw new RangeError(`invocations must contain only ${SUPPORTED_INVOCATIONS.join(", ")}`);
  }
  return result;
}

/// A session handle's input vocabulary (§10.1): every member opaque. The
/// module accepts the backend's verbatim response shape and refuses
/// anything carrying claim-shaped data — defense in depth for the
/// PII-free invariant.
const HANDLE_KEYS = Object.freeze([
  "session_id",
  "state",
  "offer_uri",
  "wallet_redirect",
  "qr_svg",
  "expires_at",
  "expires_at_unix",
  "status",
  "notification_id",
  "credential",
  "tx_code",
]);

export function validateHandle(handle) {
  if (typeof handle !== "object" || handle === null || Array.isArray(handle)) {
    throw new TypeError("handle must be an object of opaque backend fields");
  }
  if (typeof handle.session_id !== "string" || !handle.session_id) {
    throw new TypeError("handle.session_id is required");
  }
  // Vocabulary first: an unknown state label is a contract breach even
  // when an offer is present; usability (an offer) after.
  if (handle.state !== undefined && !SUPPORTED_STATES.includes(handle.state)) {
    throw new RangeError(`unknown session state ${handle.state}`);
  }
  if (typeof handle.offer_uri !== "string" && typeof handle.wallet_redirect !== "string") {
    throw new TypeError("handle needs offer_uri or wallet_redirect (an offer to hand over)");
  }
  return handle;
}

export class IssuanceFlow {
  // `getSession` fetches a session handle by id (the app's authenticated
  // backend proxy). `invocations` subset of SUPPORTED_INVOCATIONS.
  // `onPreview(handle)` (optional): called when a preview is possible; the
  // app renders consent from its own data (§10.2.5) — the module still
  // never touches claim values.
  // `qrLogo` (issue #12): string | URL — the issuer's or a partner's
  // logo, rendered as a centred badge OVER the server-rendered `qr_svg`
  // (an overlay, never baked into the matrix). `qrLogoSize`: the plate's
  // span as a % of the code's width (default 20 — ~4% of its area; the
  // level-H error-correction headroom covers it; see README "Branded
  // QR"). `qrLogoAlt`: the badge image's alt text.
  // `onTerminal(state, handle, landing)` (§10.2.4): called when the flow
  // lands — success (issued/accepted) or failure (failed/expired/
  // deleted). The app appends its own next steps to the landing node
  // (the verifier link, the restart); the landing is the app's to
  // restyle (`flow-landing flow-success|flow-failure`, `dataset.state`).
  constructor({
    root,
    getSession,
    invocations = ["qr", "deep-link"],
    dcApi = null,
    pollMs = 3000,
    onPreview = null,
    onState = null,
    onTerminal = null,
    refreshHandle = null,
    qrLogo = null,
    qrLogoSize = 20,
    qrLogoAlt = "Issuer logo",
  }) {
    // A browser (or the test's window stub — the module is DOM-thin).
    const env = typeof window !== "undefined" ? window : globalThis.window;
    if (!env || typeof env.HTMLElement !== "function") {
      throw new TypeError("IssuanceFlow runs in a browser");
    }
    if (!(root instanceof env.HTMLElement)) {
      throw new TypeError("root must be an HTMLElement");
    }
    if (typeof getSession !== "function") {
      throw new TypeError("getSession(sessionId) is required (the app's backend proxy)");
    }
    this.root = root;
    this.getSession = getSession;
    this.invocations = normalizeInvocations(invocations);
    // The DC-API shim: any subset of the @sirosfoundation/dc-api surface
    // the app injects (`{ isIssuanceAvailable, issueCredentialFromOffer }`
    // suffices). Absent → "dc-api" behaves as unavailable (QR fallback).
    this.dcApi = dcApi;
    this.pollMs = pollMs;
    this.onPreview = onPreview;
    this.onState = onState;
    this.onTerminal = onTerminal;
    // Optional refresh of the handle after issuance-relevant events
    // (default: re-fetch via getSession).
    this.refreshHandle = refreshHandle;
    // Branded QR (issue #12): the logo badge's source, size, alt.
    if (qrLogo !== null && qrLogo !== undefined) {
      if (qrLogo instanceof URL) qrLogo = qrLogo.href;
      if (typeof qrLogo !== "string" || !qrLogo.trim()) {
        throw new TypeError("qrLogo must be a non-empty string or URL");
      }
    } else {
      qrLogo = null;
    }
    if (typeof qrLogoSize !== "number" || !Number.isFinite(qrLogoSize) || qrLogoSize < 8 || qrLogoSize > 30) {
      throw new RangeError("qrLogoSize must be a number between 8 and 30 (percent of the code's width)");
    }
    if (typeof qrLogoAlt !== "string") {
      throw new TypeError("qrLogoAlt must be a string");
    }
    this.qrLogo = qrLogo;
    this.qrLogoSize = qrLogoSize;
    this.qrLogoAlt = qrLogoAlt;
    this.runId = 0;
    this.handle = null;
    this.esr = null;
    // The rendered flow's tracked rows (render/applyTransition own them;
    // no querySelector round-trips): the state line and the slot that
    // holds the launch surface → spinner → landing. The countdown
    // element is the state line's live <time> (renderState re-creates
    // it per transition; the ticker follows the reference).
    this.stateLine = null;
    this.slot = null;
    this.countdownEl = null;
  }

  // Render (or re-render) a session by id: fetch, validate, display.
  async render(sessionId) {
    this.stop(); // supersedes any prior watch FIRST, then take the run id
    const run = ++this.runId;
    this.setStatus("Loading the issuance session…");
    const handle = validateHandle(await this.getSession(sessionId));
    if (run !== this.runId) return;
    this.handle = handle;
    const state = handle.state ?? "offered";
    this.stateLine = this.renderState(handle);
    // The slot's initial occupant (§10.2.4): an already-terminal session
    // renders its landing (nothing to watch); an engaged wallet renders
    // the spinner (the offer is spent); anything else shows the launch
    // surface and the watch takes it from there.
    this.slot = this.slotFor(handle, state);
    this.root.replaceChildren();
    const section = document.createElement("section");
    section.className = "issuance-flow";
    section.append(this.stateLine);
    section.append(this.slot);
    this.status = document.createElement("p");
    this.status.setAttribute("role", "status");
    this.status.className = "flow-status";
    section.append(this.status);
    this.root.append(section);
    this.emitState(state);
    if (this.isTerminal(state)) {
      this.fireTerminal(handle, this.slot);
      return;
    }
    this.startCountdown();
    this.watch(handle);
    if (this.onPreview) this.onPreview(handle);
  }

  // The countdown ticker (§10.2.4): one per render lifecycle — a
  // self-terminating setTimeout chain guarded by the run id. Each tick
  // re-labels whatever the CURRENT state line's countdown element holds
  // (renderState re-creates it on transitions); it stops at 0:00 (the
  // backend's expired transition — the next poll or frame away — is
  // what lands the state line) and whenever superseded (stop() or a
  // re-render bumps the run id).
  startCountdown() {
    if (!this.countdownEl) return; // no expiry in the handle — nothing to tick
    const run = this.runId;
    const tick = () => {
      if (run !== this.runId) return;
      const el = this.countdownEl;
      if (!el) return;
      const label = countdownLabel(el.dateTime);
      if (el.textContent !== label) el.textContent = label;
      if (label === "0:00") return;
      window.setTimeout(tick, 1000);
    };
    window.setTimeout(tick, 1000);
  }

  // The slot for a state (Sonar S3358 wanted the nested ternary gone,
  // and the branch table reads better as itself): a terminal session
  // renders its landing (nothing to watch); an engaged wallet renders
  // the spinner (the offer is spent); anything else shows the launch
  // surface and the watch takes it from there.
  slotFor(handle, state) {
    if (this.isTerminal(state)) return this.renderLanding(handle);
    if (IN_FLIGHT_STATES.includes(state)) return this.renderSpinner();
    return this.renderLaunch(handle);
  }

  renderState(handle) {
    const p = document.createElement("p");
    p.className = `flow-state state-${handle.state ?? "offered"}`;
    p.dataset.state = handle.state ?? "offered";
    const labels = {
      awaiting_authorization: "Waiting for authorization",
      offered: "Scan or open with your wallet",
      redeeming: "Your wallet is redeeming the offer",
      pending: "Issuance in progress",
      issued: "Credential issued",
      accepted: "Stored in your wallet",
      failed: "Issuance failed",
      expired: "The offer expired",
      deleted: "Removed from your wallet",
    };
    p.textContent = labels[handle.state] ?? handle.state ?? "Scan with your wallet";
    // The offer window's countdown: while the offer is live, the expiry
    // is the user's ticking concern — a live m:ss inside the
    // machine-readable <time> element (either handle form: `expires_at`
    // ISO or `expires_at_unix` seconds — the issuer's session record).
    // Past the window the expiry is not decision-relevant (the spinner
    // and the landing own the screen; the session's expiry is not the
    // credential's validity), so nothing renders there.
    this.countdownEl = null;
    if (OFFER_WINDOW_STATES.includes(handle.state ?? "offered")) {
      const expiresAt = handle.expires_at
        ?? (typeof handle.expires_at_unix === "number"
          ? new Date(handle.expires_at_unix * 1000).toISOString()
          : null);
      if (expiresAt) {
        const time = document.createElement("time");
        time.dateTime = expiresAt;
        time.className = "flow-countdown";
        time.textContent = countdownLabel(expiresAt);
        p.append(" — expires in ", time);
        this.countdownEl = time;
      }
    }
    return p;
  }

  renderLaunch(handle) {
    const offerUri = handle.offer_uri ?? null;
    const section = document.createElement("div");
    section.className = "wallet-launch";
    // Buttons for the mechanisms that ACT (dc-api issues to this device,
    // deep-link navigates) — never for "qr": the code is its own
    // affordance, and a "Scan QR code" button over the code itself is a
    // demo artifact, not a launch surface.
    const labels = { "dc-api": "Issue to this device", "deep-link": "Open in wallet" };
    const acting = this.invocations.filter((mechanism) => mechanism !== "qr");
    if (acting.length) {
      const actions = document.createElement("div");
      actions.className = "flow-actions";
      for (const mechanism of acting) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = labels[mechanism];
        button.addEventListener("click", () => this.launch(mechanism).catch((error) => {
          this.setStatus(error.message || String(error));
        }));
        actions.append(button);
      }
      section.append(actions);
    }
    // The QR renders the offer URI — the same one a wallet would scan.
    if (this.invocations.includes("qr") && offerUri) {
      const qr = document.createElement("div");
      qr.className = "qr-code";
      if (handle.qr_svg) {
        // Server-rendered SVG (the backend served a data: URI). With a
        // `qrLogo`: the badge overlay (issue #12) — the plate + centred
        // logo over the SVG, never baked into the matrix.
        if (this.qrLogo) {
          qr.append(this.renderQrBadge(handle.qr_svg));
        } else {
          qr.innerHTML = handle.qr_svg;
        }
      } else {
        qr.textContent = "Enable an image, or scan from the issuer page";
        qr.setAttribute("aria-label", "Credential offer QR code");
      }
      section.append(qr);
    }
    return section;
  }

  // Launch the chosen mechanism. DC-API: the shim's
  // The branded-QR badge overlay (issue #12): a white, rounded plate
  // with the logo, absolutely centred over the server-rendered SVG.
  // The geometry is inline (structural — the overlay works without any
  // app CSS); the class names let an app restyle. The plate spans
  // `qrLogoSize`% of the code's WIDTH (~4% of its area at the default
  // 20) — the shape the realeyes demo proved scannable from a phone at
  // level H. The backend must render `qr_svg` at errorCorrectionLevel
  // 'H' when a badge is used (the module cannot change the matrix);
  // see README "Branded QR".
  renderQrBadge(svg) {
    const wrap = document.createElement("div");
    wrap.className = "qr-logo-wrap";
    const badge = document.createElement("div");
    badge.className = "qr-logo-badge";
    const logo = document.createElement("img");
    logo.className = "qr-logo";
    logo.src = this.qrLogo;
    logo.alt = this.qrLogoAlt;
    // The plate, over the code, centred, sized in the code's terms.
    wrap.style.position = "relative";
    wrap.style.display = "inline-block";
    badge.style.position = "absolute";
    badge.style.top = "50%";
    badge.style.left = "50%";
    badge.style.transform = "translate(-50%, -50%)";
    badge.style.width = `${this.qrLogoSize}%`;
    badge.style.aspectRatio = "1 / 1";
    // The plate: white, rounded, a subtle border — the logo sits inside
    // at ~78%, so its edges never touch the code's modules.
    badge.style.background = "#fff";
    badge.style.borderRadius = "10%";
    badge.style.border = "1px solid rgba(0, 0, 0, 0.12)";
    badge.style.display = "flex";
    badge.style.alignItems = "center";
    badge.style.justifyContent = "center";
    badge.style.boxSizing = "border-box";
    logo.style.width = "78%";
    logo.style.height = "auto";
    badge.append(logo);
    // The code first, the badge over it — the overlay, not the matrix.
    wrap.innerHTML = svg;
    wrap.append(badge);
    return wrap;
  }

  // The waiting surface (§10.2.4): the wallet engaged — the offer is
  // spent, the QR and buttons are dead weight. A self-contained SMIL
  // spinner (no CSS injection, no globals — the module is DOM-thin);
  // `flow-spinner`/`flow-spinner-label` let an app restyle or resize.
  renderSpinner() {
    const wrap = document.createElement("div");
    wrap.className = "flow-spinner";
    wrap.setAttribute("role", "status");
    wrap.setAttribute("aria-label", "Waiting for your wallet");
    wrap.innerHTML = `<svg viewBox="0 0 50 50" width="44" height="44" aria-hidden="true" focusable="false"><circle cx="25" cy="25" r="20" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" stroke-dasharray="90 36"><animateTransform attributeName="transform" type="rotate" from="0 25 25" to="360 25 25" dur="1.1s" repeatCount="indefinite"/></circle></svg>`;
    const label = document.createElement("p");
    label.className = "flow-spinner-label";
    label.textContent = "Waiting for your wallet…";
    wrap.append(label);
    return wrap;
  }

  // The landing (§10.2.4): success or failure, rendered from state labels
  // only. The outcome line carries the confirmation/refusal; the app's
  // own next steps (the verifier link on success, the restart on
  // failure) append via `onTerminal`, which receives the landing node.
  renderLanding(handle) {
    const state = handle.state;
    const success = SUCCESS_STATES.includes(state);
    const landing = document.createElement("div");
    landing.className = `flow-landing ${success ? "flow-success" : "flow-failure"}`;
    landing.dataset.state = state;
    const outcome = document.createElement("p");
    outcome.className = "flow-outcome";
    outcome.setAttribute("role", "status");
    outcome.textContent = success
      ? "Successfully delivered credential"
      : {
          failed: "The credential could not be delivered",
          expired: "The offer expired before the wallet redeemed it",
          deleted: "The wallet removed the credential",
        }[state] ?? "The issuance did not complete";
    landing.append(outcome);
    return landing;
  }

  // Apply a state transition to the rendered flow. Both watch paths —
  // SSE frames and poll refreshes — route through here, so the DOM
  // behaviour is identical either way. Returns true when the transition
  // landed the flow (terminal — the watch ends).
  applyTransition(handle) {
    const state = handle.state ?? "offered";
    // An unchanged, non-terminal state is a no-op (the SSE stream's
    // initial full-handle frame repeats the rendered state; repeated
    // in-flight frames arrive as the wallet works).
    if (state === this.handle?.state && !this.isTerminal(state)) return false;
    this.handle = handle;
    const line = this.renderState(handle);
    this.stateLine?.replaceWith(line);
    this.stateLine = line;
    this.emitState(state);
    if (this.isTerminal(state)) {
      const landing = this.renderLanding(handle);
      this.slot?.replaceWith(landing);
      this.slot = landing;
      this.stop();
      this.fireTerminal(handle, landing);
      return true;
    }
    if (IN_FLIGHT_STATES.includes(state) && this.slot?.className !== "flow-spinner") {
      const spinner = this.renderSpinner();
      this.slot?.replaceWith(spinner);
      this.slot = spinner;
    }
    return false;
  }

  fireTerminal(handle, landing) {
    if (this.onTerminal) this.onTerminal(handle.state, handle, landing);
  }

  // `issueCredentialFromOffer` — null (unavailable) falls back to QR.
  async launch(mechanism) {
    const handle = this.handle;
    if (!handle) throw new Error("render(sessionId) first");
    if (mechanism === "deep-link") {
      const link = handle.wallet_redirect ?? handle.offer_uri;
      if (!link) throw new Error("No offer link available");
      window.location.assign(link);
      return;
    }
    if (mechanism === "qr") {
      this.setStatus("Scan the QR code with your wallet…");
      return;
    }
    if (mechanism === "dc-api") {
      const offer = handle.wallet_redirect ?? handle.offer_uri;
      if (!this.dcApi || typeof this.dcApi.issueCredentialFromOffer !== "function") {
        throw new Error("Digital Credentials API is unavailable here — scan the QR code instead");
      }
      if (typeof this.dcApi.isIssuanceAvailable === "function" && !this.dcApi.isIssuanceAvailable()) {
        throw new Error("This browser cannot issue to a wallet natively — scan the QR code instead");
      }
      this.setStatus("Waiting for your wallet…");
      const result = await this.dcApi.issueCredentialFromOffer(offer);
      if (!result) {
        this.setStatus("No wallet accepted the offer natively — scan the QR code instead");
        return;
      }
      this.setStatus("Issued to your wallet.");
    }
  }

  // Status: SSE when the backend offers it (`status` — an events URL),
  // polling as the fallback. One `runId`-checked loop; every transition
  // — engagement (spinner) and terminal (landing) included — applies
  // through `applyTransition`, so both paths render identically.
  async watch(handle) {
    const run = this.runId;
    const eventsUrl = typeof handle.status === "string" ? handle.status : null;
    if (eventsUrl && typeof window.EventSource === "function") {
      this.esr = new window.EventSource(eventsUrl);
      this.esr.onmessage = (event) => {
        if (run !== this.runId) return;
        try {
          const message = JSON.parse(event.data);
          if (!message.state) return;
          if (this.isTerminal(message.state)) {
            // A terminal frame carries only {session_id, state, unix};
            // the landing wants the full fresh handle — fetch and
            // apply (the fetch's runId guard supersedes this frame's;
            // a failed fetch is the same supersession — the next poll
            // or SSE frame re-lands, never an unhandled rejection).
            this.refresh(message.session_id ?? handle.session_id).catch(() => {});
          } else {
            // An in-flight frame needs only the state; the rest of the
            // handle is already current.
            this.applyTransition({ ...this.handle, state: message.state });
          }
        } catch {
          // A non-JSON event frame: ignore (the SSE stream also carries
          // comments/keepalives on some backends).
        }
      };
      this.esr.onerror = () => {
        // SSE dropped (proxy timeout, network): fall back to polling —
        // do not lose the session.
        if (run === this.runId && this.esr) {
          this.esr.close();
          this.esr = null;
          this.poll(handle, run);
        }
      };
      return;
    }
    this.poll(handle, run);
  }

  async poll(handle, run) {
    while (run === this.runId) {
      await new Promise((resolve) => window.setTimeout(resolve, this.pollMs));
      if (run !== this.runId) return;
      try {
        const refreshed = validateHandle(
          await (this.refreshHandle
            ? this.refreshHandle(handle.session_id)
            : this.getSession(handle.session_id)),
        );
        if (run !== this.runId) return;
        if (refreshed.state !== this.handle?.state) {
          if (this.applyTransition(refreshed)) return;
        }
      } catch {
        // Transient fetch errors keep polling; the offer expiry
        // (backend-served) is authoritative.
      }
    }
  }

  // The UX's terminal set (§10.2.4): success and failure land the flow.
  // `issued` lands success — the credential was delivered; the
  // credential_accepted notification that may follow is the backend's
  // record refinement, not a further UX state.
  isTerminal(state) {
    return SUCCESS_STATES.includes(state) || FAILURE_STATES.includes(state);
  }

  emitState(state) {
    if (this.onState) this.onState(state);
  }

  // Fetch the full fresh handle and apply it (the SSE terminal path: a
  // frame carries {session_id, state, unix} only, and the landing wants
  // the whole handle).
  async refresh(sessionId) {
    const current = this.runId;
    const handle = await this.getSession(sessionId);
    if (current !== this.runId) return;
    this.applyTransition(handle);
  }

  setStatus(text) {
    if (!this.status) return;
    this.status.textContent = text;
  }

  stop() {
    this.runId += 1;
    if (this.esr) {
      this.esr.close();
      this.esr = null;
    }
  }
}