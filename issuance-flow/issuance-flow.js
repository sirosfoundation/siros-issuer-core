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
// polling as the fallback; the rendered subset is `offered → pending →
// issued → accepted / failed / expired`.
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
]);

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
  constructor({
    root,
    getSession,
    invocations = ["qr", "deep-link"],
    dcApi = null,
    pollMs = 3000,
    onPreview = null,
    onState = null,
    refreshHandle = null,
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
    // Optional refresh of the handle after issuance-relevant events
    // (default: re-fetch via getSession).
    this.refreshHandle = refreshHandle;
    this.runId = 0;
    this.handle = null;
    this.esr = null;
  }

  // Render (or re-render) a session by id: fetch, validate, display.
  async render(sessionId) {
    this.stop(); // supersedes any prior watch FIRST, then take the run id
    const run = ++this.runId;
    this.setStatus("Loading the issuance session…");
    const handle = validateHandle(await this.getSession(sessionId));
    if (run !== this.runId) return;
    this.handle = handle;
    this.root.replaceChildren();
    const section = document.createElement("section");
    section.className = "issuance-flow";
    section.append(this.renderState(handle));
    section.append(this.renderLaunch(handle));
    this.status = document.createElement("p");
    this.status.setAttribute("role", "status");
    this.status.className = "flow-status";
    section.append(this.status);
    this.root.append(section);
    this.emitState(handle.state ?? "offered");
    this.watch(handle);
    if (this.onPreview) this.onPreview(handle);
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
    };
    p.textContent = labels[handle.state] ?? handle.state ?? "Scan with your wallet";
    if (handle.expires_at) {
      const time = document.createElement("time");
      time.dateTime = handle.expires_at;
      time.textContent = new Date(handle.expires_at).toLocaleString();
      p.append(` — expires ${time.textContent}`);
    }
    return p;
  }

  renderLaunch(handle) {
    const actions = document.createElement("div");
    actions.className = "flow-actions";
    const offerUri = handle.offer_uri ?? null;
    const labels = { qr: "Scan QR code", "dc-api": "Issue to this device", "deep-link": "Open in wallet" };
    for (const mechanism of this.invocations) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = labels[mechanism];
      button.addEventListener("click", () => this.launch(mechanism).catch((error) => {
        this.setStatus(error.message || String(error));
      }));
      actions.append(button);
    }
    const section = document.createElement("div");
    section.className = "wallet-launch";
    section.append(actions);
    // The QR renders the offer URI — the same one a wallet would scan.
    if (this.invocations.includes("qr") && offerUri) {
      const qr = document.createElement("div");
      qr.className = "qr-code";
      if (handle.qr_svg) {
        // Server-rendered SVG (the backend served a data: URI).
        qr.innerHTML = handle.qr_svg;
      } else {
        qr.textContent = "Enable an image, or scan from the issuer page";
        qr.setAttribute("aria-label", "Credential offer QR code");
      }
      section.append(qr);
    }
    return section;
  }

  // Launch the chosen mechanism. DC-API: the shim's
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
  // polling as the fallback. One `runId`-checked loop; re-render on
  // user-visible transitions.
  async watch(handle) {
    const run = this.runId;
    const eventsUrl = typeof handle.status === "string" ? handle.status : null;
    if (eventsUrl && typeof window.EventSource === "function") {
      this.esr = new window.EventSource(eventsUrl);
      this.esr.onmessage = (event) => {
        if (run !== this.runId) return;
        try {
          const message = JSON.parse(event.data);
          this.emitState(message.state);
          if (this.isTerminal(message.state)) this.refresh(message.session_id ?? handle.session_id);
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
          this.emitState(refreshed.state);
          this.root.querySelector(".flow-state")?.replaceWith(this.renderState(refreshed));
          if (this.isTerminal(refreshed.state)) return;
        }
      } catch {
        // Transient fetch errors keep polling; the offer expiry
        // (backend-served) is authoritative.
      }
    }
  }

  isTerminal(state) {
    return ["accepted", "failed", "expired"].includes(state);
  }

  emitState(state) {
    if (this.onState) this.onState(state);
  }

  async refresh(sessionId) {
    const current = this.runId;
    const handle = await this.getSession(sessionId);
    if (current !== this.runId) return;
    this.root.querySelector(".flow-state")?.replaceWith(this.renderState(handle));
    this.emitState(handle.state);
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