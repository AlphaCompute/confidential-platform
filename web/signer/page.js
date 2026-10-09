"use strict";

const WASM_URL = "@WASM_URL@";
const WASM_SRI = "@WASM_SRI@";

const VERSION_KEY = "alphacompute-platform-version";
const TICKET = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CODE = /^[A-Za-z_]{1,64}$/;
// shroud-go limits its public routes to 5 requests per second per IP.
const PACE_MS = 250;
const MAX_RETRY_AFTER_S = 10;
// The KMS accepts issued_at within five minutes of its clock; one minute is left for the network.
const MAX_SKEW_MS = 240000;
const PROMPT_MS = 120000;
const ES256 = -7;
// SubjectPublicKeyInfo of an uncompressed P-256 key, up to the point's 64 coordinate bytes: the
// only form the KMS accepts.
const P256_SPKI_PREFIX = [
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
const P256_SPKI_LENGTH = 91;
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;

const MESSAGES = {
  framed: "This page cannot run inside another page. Open the link in its own tab.",
  no_passkeys: "This browser cannot use passkeys. Open this link in Safari, Chrome, Edge or Firefox.",
  bad_link: "This link is not valid.",
  platform: "The platform document did not verify. Do not continue; contact AlphaCompute.",
  older_platform: "This page was given an older platform document than one seen before. Do not continue.",
  not_signer: "This page is not served from an AlphaCompute signer address.",
  unexpected: "Something went wrong on this page. Nothing was signed. Reload to try again.",
  unavailable: "The service is unavailable. Try again in a minute.",
  rate_limited: "Too many requests from this network. Wait a minute and try again.",
  clock: (minutes) =>
    `Your device clock is off by about ${minutes} minutes. Correct it and reload.`,
  claim_closed: "This claim link is closed. Ask your AlphaCompute contact for a new link.",
  claim_expired: "This claim link has expired. Ask your AlphaCompute contact for a new link.",
  other_tab:
    "This link was already opened in another tab or on another device. Ask your AlphaCompute contact for a new link.",
  prompt_closed: "The passkey prompt was closed. Try again.",
  passkey_failed: "The passkey prompt failed. Try again, or open this link in another browser.",
  already_registered:
    "This device already holds a passkey for this organization; use another device or provider.",
  unusable_key:
    "This passkey cannot be used: it did not give a P-256 public key. Use another device or provider.",
  not_confirmed: "Not confirmed by the KMS.",
  conflict: "The service refused this step because it was already done. Reload to see where it stands.",
  signature_invalid: "The KMS did not accept the passkey's signature. Nothing was changed.",
  already_exists: "The KMS already holds this. Reload to see where it stands.",
  kms_refused: (code) => `The KMS refused this request (${code}).`,
  yours: "This organization is yours.",
  synced: "Synced passkey (backed up by your provider)",
  device_bound: "Device-bound passkey: if you lose this device you lose this key",
};

const CODES = {
  SHROUD_NOT_FOUND: MESSAGES.bad_link,
  SHROUD_SERVICE_UNAVAILABLE: MESSAGES.unavailable,
  SHROUD_RATE_LIMITED: MESSAGES.rate_limited,
  SHROUD_UPSTREAM_INVALID: MESSAGES.not_confirmed,
  SHROUD_CONFLICT: MESSAGES.conflict,
  rate_limited: MESSAGES.rate_limited,
  sealed: MESSAGES.unavailable,
  signature_invalid: MESSAGES.signature_invalid,
  already_exists: MESSAGES.already_exists,
};

function message(key, arg) {
  const m = MESSAGES[key];
  return typeof m === "function" ? m(arg) : m;
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function stop(text) {
  document.getElementById("main").replaceChildren(el("p", text, "refusal"));
}

function refuse(key, arg) {
  stop(message(key, arg));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function bytesOf(data) {
  return ArrayBuffer.isView(data)
    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    : new Uint8Array(data);
}

function utf8(text) {
  return new TextEncoder().encode(text);
}

function b64u(data) {
  let binary = "";
  for (const b of bytesOf(data)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64u(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url");
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function random(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

function equalBytes(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function fingerprint(spki) {
  const hex = wasm_bindgen.bodySha256(spki).slice("sha256:".length);
  return `sha256:${hex.match(/.{4}/g).join(" ")}`;
}

function issuedAt() {
  return new Date(Date.now()).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// Every JSON the page reads goes through the wasm parser, which refuses a repeated key.
function readJson(text) {
  return JSON.parse(wasm_bindgen.canonicalJson(text));
}

function storedVersion() {
  try {
    const v = Number(localStorage.getItem(VERSION_KEY));
    return Number.isSafeInteger(v) ? v : 0;
  } catch (_) {
    return 0;
  }
}

function storeVersion(version) {
  try {
    localStorage.setItem(VERSION_KEY, String(version));
  } catch (_) {
    // Private modes may refuse storage; the check is best effort by design.
  }
}

let lastCall = -Infinity;

// One call to shroud-go. A 429 is answered before anything is relayed, so the identical request
// is sent once more after Retry-After.
async function api(view, method, path, bodyText) {
  for (let attempt = 0; ; attempt += 1) {
    const wait = lastCall + PACE_MS - Date.now();
    if (wait > 0) await sleep(wait);
    lastCall = Date.now();
    let reply;
    try {
      reply = await fetch(view.signer.api_origin + path, {
        method,
        headers: bodyText === undefined ? {} : { "Content-Type": "application/json" },
        body: bodyText,
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
    } catch (_) {
      return { status: 0, body: null };
    }
    if (reply.status === 429 && attempt === 0) {
      const after = Number(reply.headers.get("Retry-After"));
      const seconds = Number.isFinite(after) && after >= 0 ? Math.min(after, MAX_RETRY_AFTER_S) : 1;
      await sleep(seconds * 1000);
      continue;
    }
    try {
      const text = await reply.text();
      return { status: reply.status, body: text ? readJson(text) : null };
    } catch (_) {
      return { status: 0, body: null };
    }
  }
}

function errorCode(body) {
  if (!body || typeof body !== "object") return "";
  if (typeof body.error_code === "string") return body.error_code;
  if (body.error && typeof body.error === "object" && typeof body.error.code === "string") {
    return body.error.code;
  }
  return "";
}

// The fixed sentence for a failed call; the server's own text never reaches the page.
function failure(reply) {
  if (reply.status === 0) return MESSAGES.unavailable;
  const code = errorCode(reply.body);
  if (Object.prototype.hasOwnProperty.call(CODES, code)) return CODES[code];
  if (CODE.test(code)) return message("kms_refused", code);
  if (reply.status === 404) return MESSAGES.bad_link;
  return MESSAGES.unavailable;
}

function clockRefusal(serverTime) {
  const server = typeof serverTime === "string" ? Date.parse(serverTime) : NaN;
  if (!Number.isFinite(server)) return MESSAGES.unavailable;
  const skew = Math.abs(server - Date.now());
  return skew > MAX_SKEW_MS ? message("clock", Math.round(skew / 60000)) : null;
}

function revisionsJson(view) {
  return JSON.stringify(view.kms_revisions.map((r) => r.compose_hash));
}

// The response the KMS signed for exactly `sentText`, or null.
function receipt(view, reply, route, sentText, response) {
  try {
    const expected = { route, request_sha256: wasm_bindgen.bodySha256(utf8(sentText)), response };
    const signed = wasm_bindgen.verifyKmsReceipt(
      JSON.stringify(reply.body.receipt),
      view.kms_ca_pem,
      revisionsJson(view),
      JSON.stringify(expected),
    );
    return JSON.parse(signed);
  } catch (_) {
    return null;
  }
}

function credentialList(ids) {
  return ids.map((id) => ({ type: "public-key", id: unb64u(id) }));
}

function createOptions(view, orgName, excludeIds) {
  const name = `${orgName} · AlphaCompute`;
  return {
    rp: { id: view.signer.rp_id, name: "AlphaCompute" },
    user: { id: random(32), name, displayName: name },
    challenge: random(32),
    pubKeyCredParams: [{ type: "public-key", alg: ES256 }],
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    },
    attestation: "none",
    excludeCredentials: credentialList(excludeIds),
    extensions: { credProps: true },
    timeout: PROMPT_MS,
  };
}

function getOptions(view, challenge, allowIds) {
  return {
    challenge,
    rpId: view.signer.rp_id,
    allowCredentials: credentialList(allowIds),
    userVerification: "required",
    timeout: PROMPT_MS,
  };
}

// The click handler's first await, so the browser still sees the user's gesture.
async function passkey(kind, publicKey) {
  try {
    const credential = await navigator.credentials[kind]({ publicKey });
    return credential ? { credential } : { note: MESSAGES.passkey_failed };
  } catch (e) {
    const name = e && e.name;
    if (kind === "create" && name === "InvalidStateError") {
      return { note: MESSAGES.already_registered };
    }
    if (name === "NotAllowedError" || name === "AbortError") return { note: MESSAGES.prompt_closed };
    return { note: MESSAGES.passkey_failed };
  }
}

// `{id, spki, backed_up}` of a new credential, or null unless its key is ES256 in the one SPKI
// form the KMS accepts.
function createdKey(credential) {
  const r = credential.response;
  if (!r || typeof r.getPublicKey !== "function" || typeof r.getAuthenticatorData !== "function") {
    return null;
  }
  if (typeof r.getPublicKeyAlgorithm !== "function" || r.getPublicKeyAlgorithm() !== ES256) {
    return null;
  }
  const raw = r.getPublicKey();
  if (!raw) return null;
  const spki = bytesOf(raw);
  if (spki.length !== P256_SPKI_LENGTH || !P256_SPKI_PREFIX.every((b, i) => spki[i] === b)) {
    return null;
  }
  const authData = bytesOf(r.getAuthenticatorData());
  if (authData.length < 37) return null;
  return {
    id: b64u(credential.rawId),
    spki: b64u(spki),
    backed_up: (authData[32] & FLAG_BE) !== 0,
  };
}

function signatureObject(assertion, keyId) {
  const r = assertion.response;
  const signature = {
    algorithm: "webauthn-es256",
    signature: b64u(r.signature),
    authenticator_data: b64u(r.authenticatorData),
    client_data_json: b64u(r.clientDataJSON),
  };
  if (keyId !== undefined) signature.key_id = keyId;
  return signature;
}

function keyIdOf(rawId, credentials) {
  const id = b64u(rawId);
  const found = credentials.find((c) => c.credential_id === id);
  return found ? found.key_id : null;
}

function button(label, action) {
  const b = el("button", label);
  b.type = "button";
  b.addEventListener("click", async () => {
    if (b.disabled) return;
    b.disabled = true;
    try {
      await action();
    } catch (_) {
      refuse("unexpected");
    } finally {
      b.disabled = false;
    }
  });
  return b;
}

function offer(ui, note, ...nodes) {
  ui.step.replaceChildren(...nodes);
  ui.status.textContent = note || "";
}

function screen(...head) {
  const ui = { facts: el("div"), step: el("div"), status: el("p", "", "status") };
  document.getElementById("main").replaceChildren(...head, ui.facts, ui.step, ui.status);
  return ui;
}

// The claim's progress in this tab, under the ticket's hash: the organization is revealed once
// per ticket, so a reload must find it here.
function sessionKey(ticket) {
  return `alphacompute-claim-${wasm_bindgen.bodySha256(utf8(ticket))}`;
}

function loadSession(ticket) {
  try {
    const text = sessionStorage.getItem(sessionKey(ticket));
    return text ? JSON.parse(text) : null;
  } catch (_) {
    return null;
  }
}

function saveSession(c) {
  try {
    sessionStorage.setItem(sessionKey(c.ticket), JSON.stringify(c.session));
  } catch (_) {
    // Without storage a reload cannot resume; the claim itself is unaffected.
  }
}

function claimPath(c, suffix) {
  return `/v1/claims/${c.ticket}${suffix}`;
}

function claimRefusal(read) {
  if (!read || typeof read !== "object") return MESSAGES.unavailable;
  if (read.kind !== "root" && read.kind !== "add") return MESSAGES.bad_link;
  if (read.state === "closed") return MESSAGES.claim_closed;
  if (read.state === "expired") return MESSAGES.claim_expired;
  if (read.state !== "open" && read.state !== "rooted") return MESSAGES.bad_link;
  const expires = Date.parse(read.expires_at);
  if (!Number.isFinite(expires) || expires <= Date.now()) return MESSAGES.claim_expired;
  if (read.keys_left === 0) return MESSAGES.claim_closed;
  if (typeof read.org_name !== "string" || !Array.isArray(read.credentials)) {
    return MESSAGES.unavailable;
  }
  return clockRefusal(read.server_time);
}

async function startClaim(view, viewText, ticket) {
  const reply = await api(view, "GET", `/v1/claims/${ticket}`);
  if (reply.status !== 200) return stop(failure(reply));
  const read = reply.body;
  const refusal = claimRefusal(read);
  if (refusal) return stop(refusal);

  const ui = screen(
    el("h1", read.org_name),
    el("p", read.kind === "root" ? "Claim this organization" : "Add a passkey to this organization"),
    el("p", `This link stays open until ${read.expires_at}.`),
  );
  const c = { view, read, ticket, ui, session: loadSession(ticket) };
  const s = c.session;
  if (read.state === "rooted") {
    if (!s || !s.root_key_id) return stop(MESSAGES.other_tab);
    return rooted(c);
  }
  if (s && s.org_id && s.first) return offerRoot(c);
  return offerFirst(c);
}

function offerFirst(c, note) {
  const exclude = c.read.credentials.map((x) => x.credential_id);
  const options = createOptions(c.view, c.read.org_name, exclude);
  offer(
    c.ui,
    note,
    button("Create passkey", async () => {
      const { credential, note } = await passkey("create", options);
      if (!credential) return offerFirst(c, note);
      const key = createdKey(credential);
      if (!key) return offerFirst(c, MESSAGES.unusable_key);
      return reveal(c, key);
    }),
  );
}

// Asked only once a passkey exists, so a closed prompt never spends the one reveal.
async function reveal(c, key) {
  const reply = await api(c.view, "POST", claimPath(c, "/org"));
  if (reply.status === 409) {
    const state = reply.body && reply.body.details && reply.body.details.state;
    if (state === "closed") return stop(MESSAGES.claim_closed);
    if (state === "expired") return stop(MESSAGES.claim_expired);
    return stop(MESSAGES.other_tab);
  }
  const b = reply.body;
  if (reply.status !== 200 || !b || !UUID.test(b.org_id) || !UUID.test(b.principal_id)) {
    const note = reply.status === 200 ? MESSAGES.unavailable : failure(reply);
    return offer(c.ui, note, button("Try again", () => reveal(c, key)));
  }
  c.session = { org_id: b.org_id, principal_id: b.principal_id, first: key };
  saveSession(c);
  return offerRoot(c);
}

// Relays one key registration and returns the response the KMS signed for it, or a note.
async function register(c, credentialId, registration, publicKey) {
  const body = `{"credential_id":${JSON.stringify(credentialId)},"registration":${registration}}`;
  const reply = await api(c.view, "POST", claimPath(c, "/keys"), body);
  if (reply.status !== 200) return { note: failure(reply) };
  const signed = receipt(c.view, reply, "key.register", registration, {
    org_id: c.session.org_id,
    public_key: publicKey,
  });
  if (!signed || typeof signed.id !== "string") return { note: MESSAGES.not_confirmed };
  return { signed };
}

function offerRoot(c, note) {
  const s = c.session;
  const payload = {
    org_id: s.org_id,
    principal_id: s.principal_id,
    public_key: s.first.spki,
    label: "passkey-1",
    issued_at: issuedAt(),
  };
  const signable = wasm_bindgen.signingDigest("org-root-key", JSON.stringify(payload));
  const options = getOptions(c.view, signable.digest, [s.first.id]);
  offer(
    c.ui,
    note,
    button("Confirm with passkey", async () => {
      const { credential, note } = await passkey("get", options);
      if (!credential) return offerRoot(c, note);
      const registration = wasm_bindgen.canonicalJson(
        JSON.stringify({ payload, signature: signatureObject(credential) }),
      );
      const result = await register(c, s.first.id, registration, s.first.spki);
      if (!result.signed) return offerRoot(c, result.note);
      s.root_key_id = result.signed.id;
      saveSession(c);
      return rooted(c);
    }),
  );
}

function describeKey(key) {
  return [
    el("p", fingerprint(unb64u(key.spki)), "fingerprint"),
    el("p", key.backed_up ? MESSAGES.synced : MESSAGES.device_bound),
  ];
}

function rooted(c) {
  c.ui.facts.replaceChildren(
    el("p", MESSAGES.yours, "confirmed"),
    el("p", "Root passkey fingerprint:"),
    ...describeKey(c.session.first),
  );
  offer(c.ui, "");
}

async function verifiedPlatform() {
  try {
    const reply = await fetch("./platform.json", { cache: "no-store" });
    if (!reply.ok) return null;
    const viewText = wasm_bindgen.verifyPlatform(await reply.text(), Date.now());
    return { view: JSON.parse(viewText), viewText };
  } catch (_) {
    return null;
  }
}

async function boot() {
  if (window.top !== window.self) return refuse("framed");
  if (!window.PublicKeyCredential) return refuse("no_passkeys");

  await wasm_bindgen({ module_or_path: fetch(WASM_URL, { integrity: WASM_SRI }) });

  const mode = location.pathname.split("/").pop();
  const ticket = location.hash.slice(1);
  if ((mode !== "claim" && mode !== "approve") || !TICKET.test(ticket)) return refuse("bad_link");

  const platform = await verifiedPlatform();
  if (!platform) return refuse("platform");
  const { view, viewText } = platform;

  if (view.version < storedVersion()) return refuse("older_platform");
  storeVersion(view.version);

  if (!view.signer || !view.signer.origins.includes(location.origin)) return refuse("not_signer");

  if (mode === "claim") return startClaim(view, viewText, ticket);
  return startApproval(view, viewText, ticket);
}

document.addEventListener("DOMContentLoaded", () => {
  boot().catch(() => refuse("unexpected"));
});
