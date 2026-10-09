"use strict";

const WASM_URL = "@WASM_URL@";
const WASM_SRI = "@WASM_SRI@";

const VERSION_KEY = "alphacompute-platform-version";
const TICKET = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NIL_APP = "00000000-0000-0000-0000-000000000000";
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
  no_credentials: "No passkey of this organization is known. Ask your AlphaCompute contact.",
  foreign_passkey: "That passkey does not belong to this organization. Use one that does.",
  check_failed: "This passkey did not sign as expected. Try again.",
  yours: "This organization is yours.",
  added: "The new passkey is registered.",
  synced: "Synced passkey (backed up by your provider)",
  device_bound: "Device-bound passkey: if you lose this device you lose this key",
  two_keys: "Done. Your organization has two passkeys.",
  added_done: "Done. The new passkey signs as expected.",
  approval_expired: "This approval link has expired.",
  decided: "This request was already approved, declined or cancelled.",
  mismatch:
    "What the service asked you to approve does not match what it would run. Nothing was signed.",
  unreadable:
    "This page cannot read what the service asked you to approve, so it cannot show it to you. Nothing was signed.",
  approved: "Approved. You can close this tab.",
  declined: "Declined. You can close this tab.",
  secret_missing: "Enter a value for every secret.",
  not_sealed: "The KMS node did not prove itself, so the secret was not sent. Try again.",
  catalog: "The catalog entry for this launch is not signed by AlphaCompute. Nothing was signed.",
  not_from_catalog: "This launch is replacing a launch not from this catalog.",
  revision_revoked: "The KMS refuses this launch because it was revoked before. Nothing was approved.",
  one_key: (expiresAt) =>
    `Your organization has one passkey. If you lose it you lose the organization. Your link stays open until ${expiresAt}.`,
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
  revision_revoked: MESSAGES.revision_revoked,
};

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function stop(text) {
  document.getElementById("main").replaceChildren(el("p", text, "refusal"));
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
  if (CODE.test(code)) return MESSAGES.kms_refused(code);
  if (reply.status === 404) return MESSAGES.bad_link;
  return MESSAGES.unavailable;
}

// As `failure`, but a request that is no longer pending names its state.
function approvalFailure(reply) {
  const details = reply.status === 409 && reply.body && reply.body.details;
  if (details && typeof details.state === "string") {
    return details.state === "expired" ? MESSAGES.approval_expired : MESSAGES.decided;
  }
  return failure(reply);
}

function clockRefusal(serverTime) {
  const server = typeof serverTime === "string" ? Date.parse(serverTime) : NaN;
  if (!Number.isFinite(server)) return MESSAGES.unavailable;
  const skew = Math.abs(server - Date.now());
  return skew > MAX_SKEW_MS ? MESSAGES.clock(Math.round(skew / 60000)) : null;
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
      stop(MESSAGES.unexpected);
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

function claimRefusal(read, resuming) {
  if (!read || typeof read !== "object") return MESSAGES.unavailable;
  if (read.kind !== "root" && read.kind !== "add") return MESSAGES.bad_link;
  if (read.state === "closed") return MESSAGES.claim_closed;
  if (read.state === "expired") return MESSAGES.claim_expired;
  if (read.state !== "open" && read.state !== "rooted") return MESSAGES.bad_link;
  const expires = Date.parse(read.expires_at);
  if (!Number.isFinite(expires) || expires <= Date.now()) return MESSAGES.claim_expired;
  if (read.keys_left === 0 && !resuming) return MESSAGES.claim_closed;
  if (typeof read.org_name !== "string" || !Array.isArray(read.credentials)) {
    return MESSAGES.unavailable;
  }
  return clockRefusal(read.server_time);
}

async function startClaim(view, ticket) {
  const reply = await api(view, "GET", `/v1/claims/${ticket}`);
  if (reply.status !== 200) return stop(failure(reply));
  const read = reply.body;
  const session = loadSession(ticket);
  // The last key registered spends the link, and a reload in this tab still owes the checks.
  const refusal = claimRefusal(read, Boolean(session && session.first && session.first.key_id));
  if (refusal) return stop(refusal);
  if (read.kind === "add" && read.credentials.length === 0) return stop(MESSAGES.no_credentials);

  const ui = screen(
    el("h1", read.org_name),
    el("p", read.kind === "root" ? "Claim this organization" : "Add a passkey to this organization"),
    el("p", `This link stays open until ${read.expires_at}.`),
  );
  const c = { view, read, ticket, ui, session, checked: new Set() };
  const s = c.session;
  const revealed = Boolean(s && s.org_id && s.first);
  const registered = revealed && Boolean(s.first.key_id);
  if (read.kind === "add") {
    if (registered) return added(c);
    return revealed ? offerAddApproval(c) : offerFirst(c);
  }
  if (registered) return rooted(c);
  if (read.state === "rooted") return stop(MESSAGES.other_tab);
  return revealed ? offerRoot(c) : offerFirst(c);
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
  return c.read.kind === "root" ? offerRoot(c) : offerAddApproval(c);
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

// One step that signs a key document and relays it: `allow` limits the passkeys asked, `keyIdFor`
// maps the one that answered to its KMS key id (undefined for the root's self-signature), and
// `next` runs once the receipt verified.
function offerRegistration(c, note, step) {
  const signable = wasm_bindgen.signingDigest(step.context, JSON.stringify(step.payload));
  const options = getOptions(c.view, signable.digest, step.allow);
  offer(
    c.ui,
    note,
    button(step.label, async () => {
      const { credential, note } = await passkey("get", options);
      if (!credential) return step.retry(note);
      const keyId = step.keyIdFor(credential);
      if (keyId === null) return step.retry(MESSAGES.foreign_passkey);
      const registration = wasm_bindgen.canonicalJson(
        JSON.stringify({ payload: step.payload, signature: signatureObject(credential, keyId) }),
      );
      const result = await register(c, step.key.id, registration, step.key.spki);
      if (!result.signed) return step.retry(result.note);
      step.key.key_id = result.signed.id;
      saveSession(c);
      return step.next();
    }),
  );
}

function offerRoot(c, note) {
  const s = c.session;
  offerRegistration(c, note, {
    label: "Confirm with passkey",
    context: "org-root-key",
    payload: {
      org_id: s.org_id,
      principal_id: s.principal_id,
      public_key: s.first.spki,
      label: "passkey-1",
      issued_at: issuedAt(),
    },
    key: s.first,
    allow: [s.first.id],
    keyIdFor: () => undefined,
    retry: (n) => offerRoot(c, n),
    next: () => rooted(c),
  });
}

function offerAddApproval(c, note) {
  const s = c.session;
  offerRegistration(c, note, {
    label: "Approve it with a passkey of this organization",
    context: "principal-key",
    payload: principalKey(s, s.first, "passkey-1"),
    key: s.first,
    allow: c.read.credentials.map((x) => x.credential_id),
    keyIdFor: (credential) => keyIdOf(credential.rawId, c.read.credentials),
    retry: (n) => offerAddApproval(c, n),
    next: () => added(c),
  });
}

function principalKey(s, key, label) {
  return { principal_id: s.principal_id, public_key: key.spki, label, issued_at: issuedAt() };
}

function describeKey(title, key) {
  return [
    el("p", title),
    el("p", fingerprint(unb64u(key.spki)), "fingerprint"),
    el("p", key.backed_up ? MESSAGES.synced : MESSAGES.device_bound),
  ];
}

function rooted(c) {
  const s = c.session;
  const facts = [el("p", MESSAGES.yours, "confirmed"), ...describeKey("Root passkey:", s.first)];
  if (s.second && s.second.key_id) facts.push(...describeKey("Second passkey:", s.second));
  c.ui.facts.replaceChildren(...facts);
  if (s.second && s.second.key_id) return offerChecks(c, [s.first, s.second], MESSAGES.two_keys);
  if (s.second) return offerSecondApproval(c);
  return offerSecond(c);
}

function added(c) {
  c.ui.facts.replaceChildren(
    el("p", MESSAGES.added, "confirmed"),
    ...describeKey("New passkey:", c.session.first),
  );
  // The passkey that signed the registration has just been checked by the KMS, and the page
  // knows no public key of it to check it against.
  return offerChecks(c, [c.session.first], MESSAGES.added_done);
}

function offerSecond(c, note) {
  const s = c.session;
  const options = createOptions(c.view, c.read.org_name, [s.first.id]);
  offer(
    c.ui,
    note,
    el("p", "Add a second passkey so that losing one device does not lose the organization."),
    button("Add a second passkey on another device or provider", async () => {
      const { credential, note } = await passkey("create", options);
      if (!credential) return offerSecond(c, note);
      const key = createdKey(credential);
      if (!key) return offerSecond(c, MESSAGES.unusable_key);
      s.second = key;
      saveSession(c);
      return offerSecondApproval(c);
    }),
    button("Skip for now", () =>
      offer(c.ui, "", el("p", MESSAGES.one_key(c.read.expires_at), "warning")),
    ),
  );
}

function offerSecondApproval(c, note) {
  const s = c.session;
  offerRegistration(c, note, {
    label: "Approve it with your first passkey",
    context: "principal-key",
    payload: principalKey(s, s.second, "passkey-2"),
    key: s.second,
    allow: [s.first.id],
    keyIdFor: () => s.first.key_id,
    retry: (n) => offerSecondApproval(c, n),
    next: () => rooted(c),
  });
}

// One assertion from each key over a fresh challenge, verified here against the key it claims.
function offerChecks(c, keys, done, note) {
  if (keys.every((k) => c.checked.has(k.id))) return offer(c.ui, "", el("p", done, "confirmed"));
  const steps = keys.map((key, i) => {
    const label = `Check passkey ${i + 1}`;
    if (c.checked.has(key.id)) return el("p", `${label}: signed as expected.`);
    const challenge = random(32);
    const options = getOptions(c.view, challenge, [key.id]);
    return button(label, async () => {
      const { credential, note } = await passkey("get", options);
      if (!credential) return offerChecks(c, keys, done, note);
      if (!(await signedAsExpected(c.view, key, challenge, credential))) {
        return offerChecks(c, keys, done, MESSAGES.check_failed);
      }
      c.checked.add(key.id);
      return offerChecks(c, keys, done);
    });
  });
  offer(c.ui, note, el("p", "Check that each passkey signs, one at a time."), ...steps);
}

// r ‖ s, each 32 bytes, of a DER ECDSA signature, or null.
function rawSignature(der) {
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2) return null;
  const raw = new Uint8Array(64);
  let at = 2;
  for (let i = 0; i < 2; i += 1) {
    const length = der[at + 1];
    if (der[at] !== 0x02 || !length || at + 2 + length > der.length) return null;
    let int = der.subarray(at + 2, at + 2 + length);
    while (int.length > 1 && int[0] === 0) int = int.subarray(1);
    if (int.length > 32) return null;
    raw.set(int, (i + 1) * 32 - int.length);
    at += 2 + length;
  }
  return at === der.length ? raw : null;
}

async function signedAsExpected(view, key, challenge, assertion) {
  try {
    const r = assertion.response;
    if (b64u(assertion.rawId) !== key.id) return false;
    const clientData = bytesOf(r.clientDataJSON);
    const client = JSON.parse(new TextDecoder().decode(clientData));
    if (
      client.type !== "webauthn.get" ||
      client.challenge !== b64u(challenge) ||
      client.origin !== location.origin ||
      client.crossOrigin === true ||
      client.topOrigin !== undefined
    ) {
      return false;
    }
    const authData = bytesOf(r.authenticatorData);
    const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(view.signer.rp_id)));
    if (authData.length < 37 || !equalBytes(authData.subarray(0, 32), rpHash)) return false;
    if ((authData[32] & (FLAG_UP | FLAG_UV)) !== (FLAG_UP | FLAG_UV)) return false;
    const signature = rawSignature(bytesOf(r.signature));
    if (!signature) return false;
    const publicKey = await crypto.subtle.importKey(
      "spki",
      unb64u(key.spki),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientData));
    const signed = new Uint8Array(authData.length + clientHash.length);
    signed.set(authData);
    signed.set(clientHash, authData.length);
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      signature,
      signed,
    );
  } catch (_) {
    return false;
  }
}

function approvalPath(a, suffix) {
  return `/v1/approval-requests/${a.ticket}${suffix}`;
}

function approvalRefusal(read) {
  if (!read || typeof read !== "object") return MESSAGES.unavailable;
  if (read.state === "expired") return MESSAGES.approval_expired;
  if (read.state !== "pending") return MESSAGES.decided;
  const expires = Date.parse(read.expires_at);
  if (!Number.isFinite(expires) || expires <= Date.now()) return MESSAGES.approval_expired;
  if (
    !UUID.test(read.org_id) ||
    !UUID.test(read.app_id) ||
    !/^sha256:[0-9a-f]{64}$/.test(read.compose_hash) ||
    typeof read.title !== "string" ||
    !Array.isArray(read.credentials)
  ) {
    return MESSAGES.unavailable;
  }
  return clockRefusal(read.server_time) || (read.credentials.length ? null : MESSAGES.no_credentials);
}

// What the request asks to run, or a refusal: the compose bytes it names, only if they hash to
// its compose_hash, parsed for display from those same bytes.
function uploadedLaunch(read) {
  if (typeof read.compose !== "string") return { refusal: MESSAGES.mismatch };
  return parsedLaunch(read, read.compose, {
    machine: `${read.machine || "not stated"} (chosen by the service, not part of what you sign)`,
  });
}

function parsedLaunch(read, compose, extra) {
  if (wasm_bindgen.bodySha256(utf8(compose)) !== read.compose_hash) {
    return { refusal: MESSAGES.mismatch };
  }
  try {
    return { compose, services: JSON.parse(wasm_bindgen.composeServices(compose)), ...extra };
  } catch (_) {
    return { refusal: MESSAGES.unreadable };
  }
}

function imageLines(image) {
  const at = (image || "").indexOf("@sha256:");
  return at < 0
    ? [el("p", `Image: ${image || "none"}`), el("p", "Digest: none (not pinned)", "digest")]
    : [el("p", `Image: ${image.slice(0, at)}`), el("p", `Digest: ${image.slice(at + 1)}`, "digest")];
}

function serviceBlock(name, service) {
  const block = el("div", undefined, "service");
  block.append(el("h3", name), ...imageLines(service.image));
  const lists = [
    ["Published ports", service.ports],
    ["Named volumes", service.volumes],
    ["Receives secrets", service.secrets],
  ];
  for (const [title, items] of lists) {
    if (items.length) block.append(el("p", `${title}: ${items.join(", ")}`));
  }
  return block;
}

function describeLaunch(a) {
  const { read, launch } = a;
  const nodes = [];
  if (launch.heading) nodes.push(el("p", launch.heading));
  for (const line of launch.notes || []) nodes.push(el("p", line, "warning"));
  nodes.push(el("h2", "What will run"));
  const runtime = launch.services["alpha-runtime"];
  for (const [name, service] of Object.entries(launch.services)) {
    if (name !== "alpha-runtime") nodes.push(serviceBlock(name, service));
  }
  if (runtime) {
    const block = el("div", undefined, "service");
    block.append(el("h3", "AlphaCompute runtime"), ...imageLines(runtime.image));
    nodes.push(block);
  }
  nodes.push(el("p", `Machine: ${launch.machine}`));
  const details = el("details");
  details.append(
    el("summary", "Technical details"),
    el("p", `App: ${read.app_id}`),
    el("p", `compose_hash: ${read.compose_hash}`, "digest"),
    el("pre", launch.compose),
  );
  nodes.push(details);
  return nodes;
}

async function startApproval(view, viewText, ticket) {
  const reply = await api(view, "GET", `/v1/approval-requests/${ticket}`);
  if (reply.status !== 200) return stop(failure(reply));
  const read = reply.body;
  const refusal = approvalRefusal(read);
  if (refusal) return stop(refusal);
  const before = currentServices(read.current);
  const launch =
    read.catalog_template_sha256 === null || read.catalog_template_sha256 === undefined
      ? uploadedLaunch(read)
      : await catalogLaunch(view, read, before);
  if (launch.refusal) return stop(launch.refusal);

  const ui = screen(
    el("h1", read.title),
    el("p", `Launch approval for ${typeof read.org_name === "string" ? read.org_name : read.org_id}`),
  );
  const a = { view, viewText, read, ticket, ui, launch, credential: null, values: null };
  a.fields = secretFields(launch.services, before);
  a.secretsBox = el("div");
  a.secretsBox.append(...a.fields.map((f) => f.node));
  ui.facts.replaceChildren(...describeLaunch(a), a.secretsBox);
  return offerApproval(a);
}

function declaredSecrets(services) {
  return [...new Set(Object.values(services).flatMap((s) => s.secrets))].sort();
}

// One password field per declared Secret. A Secret the current launch also declares is already
// held by the KMS, because approving that launch put it, so it defaults to keeping that value.
function secretFields(services, before) {
  const held = before ? declaredSecrets(before) : [];
  return declaredSecrets(services).map((name) => {
    const node = el("div", undefined, "secret");
    const input = el("input");
    input.type = "password";
    input.autocomplete = "off";
    input.id = `secret-${name}`;
    const label = el("label", `Secret ${name}`);
    label.htmlFor = input.id;
    node.append(label);
    let keep = null;
    if (held.includes(name)) {
      keep = el("select");
      keep.id = `keep-${name}`;
      const kept = el("option", "Keep the current value");
      kept.value = "keep";
      const replaced = el("option", "Replace");
      replaced.value = "replace";
      keep.append(kept, replaced);
      keep.value = "keep";
      node.append(keep);
    }
    node.append(input);
    return { name, input, keep, node };
  });
}

// Reads every field once and empties it, or returns a note and leaves the fields as they were.
function takeValues(a) {
  const sent = a.fields.filter((f) => !f.keep || f.keep.value !== "keep");
  if (sent.some((f) => !f.input.value)) return { note: MESSAGES.secret_missing };
  const values = sent.map((f) => ({ name: f.name, value: utf8(f.input.value), done: false }));
  for (const f of a.fields) f.input.value = "";
  a.secretsBox.replaceChildren(
    ...a.fields.map((f) =>
      el("p", f.keep && f.keep.value === "keep" ? `${f.name}: keeping the current value` : f.name),
    ),
  );
  return { values };
}

// Every touch after the first is limited to the passkey the first one used.
function allowed(a) {
  return a.credential ? [a.credential] : a.read.credentials.map((x) => x.credential_id);
}

// Signs with one passkey and keeps the passkey's id for later touches, or returns a note.
async function approvalSignature(a, options) {
  const { credential, note } = await passkey("get", options);
  if (!credential) return { note };
  const keyId = keyIdOf(credential.rawId, a.read.credentials);
  if (keyId === null) return { note: MESSAGES.foreign_passkey };
  a.credential = b64u(credential.rawId);
  return { signature: signatureObject(credential, keyId) };
}

// The next step: each Secret put, then the registration, which shroud-go refuses Secrets after.
function offerApproval(a, note) {
  const pending = a.values ? a.values.filter((v) => !v.done) : [];
  const total = a.values ? a.values.length + 1 : 1;
  const step = total - pending.length;
  const label = step === 1 ? "Approve with passkey" : `Sign ${step} of ${total}`;
  const run = a.values ? stepAction(a, pending[0]) : firstAction(a);
  offer(a.ui, note, button(label, run), declineButton(a));
}

// The first click reads the Secret values, so its inputs are built in the click, before any await.
function firstAction(a) {
  return () => {
    if (a.fields.length) {
      const taken = takeValues(a);
      if (taken.note) return offerApproval(a, taken.note);
      a.values = taken.values;
    } else {
      a.values = [];
    }
    return stepAction(a, a.values[0])();
  };
}

function stepAction(a, item) {
  const inputs = item ? putInputs(a, item) : revisionInputs(a);
  return () => (item ? put(a, item, inputs) : registerRevision(a, inputs));
}

function putInputs(a, item) {
  const payload = {
    name: `${a.read.app_id}.${item.name}`,
    app_ids: [a.read.app_id],
    content_sha256: wasm_bindgen.bodySha256(item.value),
    issued_at: issuedAt(),
  };
  const signable = wasm_bindgen.signingDigest("secret", JSON.stringify(payload));
  return { payload, document: signable.document, options: getOptions(a.view, signable.digest, allowed(a)) };
}

async function put(a, item, inputs) {
  const { signature, note } = await approvalSignature(a, inputs.options);
  if (!signature) return offerApproval(a, note);
  const sealer = new wasm_bindgen.KmsSecretSealer();
  const channel = await api(a.view, "POST", approvalPath(a, "/kms-channel"), sealer.hello());
  if (channel.status !== 200) return offerApproval(a, approvalFailure(channel));
  let sealed;
  try {
    sealed = sealer.seal(
      JSON.stringify(channel.body),
      a.viewText,
      inputs.document,
      a.read.org_id,
      item.value,
      Date.now(),
    );
  } catch (_) {
    return offerApproval(a, MESSAGES.not_sealed);
  }
  const body = wasm_bindgen.canonicalJson(
    JSON.stringify({ payload: inputs.payload, signature, sealed: JSON.parse(sealed) }),
  );
  const reply = await api(a.view, "PUT", approvalPath(a, `/secrets/${item.name}`), body);
  if (reply.status !== 200) return offerApproval(a, approvalFailure(reply));
  const signed = receipt(a.view, reply, "secret.put", body, {
    name: inputs.payload.name,
    org_id: a.read.org_id,
  });
  if (!signed) return offerApproval(a, MESSAGES.not_confirmed);
  // Kept until now so that a failed put can be sealed again; a confirmed one is never resent.
  item.value.fill(0);
  item.done = true;
  return offerApproval(a);
}

function revisionInputs(a) {
  const payload = { app_id: a.read.app_id, compose: a.launch.compose };
  const signable = wasm_bindgen.signingDigest("revision", JSON.stringify(payload));
  return { payload, options: getOptions(a.view, signable.digest, allowed(a)) };
}

async function registerRevision(a, inputs) {
  const { read } = a;
  const { signature, note } = await approvalSignature(a, inputs.options);
  if (!signature) return offerApproval(a, note);
  const body = wasm_bindgen.canonicalJson(JSON.stringify({ payload: inputs.payload, signature }));
  const reply = await api(a.view, "POST", approvalPath(a, "/revision"), body);
  if (reply.status !== 200) return offerApproval(a, approvalFailure(reply));
  const signed = receipt(a.view, reply, "revision.register", body, {
    app_id: read.app_id,
    compose_hash: read.compose_hash,
    org_id: read.org_id,
  });
  if (!signed) return offerApproval(a, MESSAGES.not_confirmed);
  return offer(a.ui, "", el("p", MESSAGES.approved, "confirmed"));
}

function declineButton(a) {
  return button("Decline", async () => {
    const reply = await api(a.view, "POST", approvalPath(a, "/decline"));
    if (reply.status === 200) return offer(a.ui, "", el("p", MESSAGES.declined, "confirmed"));
    a.ui.status.textContent = approvalFailure(reply);
  });
}

// The verified catalog entry named by a template hash, rendered for `appId`, or null.
async function catalogEntry(view, templateHex, appId) {
  try {
    const reply = await fetch(`./catalog/${templateHex}.json`, { cache: "no-store" });
    if (!reply.ok) return null;
    const text = await reply.text();
    return JSON.parse(
      wasm_bindgen.verifyCatalog(text, JSON.stringify(view.catalog_key), appId),
    );
  } catch (_) {
    return null;
  }
}

async function catalogLaunch(view, read, before) {
  const hex = /^(?:sha256:)?([0-9a-f]{64})$/.exec(read.catalog_template_sha256);
  const found = view.catalog_key && hex ? await catalogEntry(view, hex[1], read.app_id) : null;
  if (!found) return { refusal: MESSAGES.catalog };
  const { entry, compose } = found;
  const r = entry.resources || {};
  const launch = parsedLaunch(read, compose, {
    machine: `${r.cpu} vCPU, ${r.memory_mib} MiB`,
    heading: `${entry.title}, version ${entry.version}`,
  });
  if (launch.refusal || !read.current) return launch;
  const previous = await previousEntry(view, read);
  if (previous && previous.entry.catalog_id === entry.catalog_id) {
    launch.heading = `${entry.title}, version ${previous.entry.version} → ${entry.version}`;
    return launch;
  }
  launch.notes = [MESSAGES.not_from_catalog, ...imageChanges(before, launch.services)];
  return launch;
}

// The verified entry `current` was rendered from: the render replaced the template's one nil
// App id with this App's, so putting the nil id back gives the template's exact bytes.
async function previousEntry(view, read) {
  const compose = read.current.compose;
  const name = `"name":"${read.app_id}"`;
  if (typeof compose !== "string" || compose.split(name).length !== 2) return null;
  const template = compose.replace(name, `"name":"${NIL_APP}"`);
  const hex = wasm_bindgen.bodySha256(utf8(template)).slice("sha256:".length);
  const found = await catalogEntry(view, hex, read.app_id);
  return found && found.compose === compose ? found : null;
}

// What `current` claims runs today, only where its image differs from this launch's.
// The services of the compose the service says runs today, or null when it sent none or it does
// not parse.
function currentServices(current) {
  try {
    return current ? JSON.parse(wasm_bindgen.composeServices(current.compose)) : null;
  } catch (_) {
    return null;
  }
}

function imageChanges(before, services) {
  if (!before) return [];
  const names = [...new Set([...Object.keys(before), ...Object.keys(services)])].sort();
  const image = (s) => (s && s.image) || "nothing";
  return names
    .filter((n) => image(before[n]) !== image(services[n]))
    .map(
      (n) =>
        `${n}: ${image(before[n])} today, according to the service; ${image(services[n])} in this launch.`,
    );
}

function servedBySigner(view) {
  return Boolean(
    view.signer && Array.isArray(view.signer.origins) && view.signer.origins.includes(location.origin),
  );
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
  if (window.top !== window.self) return stop(MESSAGES.framed);
  if (!window.PublicKeyCredential) return stop(MESSAGES.no_passkeys);

  await wasm_bindgen({ module_or_path: fetch(WASM_URL, { integrity: WASM_SRI }) });

  const mode = location.pathname.split("/").pop();
  const ticket = location.hash.slice(1);
  if ((mode !== "claim" && mode !== "approve") || !TICKET.test(ticket)) return stop(MESSAGES.bad_link);

  const platform = await verifiedPlatform();
  if (!platform) return stop(MESSAGES.platform);
  const { view, viewText } = platform;

  if (view.version < storedVersion()) return stop(MESSAGES.older_platform);
  storeVersion(view.version);

  if (!servedBySigner(view)) return stop(MESSAGES.not_signer);

  if (mode === "claim") return startClaim(view, ticket);
  return startApproval(view, viewText, ticket);
}

document.addEventListener("DOMContentLoaded", () => {
  boot().catch(() => stop(MESSAGES.unexpected));
});
