"use strict";

const WASM_URL = "@WASM_URL@";
const WASM_SRI = "@WASM_SRI@";
const FONT_URL = "@FONT_URL@";
const FONT_SRI = "@FONT_SRI@";

const VERSION_KEY = "alphacompute-platform-version";
const TICKET = /^[A-Za-z0-9_-]{43}$/;
const TICKET_CODE = /^[0-9A-HJKMNP-TV-Z]{8}$/;
const MODES = ["claim", "approve", "revoke"];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH = /^sha256:[0-9a-f]{64}$/;
const PINNED = /@sha256:[0-9a-f]{64}$/;
const CODE = /^[A-Za-z_]{1,64}$/;
// alpha-control limits its ticket routes to 5 requests per second per IP.
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
const FLAG_BS = 0x10;

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
  closed: "This link was already used, declined or closed.",
  expired: "This link has expired.",
  bad_code: "Enter the 8 characters of your code.",
  prompt_closed: "The passkey prompt was closed. Try again.",
  passkey_failed: "The passkey prompt failed. Try again, or open this link in another browser.",
  already_registered:
    "This device already holds a passkey for this organization; use another device or provider.",
  unusable_key:
    "This passkey cannot be used: it did not give a P-256 public key. Use another device or provider.",
  network_dark: "None: the App is network-dark apart from the platform's own connections.",
  not_confirmed: "Not confirmed by the KMS.",
  conflict: "The service refused this step because it was already done. Reload to see where it stands.",
  signature_invalid: "The KMS did not accept the passkey's signature. Nothing was changed.",
  already_exists: "The KMS already holds this. Reload to see where it stands.",
  kms_refused: (code) => `The KMS refused this request (${code}).`,
  no_credentials: "No passkey of this organization is known. Ask your AlphaCompute contact.",
  foreign_passkey: "That passkey does not belong to this organization. Use one that does.",
  check_failed: "This passkey did not sign as expected. Try again.",
  sign_in: (email) => `Sign in as ${email} to claim this organization.`,
  sign_in_failed: "Sign-in did not complete. Try again.",
  not_owner: "That sign-in is not the owner of this organization. Sign in as the owner.",
  no_storage: "This browser does not let the page keep the sign-in in this tab. Allow site data and try again.",
  root_statement: (email, org, id) =>
    `You, ${email}, are making this passkey the root key of ${org} (${id}).`,
  add_statement: (principal, org) =>
    `This passkey becomes a key of principal ${principal} in ${org}, approved by one of its passkeys.`,
  root_taken: "Your organization was claimed by another key. Do not continue. Contact AlphaCompute.",
  yours: "This organization is yours.",
  unrooted:
    "This organization has no passkey yet. Finish onboarding from the email we sent, then open this link again.",
  machine:
    "The service sets the machine size (CPU and memory). The size never changes the code or keys you approve, so you do not sign it.",
  added: "The new passkey is registered.",
  synced: "Synced passkey (backed up by your provider)",
  device_bound: "Device-bound passkey: if you lose this device you lose this key",
  two_keys: "Done. Your organization has two passkeys.",
  added_done: "Done. The new passkey signs as expected.",
  mismatch:
    "What the service asked you to approve does not match what it would run. Nothing was signed.",
  unreadable:
    "This page cannot read what the service asked you to approve, so it cannot show it to you. Nothing was signed.",
  not_registrable:
    "The KMS would refuse to register what the service asked you to approve. Nothing was signed.",
  approved: "Approved. You can close this tab.",
  declined: "Declined. You can close this tab.",
  secret_missing: "Enter a value for every secret.",
  not_sealed: "The KMS node did not prove itself, so the secret was not sent. Try again.",
  catalog: "The catalog entry for this launch is not signed by AlphaCompute. Nothing was signed.",
  revision_revoked: "The KMS refuses this launch because it was revoked before. Nothing was approved.",
  requester: "From the requester, not verified:",
  no_change: "No change to images, published ports, volumes, environment, Secrets or network openings.",
  keep_predecessor: (hash) => `Keep the previous Revision ${hash} runnable`,
  revoke_effect:
    "Revoking stops the KMS from giving these launches keys, Secrets or certificates: no copy can start, and a running copy gets none again. It cannot be undone; the same launch can never be approved again.",
  revoked: "Revoked. You can close this tab.",
  one_key: (expiresAt) =>
    `Your organization has one passkey. If you lose it you lose the organization. Your link stays open until ${expiresAt}.`,
};

const CODES = {
  ticket_not_found: MESSAGES.bad_link,
  unavailable: MESSAGES.unavailable,
  rate_limited: MESSAGES.rate_limited,
  upstream_invalid: MESSAGES.not_confirmed,
  conflict: MESSAGES.conflict,
  ticket_expired: MESSAGES.expired,
  ticket_closed: MESSAGES.closed,
  session_refused: MESSAGES.not_owner,
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

// A row of `label: value` whose two spans the stylesheet lays out apart.
function fact(label, value, valueClass) {
  const row = el("p", undefined, "fact");
  row.append(el("span", `${label}: `), el("span", value, valueClass));
  return row;
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

// A put commits to 32 random bytes and the value, so the stored document is no test for a guess.
function salted(value) {
  const out = new Uint8Array(32 + value.length);
  out.set(random(32));
  out.set(value, 32);
  value.fill(0);
  return out;
}

function equalBytes(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function fingerprint(spki) {
  const hex = wasm_bindgen.bodySha256(spki).slice("sha256:".length);
  return `sha256:${hex.match(/.{4}/g).join(" ")}`;
}

function issuedAt() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
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

// One call to alpha-control. A 429 is answered before anything is relayed, so the identical request
// is sent once more after Retry-After. `headers` adds to the content type.
async function api(view, method, path, bodyText, headers = {}) {
  for (let attempt = 0; ; attempt += 1) {
    const wait = lastCall + PACE_MS - Date.now();
    if (wait > 0) await sleep(wait);
    lastCall = Date.now();
    let reply;
    try {
      reply = await fetch(view.signer.api_origin + path, {
        method,
        headers: bodyText === undefined ? headers : { "Content-Type": "application/json", ...headers },
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

// The fixed sentence for a failed call; the server's own text never reaches the page.
function failure(reply) {
  if (reply.status === 0) return MESSAGES.unavailable;
  const raw = reply.body?.error?.code;
  const code = typeof raw === "string" ? raw : "";
  if (Object.hasOwn(CODES, code)) return CODES[code];
  if (CODE.test(code)) return MESSAGES.kms_refused(code);
  if (reply.status === 404) return MESSAGES.bad_link;
  return MESSAGES.unavailable;
}

function clockRefusal(serverTime) {
  const server = typeof serverTime === "string" ? Date.parse(serverTime) : NaN;
  if (!Number.isFinite(server)) return MESSAGES.unavailable;
  const skew = Math.abs(server - Date.now());
  return skew > MAX_SKEW_MS ? MESSAGES.clock(Math.round(skew / 60000)) : null;
}

function ticketRefusal(read, kind) {
  if (!read || typeof read !== "object") return MESSAGES.unavailable;
  if (read.kind !== kind) return MESSAGES.bad_link;
  if (read.state === "expired") return MESSAGES.expired;
  if (read.state !== "open") return MESSAGES.closed;
  const expires = Date.parse(read.expires_at);
  if (!Number.isFinite(expires) || expires <= Date.now()) return MESSAGES.expired;
  if (
    !UUID.test(read.org_id) ||
    typeof read.org_name !== "string" ||
    !Array.isArray(read.credentials) ||
    !read.credentials.every((c) => typeof c?.credential_id === "string" && typeof c.key_id === "string")
  ) {
    return MESSAGES.unavailable;
  }
  return clockRefusal(read.server_time);
}

// The ticket, with the sentence that refuses it when the read failed, it is of another kind or
// it is not open; `check` adds the kind's own refusals.
async function readTicket(view, ticket, kind, check) {
  const reply = await api(view, "GET", `/v1/tickets/${ticket}`);
  if (reply.status !== 200) return { refusal: failure(reply) };
  const read = reply.body;
  return { read, refusal: ticketRefusal(read, kind) || check(read) };
}

function ticketPath(ticket, op) {
  return `/v1/tickets/${ticket}/kms/${op}`;
}

// The response the KMS signed for exactly `sentText`, or null.
function receipt(view, reply, route, sentText, response) {
  try {
    const expected = { route, request_sha256: wasm_bindgen.bodySha256(utf8(sentText)), response };
    const signed = wasm_bindgen.verifyKmsReceipt(
      JSON.stringify(reply.body.receipt),
      view.kms_ca_pem,
      JSON.stringify(view.kms_revisions.map((r) => r.compose_hash)),
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
    backed_up: (authData[32] & FLAG_BS) !== 0,
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

function button(label, action, className) {
  const b = el("button", label, className);
  b.type = "button";
  b.addEventListener("click", async () => {
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
  const ui = {
    facts: el("div", undefined, "facts"),
    step: el("div", undefined, "step"),
    status: el("p", "", "status"),
  };
  ui.status.role = "status";
  document.getElementById("main").replaceChildren(...head, ui.facts, ui.step, ui.status);
  return ui;
}

// The passkeys this tab made for a claim, under the ticket's hash, so that a reload resumes.
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

// Whether the tab kept it: without storage a reload cannot resume, and a sign-in cannot be used.
function saveSession(c) {
  try {
    sessionStorage.setItem(sessionKey(c.ticket), JSON.stringify(c.session));
    return true;
  } catch (_) {
    return false;
  }
}

// A root needs the owner's session, which only the tab that redeemed the sign-in holds; a key
// added to a rooted organization needs a signature by one of its keys.
function claimRefusal(read) {
  if (typeof read.rooted !== "boolean") return MESSAGES.unavailable;
  if (read.rooted) {
    if (!UUID.test(read.principal_id)) return MESSAGES.unavailable;
    return read.credentials.length ? null : MESSAGES.no_credentials;
  }
  const o = read.oidc;
  if (typeof read.owner_email !== "string" || typeof o?.client_id !== "string") {
    return MESSAGES.unavailable;
  }
  return /^https:\/\//.test(o.authorization_endpoint) ? null : MESSAGES.unavailable;
}

async function startClaim(view, ticket, note) {
  const { read, refusal } = await readTicket(view, ticket, "claim", claimRefusal);
  if (refusal) return stop(refusal);
  const ui = screen(
    el("p", read.rooted ? "Add a passkey to this organization" : "Claim this organization", "eyebrow"),
    el("h1", read.org_name),
    el("p", `This link stays open until ${read.expires_at}.`),
  );
  const c = { view, read, ticket, ui, session: loadSession(ticket) || {}, checked: new Set() };
  const s = c.session;
  if (s.first?.key_id) return s.root ? rooted(c) : added(c);
  // A root this tab signed may have reached the KMS without the tab learning its key id; the KMS
  // answers the same key with the stored root, so it is offered again, never as an added key.
  if (s.root && s.first && s.owner) return offerRoot(c, note);
  if (read.rooted) {
    ui.facts.replaceChildren(el("p", MESSAGES.add_statement(read.principal_id, read.org_name), "warning"));
    return s.first ? offerAddApproval(c, note) : offerFirst(c, note);
  }
  ui.facts.replaceChildren(
    el("p", MESSAGES.root_statement(read.owner_email, read.org_name, read.org_id), "warning"),
  );
  if (!s.owner) return offerSignIn(c, note);
  return s.first ? offerRoot(c, note) : offerFirst(c, note);
}

// The owner's principal once this tab signed in, else the one the ticket names for a new key.
function principalOf(c) {
  return c.session.owner?.principal_id ?? c.read.principal_id;
}

function redirectUri() {
  return `${location.origin}${location.pathname}`;
}

function oidcKey(state) {
  return `alphacompute-oidc-${state}`;
}

function offerSignIn(c, note) {
  offer(c.ui, note, button(MESSAGES.sign_in(c.read.owner_email), () => signIn(c)));
}

// Authorization code with PKCE: the identity provider sends the person back to this path with
// the code, and alpha-control redeems it and returns a session secret that the root relay needs,
// so a second holder of the ticket cannot root the organization after the owner signed in.
async function signIn(c) {
  const state = b64u(random(32));
  const verifier = b64u(random(32));
  try {
    sessionStorage.setItem(oidcKey(state), JSON.stringify({ ticket: c.ticket, verifier }));
  } catch (_) {
    return offerSignIn(c, MESSAGES.no_storage);
  }
  const challenge = b64u(await crypto.subtle.digest("SHA-256", utf8(verifier)));
  const url = new URL(c.read.oidc.authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: c.read.oidc.client_id,
    redirect_uri: redirectUri(),
    scope: "openid email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    login_hint: c.read.owner_email,
  }).toString();
  location.assign(url.href);
}

async function finishSignIn(view) {
  const query = new URLSearchParams(location.search);
  const key = oidcKey(query.get("state") || "");
  let saved = null;
  try {
    saved = JSON.parse(sessionStorage.getItem(key));
    sessionStorage.removeItem(key);
  } catch (_) {
    // A tab that kept nothing cannot finish this sign-in.
  }
  if (!saved || !TICKET.test(saved.ticket)) return stop(MESSAGES.sign_in_failed);
  history.replaceState(null, "", `${location.pathname}#${saved.ticket}`);
  const code = query.get("code");
  if (!code) return startClaim(view, saved.ticket, MESSAGES.sign_in_failed);
  const body = JSON.stringify({ code, code_verifier: saved.verifier, redirect_uri: redirectUri() });
  const reply = await api(view, "POST", `/v1/tickets/${saved.ticket}/session`, body);
  if (reply.status !== 200) return startClaim(view, saved.ticket, failure(reply));
  const owner = reply.body;
  if (!TICKET.test(owner?.session) || !UUID.test(owner.principal_id)) {
    return startClaim(view, saved.ticket, MESSAGES.unavailable);
  }
  const session = { session: owner.session, principal_id: owner.principal_id };
  const c = { ticket: saved.ticket, session: { ...loadSession(saved.ticket), owner: session } };
  return saveSession(c) ? startClaim(view, saved.ticket) : stop(MESSAGES.no_storage);
}

// A button that creates one passkey and hands its key to `next`, or offers `retry` a note.
function createButton(label, options, retry, next, className) {
  return button(
    label,
    async () => {
      const { credential, note } = await passkey("create", options);
      if (!credential) return retry(note);
      const key = createdKey(credential);
      if (!key) return retry(MESSAGES.unusable_key);
      return next(key);
    },
    className,
  );
}

function offerFirst(c, note) {
  const exclude = c.read.credentials.map((x) => x.credential_id);
  const options = createOptions(c.view, c.read.org_name, exclude);
  const next = (key) => {
    c.session = { ...c.session, first: key, root: !c.read.rooted };
    saveSession(c);
    return c.read.rooted ? offerAddApproval(c) : offerRoot(c);
  };
  offer(c.ui, note, createButton("Create passkey", options, (n) => offerFirst(c, n), next));
}

// One step that signs a key document and relays it as `op` (`root` or `key`): `allow` limits the
// passkeys asked, `keyIdFor` maps the one that answered to its KMS key id (undefined for the
// root's self-signature), and `next` runs once the receipt verified.
function offerRegistration(c, note, step) {
  const signable = wasm_bindgen.signingDigest(step.context, JSON.stringify(step.payload));
  const options = getOptions(c.view, signable.digest, step.allow);
  const sign = button(step.label, async () => {
    const { credential, note } = await passkey("get", options);
    if (!credential) return step.retry(note);
    const keyId = step.keyIdFor(credential);
    if (keyId === null) return step.retry(MESSAGES.foreign_passkey);
    const registration = wasm_bindgen.canonicalJson(
      JSON.stringify({ payload: step.payload, signature: signatureObject(credential, keyId) }),
    );
    const body = `{"credential_id":${JSON.stringify(step.key.id)},"registration":${registration}}`;
    const owner = step.op === "root" ? { "Alpha-Claim-Session": c.session.owner.session } : {};
    const reply = await api(c.view, "POST", ticketPath(c.ticket, step.op), body, owner);
    const code = reply.body?.error?.code;
    if (step.op === "root" && code === "already_exists") return stop(MESSAGES.root_taken);
    if (step.op === "root" && code === "session_refused") {
      delete c.session.owner;
      saveSession(c);
      return offerSignIn(c, MESSAGES.not_owner);
    }
    if (reply.status !== 200) return step.retry(failure(reply));
    const signed = receipt(c.view, reply, "key.register", registration, {
      org_id: c.read.org_id,
      public_key: step.key.spki,
    });
    if (typeof signed?.id !== "string") return step.retry(MESSAGES.not_confirmed);
    step.key.key_id = signed.id;
    saveSession(c);
    return step.next();
  });
  offer(c.ui, note, sign);
}

// The self-signed document that makes `key` the first key of an organization.
function rootStep(orgId, principalId, key) {
  return {
    label: "Confirm with passkey",
    context: "org-root-key",
    op: "root",
    payload: {
      org_id: orgId,
      principal_id: principalId,
      public_key: key.spki,
      label: "passkey-1",
      issued_at: issuedAt(),
    },
    key,
    allow: [key.id],
    keyIdFor: () => undefined,
  };
}

function offerRoot(c, note) {
  offerRegistration(c, note, {
    ...rootStep(c.read.org_id, principalOf(c), c.session.first),
    retry: (n) => offerRoot(c, n),
    next: () => rooted(c),
  });
}

function offerAddApproval(c, note) {
  const s = c.session;
  offerRegistration(c, note, {
    label: "Approve it with a passkey of this organization",
    context: "principal-key",
    op: "key",
    payload: principalKey(c, s.first, "passkey-1"),
    key: s.first,
    allow: c.read.credentials.map((x) => x.credential_id),
    keyIdFor: (credential) => keyIdOf(credential.rawId, c.read.credentials),
    retry: (n) => offerAddApproval(c, n),
    next: () => added(c),
  });
}

function principalKey(c, key, label) {
  return { principal_id: principalOf(c), public_key: key.spki, label, issued_at: issuedAt() };
}

function describeKey(title, key) {
  return [
    el("p", title, "eyebrow"),
    el("p", fingerprint(unb64u(key.spki)), "fingerprint"),
    el("p", key.backed_up ? MESSAGES.synced : MESSAGES.device_bound, "muted"),
  ];
}

function rooted(c) {
  const s = c.session;
  const facts = [el("p", MESSAGES.yours, "confirmed"), ...describeKey("Root passkey:", s.first)];
  if (s.second?.key_id) facts.push(...describeKey("Second passkey:", s.second));
  c.ui.facts.replaceChildren(...facts);
  if (s.second?.key_id) return offerChecks(c, [s.first, s.second], MESSAGES.two_keys);
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
    createButton(
      "Add a second passkey on another device or provider",
      options,
      (n) => offerSecond(c, n),
      (key) => {
        s.second = key;
        saveSession(c);
        return offerSecondApproval(c);
      },
    ),
    button(
      "Skip for now",
      () => offer(c.ui, "", el("p", MESSAGES.one_key(c.read.expires_at), "warning")),
      "secondary",
    ),
  );
}

function offerSecondApproval(c, note) {
  const s = c.session;
  offerRegistration(c, note, {
    label: "Approve it with your first passkey",
    context: "principal-key",
    op: "key",
    payload: principalKey(c, s.second, "passkey-2"),
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
    if (c.checked.has(key.id)) return el("p", `${label}: signed as expected.`, "verified");
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

// An approval carries only bodies signed by a key already in the organization's roster, so a
// ticket of an organization without one is refused rather than offered a new key.
function approvalRefusal(read) {
  if (
    !UUID.test(read.app_id) ||
    !HASH.test(read.compose_hash) ||
    typeof read.title !== "string"
  ) {
    return MESSAGES.unavailable;
  }
  return read.credentials.length ? null : MESSAGES.unrooted;
}

// What the request asks to run, or a refusal: the Revision bytes it names, only if they hash to
// its compose_hash, parsed for display from those same bytes.
function uploadedLaunch(read) {
  if (typeof read.revision !== "string") return { refusal: MESSAGES.mismatch };
  return parsedLaunch(read, read.revision, {
    machine: read.machine || "not stated",
    machineNote: MESSAGES.machine,
  });
}

function parsedLaunch(read, compose, extra) {
  if (wasm_bindgen.bodySha256(utf8(compose)) !== read.compose_hash) {
    return { refusal: MESSAGES.mismatch };
  }
  try {
    return {
      compose,
      services: JSON.parse(wasm_bindgen.composeServices(compose)),
      openings: JSON.parse(wasm_bindgen.revisionOpenings(compose)),
      ...extra,
    };
  } catch (_) {
    return { refusal: MESSAGES.unreadable };
  }
}

// The App's registered Revision that this approval replaces, parsed from bytes that hash to the
// compose_hash the page revokes, or null when there is none.
function previousLaunch(read) {
  const p = read.predecessor;
  if (p == null) return null;
  if (!HASH.test(p.compose_hash) || typeof p.revision !== "string") {
    return { refusal: MESSAGES.unavailable };
  }
  return parsedLaunch(p, p.revision, { compose_hash: p.compose_hash });
}

// The full image reference, never shortened: a digest is compared with the customer's own build.
function imageLine(name, image) {
  const row = fact("Image", image || "none", "digest");
  if (!PINNED.test(image || "")) row.append(el("span", "not pinned", "warning"));
  // A refused clipboard must not replace the approval with an error, so the write's failure is dropped.
  const copy = button("Copy", () => navigator.clipboard.writeText(image).catch(() => {}), "copy");
  copy.ariaLabel = `Copy the image of ${name}`;
  row.append(copy);
  return row;
}

function serviceBlock(name, service, ports = service.ports) {
  const block = el("div", undefined, "service");
  block.append(el("h3", name), imageLine(name, service.image));
  const lists = [
    ["Published ports", ports],
    ["Named volumes", service.volumes],
    ["Receives secrets", service.secrets],
  ];
  for (const [title, items] of lists) {
    if (items.length) block.append(fact(title, items.join(", ")));
  }
  for (const [k, v] of Object.entries(service.environment)) {
    block.append(el("p", `${k}=${v}`, "env"));
  }
  return block;
}

// ponytail: a service is AlphaCompute's only when its image is in the AlphaCompute registry, where
// only AlphaCompute publishes, and pinned by digest, which fixes the exact code; the compose's own
// names and paths are requester-controlled and prove nothing. Ceiling: every pinned image in that
// registry counts, with no per-image allowlist; the upgrade is the release-signed list of runtime
// images in the platform document.
const PLATFORM_IMAGE = /^ghcr\.io\/alphacompute\/[^@]+@sha256:[0-9a-f]{64}$/;
function isPlatform(service) {
  return PLATFORM_IMAGE.test(service.image || "");
}

function runtimeBlock(runtime) {
  const upstream = runtime.environment.ALPHACOMPUTE_TLS_UPSTREAM;
  // The runtime terminates TLS only on its container port 8443 over TCP; a port without a host
  // side is published on a random host port, so neither names an endpoint.
  const hostOfTls = (p) => upstream && /^(.+):8443(\/tcp)?$/.exec(p)?.[1];
  const hosts = runtime.ports.map(hostOfTls).filter(Boolean);
  const block = serviceBlock(
    "AlphaCompute runtime",
    runtime,
    runtime.ports.filter((p) => !hostOfTls(p)),
  );
  if (hosts.length) {
    block.append(fact("Endpoint", `HTTPS on ${hosts.join(", ")}, forwarded to ${upstream}`));
  }
  return block;
}

function openingLine(direction, o) {
  return `${direction} ${o.protocol} ${o.port} ${o.cidr} — ${o.justification}`;
}

function openingLines(openings) {
  if (!openings) return [];
  return [
    ...openings.ingress.map((o) => openingLine("ingress", o)),
    ...openings.egress.map((o) => openingLine("egress", o)),
  ];
}

// A Kata Revision's declared openings, one line each; a compose has none to show (null).
function networkBlock(openings) {
  const block = el("div", undefined, "service");
  block.append(el("h3", "Network"));
  const lines = openingLines(openings).map((line) => el("p", line));
  block.append(...(lines.length ? lines : [el("p", MESSAGES.network_dark)]));
  return block;
}

// What this Revision adds or changes against the one it replaces, each `[text, added]`. An
// addition widens what runs or what it may reach, so the page marks it.
function changes(before, after) {
  const lines = [];
  const names = [...new Set([...Object.keys(before.services), ...Object.keys(after.services)])];
  for (const n of names.sort()) {
    const b = before.services[n];
    const s = after.services[n];
    if (!s) {
      lines.push([`${n}: removed`, false]);
      continue;
    }
    if (!b) {
      lines.push([`${n}: added, image ${s.image}`, true]);
      continue;
    }
    if (b.image !== s.image) lines.push([`${n}: image ${b.image} → ${s.image}`, true]);
    for (const p of s.ports.filter((x) => !b.ports.includes(x))) lines.push([`${n}: publishes ${p}`, true]);
    for (const p of b.ports.filter((x) => !s.ports.includes(x))) lines.push([`${n}: stops publishing ${p}`, false]);
    const keys = [...new Set([...Object.keys(b.environment), ...Object.keys(s.environment)])];
    for (const k of keys.sort()) {
      if (b.environment[k] === s.environment[k]) continue;
      if (!(k in s.environment)) lines.push([`${n}: ${k} removed`, false]);
      else lines.push([`${n}: ${k}=${s.environment[k]}`, true]);
    }
    for (const v of s.volumes.filter((x) => !b.volumes.includes(x))) lines.push([`${n}: mounts volume ${v}`, true]);
    for (const secret of s.secrets.filter((x) => !b.secrets.includes(x))) {
      lines.push([`${n}: receives Secret ${secret}`, true]);
    }
  }
  const was = openingLines(before.openings);
  const now = openingLines(after.openings);
  for (const line of now.filter((x) => !was.includes(x))) lines.push([`opens ${line}`, true]);
  for (const line of was.filter((x) => !now.includes(x))) lines.push([`closes ${line}`, false]);
  return lines;
}

function diffBlock(before, launch) {
  const block = el("div", undefined, "service");
  block.append(el("h2", "Changes from the previous Revision"), fact("Previous", before.compose_hash, "digest"));
  const lines = changes(before, launch).map(([text, added]) => el("p", text, added ? "added" : undefined));
  block.append(...(lines.length ? lines : [el("p", MESSAGES.no_change)]));
  return block;
}

function describeLaunch(a) {
  const { read, launch, before } = a;
  const nodes = [];
  if (before) nodes.push(diffBlock(before, launch));
  const runtime = launch.services["alpha-runtime"];
  const publicName = runtime && isPlatform(runtime) ? runtime.environment.ALPHACOMPUTE_PUBLIC_NAME : undefined;
  const summary = el("div", undefined, "summary");
  if (publicName) summary.append(fact("Public URL", `https://${publicName}`));
  summary.append(fact("Organization", read.org_name), fact("Machine", launch.machine));
  nodes.push(summary);
  if (launch.machineNote) nodes.push(el("p", launch.machineNote, "muted"));
  nodes.push(fact("App", read.app_id), fact("Revision", read.compose_hash, "digest"));
  nodes.push(el("p", MESSAGES.requester, "muted"), el("p", read.title));
  nodes.push(el("h2", "What will run"));
  for (const [n, s] of Object.entries(launch.services)) {
    nodes.push(n === "alpha-runtime" && isPlatform(s) ? runtimeBlock(s) : serviceBlock(n, s));
  }
  if (launch.openings) nodes.push(networkBlock(launch.openings));
  const details = el("details");
  details.append(el("summary", "The exact bytes you sign"), el("pre", launch.compose));
  nodes.push(details);
  return nodes;
}

async function startApproval(view, viewText, ticket) {
  const { read, refusal } = await readTicket(view, ticket, "approve", approvalRefusal);
  if (refusal) return stop(refusal);
  const before = previousLaunch(read);
  if (before?.refusal) return stop(before.refusal);
  const launch =
    read.catalog_template_sha256 == null ? uploadedLaunch(read) : await catalogLaunch(view, read);
  if (launch.refusal) return stop(launch.refusal);
  // Built before any Secret is stored: a launch the KMS would not register stops here.
  try {
    const policy = JSON.stringify(view.kata_policy ?? null);
    launch.payload = JSON.parse(
      wasm_bindgen.revisionPayload(read.app_id, launch.compose, policy, view.kms_ca_pem),
    );
  } catch (_) {
    return stop(MESSAGES.not_registrable);
  }

  const ui = screen();
  const a = { view, viewText, read, ticket, ui, launch, before, credential: null, values: null };
  a.fields = secretFields(launch.services, before?.services, putSecrets(read), read.secrets);
  a.secretsBox = el("div", undefined, "secrets");
  a.secretsBox.append(...a.fields.map((f) => f.node));
  ui.facts.replaceChildren(...describeLaunch(a));
  // The decision sits beside what the App is on a wide page, and pins its buttons to the bottom
  // of a narrow one once every Secret is filled.
  const decision = el("div", undefined, "decision");
  const sync = () => {
    const filled = a.fields.every((f) => f.keep?.value === "keep" || f.input.value);
    decision.className = filled ? "decision ready" : "decision";
  };
  for (const f of a.fields) {
    f.input.addEventListener("input", sync);
    f.generate.addEventListener("click", sync);
    f.keep?.addEventListener("change", sync);
  }
  sync();
  decision.append(a.secretsBox);
  if (before) decision.append(...keepBox(a));
  decision.append(ui.step, ui.status);
  const layout = el("div", undefined, "approval");
  layout.append(ui.facts, decision);
  document
    .getElementById("main")
    .replaceChildren(el("p", `Launch approval for ${read.org_name}`, "eyebrow"), el("h1", launch.heading || read.app_id), layout);
  offerApproval(a);
}

// Unticked by default, and the default lives here rather than in the ticket: approving a new
// Revision revokes the one it replaces unless the person keeps it.
function keepBox(a) {
  a.keep = el("input");
  a.keep.type = "checkbox";
  a.keep.id = "keep-predecessor";
  const label = el("label", MESSAGES.keep_predecessor(a.before.compose_hash));
  label.htmlFor = a.keep.id;
  const row = el("p", undefined, "keep");
  row.append(a.keep, label);
  return [row, el("p", MESSAGES.revoke_effect, "warning")];
}

function declaredSecrets(services) {
  return [...new Set(Object.values(services).flatMap((s) => s.secrets))].sort();
}

// The Secrets the service reports as put for this request, by a key of the organization.
function putSecrets(read) {
  if (!Array.isArray(read.secrets)) return [];
  return read.secrets.filter((s) => s && s.set === true).map((s) => s.name);
}

// One password field per declared Secret. A Secret the previous Revision also declares is already
// held by the KMS, because approving that Revision put it, and so is one the service reports as
// put; either defaults to keeping that value.
// The description is unsigned display text: shown as text, never used to choose which Secrets are asked.
function secretFields(services, before, put, reported) {
  const held = [...(before ? declaredSecrets(before) : []), ...put];
  return declaredSecrets(services).map((name, index) => {
    const node = el("div", undefined, "secret");
    const input = el("input");
    input.type = "password";
    input.autocomplete = "off";
    input.id = `secret-${name}`;
    const label = el("label", `Secret ${name}`);
    label.htmlFor = input.id;
    node.append(label);
    const description = Array.isArray(reported) ? reported.find((s) => s && s.name === name)?.description : undefined;
    let describedBy = null;
    let caption = null;
    let describedIds = "";
    if (typeof description === "string" && description) {
      describedBy = el("p", description, "muted");
      describedBy.id = `description-${index}`; // the other ids start with secret-, keep- or generate- plus a Secret name; this prefix cannot match them
      caption = el("p", MESSAGES.requester, "muted");
      caption.id = `caption-${index}`;
      describedIds = `${caption.id} ${describedBy.id}`;
      input.setAttribute("aria-describedby", describedIds);
    }
    let keep = null;
    if (held.includes(name)) {
      keep = el("select");
      keep.id = `keep-${name}`;
      keep.ariaLabel = `Secret ${name}`;
      if (describedBy) keep.setAttribute("aria-describedby", describedIds);
      const kept = el("option", "Keep the current value");
      kept.value = "keep";
      const replaced = el("option", "Replace");
      replaced.value = "replace";
      keep.append(kept, replaced);
      keep.value = "keep";
      input.hidden = true;
      keep.addEventListener("change", () => {
        input.hidden = keep.value === "keep";
      });
      node.append(keep);
    }
    node.append(input);
    if (describedBy) node.append(caption, describedBy);
    const generate = el("button", "Generate a random value", "secondary");
    generate.type = "button";
    generate.ariaLabel = `Generate a random value for Secret ${name}`;
    generate.id = `generate-${name}`;
    generate.addEventListener("click", () => {
      input.value = [...crypto.getRandomValues(new Uint8Array(32))]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      if (keep) keep.value = "replace";
      input.hidden = false;
    });
    node.append(generate);
    return { name, input, keep, generate, node };
  });
}

// Reads every field once and empties it, or returns a note and leaves the fields as they were.
function takeValues(a) {
  const sent = a.fields.filter((f) => f.keep?.value !== "keep");
  if (sent.some((f) => !f.input.value)) return { note: MESSAGES.secret_missing };
  const values = sent.map((f) => ({ name: f.name, value: salted(utf8(f.input.value)), done: false }));
  for (const f of a.fields) f.input.value = "";
  a.secretsBox.replaceChildren(
    ...a.fields.map((f) =>
      el("p", f.keep?.value === "keep" ? `${f.name}: keeping the current value` : f.name),
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

// The next step, in the order the KMS needs them: each Secret put, then the registration, then
// the predecessor's revocation unless the person keeps it.
function offerApproval(a, note) {
  const revoke = Boolean(a.keep) && !a.keep.checked;
  const pending = a.values ? a.values.filter((v) => !v.done) : [];
  const total = (a.values ? a.values.length : 0) + 1 + (revoke ? 1 : 0);
  const left = pending.length + (a.registered ? 0 : 1) + (revoke ? 1 : 0);
  const step = total - left + 1;
  let label = step === 1 ? "Approve with passkey" : `Sign ${step} of ${total}`;
  let run;
  if (!a.values) run = firstAction(a);
  else if (pending.length) run = stepAction(a, pending[0]);
  else if (!a.registered) run = stepAction(a);
  else {
    label = `${label}: revoke the previous Revision ${a.before.compose_hash}`;
    run = revokeAction(a);
  }
  // Once the Revision is registered, declining would no longer undo anything.
  offer(a.ui, note, button(label, run), ...(a.registered ? [] : [declineButton(a)]));
}

// The first click reads the Secret values and fixes the choice of the predecessor, so its inputs
// are built in the click, before any await.
function firstAction(a) {
  return () => {
    const taken = takeValues(a);
    if (taken.note) return offerApproval(a, taken.note);
    a.values = taken.values;
    if (a.keep) a.keep.disabled = true;
    return a.values.length ? stepAction(a, a.values[0])() : stepAction(a)();
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
  const channel = await api(a.view, "POST", ticketPath(a.ticket, "channel"), sealer.hello());
  if (channel.status !== 200) return offerApproval(a, failure(channel));
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
  const reply = await api(a.view, "POST", ticketPath(a.ticket, "secret"), body);
  if (reply.status !== 200) return offerApproval(a, failure(reply));
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
  const payload = a.launch.payload;
  const signable = wasm_bindgen.signingDigest("revision", JSON.stringify(payload));
  return { payload, options: getOptions(a.view, signable.digest, allowed(a)) };
}

async function registerRevision(a, inputs) {
  const { read } = a;
  const { signature, note } = await approvalSignature(a, inputs.options);
  if (!signature) return offerApproval(a, note);
  const body = wasm_bindgen.canonicalJson(JSON.stringify({ payload: inputs.payload, signature }));
  const reply = await api(a.view, "POST", ticketPath(a.ticket, "revision"), body);
  if (reply.status !== 200) return offerApproval(a, failure(reply));
  const signed = receipt(a.view, reply, "revision.register", body, {
    app_id: read.app_id,
    compose_hash: read.compose_hash,
    org_id: read.org_id,
  });
  if (!signed) return offerApproval(a, MESSAGES.not_confirmed);
  a.registered = true;
  if (a.keep && !a.keep.checked) return offerApproval(a);
  return offer(a.ui, "", el("p", MESSAGES.approved, "confirmed"));
}

function revokeAction(a) {
  return async () => {
    const { note } = await revokeOne(a, a.before.compose_hash);
    if (note) return offerApproval(a, note);
    return offer(a.ui, "", el("p", MESSAGES.approved, "confirmed"));
  };
}

// Signs `{compose_hash, issued_at}` under the Control context and relays it; `{revokedAt}` once
// the receipt verified, or `{note}`. issued_at is taken before the prompt's await, so a page left
// open stays inside the KMS's five minutes.
async function revokeOne(x, hash) {
  const payload = { compose_hash: hash, issued_at: issuedAt() };
  const signable = wasm_bindgen.signingDigest("control", JSON.stringify(payload));
  const { signature, note } = await approvalSignature(x, getOptions(x.view, signable.digest, allowed(x)));
  if (!signature) return { note };
  const body = wasm_bindgen.canonicalJson(JSON.stringify({ payload, signature }));
  const reply = await api(x.view, "POST", ticketPath(x.ticket, "revoke"), body);
  if (reply.status !== 200) return { note: failure(reply) };
  const signed = receipt(x.view, reply, "revision.revoke", body, { compose_hash: hash });
  if (!signed || typeof signed.revoked_at !== "string") return { note: MESSAGES.not_confirmed };
  return { revokedAt: signed.revoked_at };
}

function declineButton(a) {
  return button(
    "Decline",
    async () => {
      const reply = await api(a.view, "POST", `/v1/tickets/${a.ticket}/decline`);
      if (reply.status === 200) return offer(a.ui, "", el("p", MESSAGES.declined, "confirmed"));
      a.ui.status.textContent = failure(reply);
    },
    "secondary",
  );
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

async function catalogLaunch(view, read) {
  const hex = /^(?:sha256:)?([0-9a-f]{64})$/.exec(read.catalog_template_sha256);
  const found = view.catalog_key && hex ? await catalogEntry(view, hex[1], read.app_id) : null;
  if (!found) return { refusal: MESSAGES.catalog };
  const { entry, compose } = found;
  const r = entry.resources || {};
  return parsedLaunch(read, compose, {
    machine: `${r.cpu} vCPU, ${r.memory_mib} MiB`,
    heading: `${entry.title}, version ${entry.version}`,
  });
}

// Which Revisions to revoke is the service's word: revoking only takes away, and the page can
// confirm a revocation but not that the list is complete.
function revocationRefusal(read) {
  if (
    !UUID.test(read.app_id) ||
    typeof read.title !== "string" ||
    !Array.isArray(read.revisions) ||
    !read.revisions.length ||
    !read.revisions.every((h) => HASH.test(h)) ||
    new Set(read.revisions).size !== read.revisions.length
  ) {
    return MESSAGES.unavailable;
  }
  return read.credentials.length ? null : MESSAGES.no_credentials;
}

async function startRevocation(view, ticket) {
  const { read, refusal } = await readTicket(view, ticket, "revoke", revocationRefusal);
  if (refusal) return stop(refusal);
  const ui = screen(el("p", `Revocation for ${read.org_name}`, "eyebrow"), el("h1", read.title));
  const r = { view, read, ticket, ui, credential: null, revoked: new Map(), rows: el("div") };
  ui.facts.replaceChildren(
    el("p", MESSAGES.revoke_effect, "warning"),
    fact("App", read.app_id),
    r.rows,
  );
  return offerRevocation(r);
}

// The next Revision to revoke: each is its own signed document, so each takes a touch.
function offerRevocation(r, note) {
  r.rows.replaceChildren(
    ...r.read.revisions.map((hash) => {
      const at = r.revoked.get(hash);
      return fact(at ? `Revoked at ${at}` : "To revoke", hash, "digest");
    }),
  );
  const pending = r.read.revisions.filter((hash) => !r.revoked.has(hash));
  if (!pending.length) return offer(r.ui, "", el("p", MESSAGES.revoked, "confirmed"));
  const total = r.read.revisions.length;
  const step = total - pending.length + 1;
  const label = step === 1 ? "Revoke with passkey" : `Sign ${step} of ${total}`;
  offer(r.ui, note, button(label, () => revoke(r, pending[0])));
}

async function revoke(r, hash) {
  const { note, revokedAt } = await revokeOne(r, hash);
  if (note) return offerRevocation(r, note);
  r.revoked.set(hash, revokedAt);
  return offerRevocation(r);
}

// A code typed at the signer address stands for the ticket of a link.
function offerCode(platform, note) {
  const ui = screen(el("h1", "Enter your code"));
  const input = el("input");
  input.id = "code";
  input.autocomplete = "off";
  const label = el("label", "Code");
  label.htmlFor = input.id;
  const go = button("Continue", async () => {
    const code = input.value.toUpperCase().replace(/[\s-]/g, "");
    if (!TICKET_CODE.test(code)) return offerCode(platform, MESSAGES.bad_code);
    const reply = await api(platform.view, "GET", `/v1/tickets/by-code/${code}`);
    const t = reply.body;
    if (reply.status !== 200) return offerCode(platform, failure(reply));
    if (!MODES.includes(t?.kind) || !TICKET.test(t.ticket)) {
      return offerCode(platform, MESSAGES.unavailable);
    }
    history.replaceState(null, "", `./${t.kind}#${t.ticket}`);
    return start(platform, t.kind, t.ticket);
  });
  offer(ui, note, label, input, go);
}

function start(platform, mode, ticket) {
  if (mode === "claim") return startClaim(platform.view, ticket);
  if (mode === "revoke") return startRevocation(platform.view, ticket);
  return startApproval(platform.view, platform.viewText, ticket);
}

function servedBySigner(view) {
  return Boolean(view.signer?.origins.includes(location.origin));
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

// Fetched with its integrity, which an @font-face source cannot carry, so that the hash of
// index.html covers the glyphs the page draws. A font that fails leaves the fallback in place.
async function loadFont() {
  if (!document.fonts) return;
  const reply = await fetch(FONT_URL, { integrity: FONT_SRI });
  const face = new FontFace("Public Sans", await reply.arrayBuffer());
  document.fonts.add(await face.load());
}

async function boot() {
  if (window.top !== window.self) return stop(MESSAGES.framed);
  if (!window.PublicKeyCredential) return stop(MESSAGES.no_passkeys);

  await wasm_bindgen({ module_or_path: fetch(WASM_URL, { integrity: WASM_SRI }) });

  const mode = location.pathname.split("/").pop();
  const ticket = location.hash.slice(1);
  if (!(mode === "" || MODES.includes(mode)) || (ticket && !(mode && TICKET.test(ticket)))) {
    return stop(MESSAGES.bad_link);
  }

  const platform = await verifiedPlatform();
  if (!platform) return stop(MESSAGES.platform);
  const { view } = platform;

  if (view.version < storedVersion()) return stop(MESSAGES.older_platform);
  storeVersion(view.version);

  if (!servedBySigner(view)) return stop(MESSAGES.not_signer);

  if (ticket) return start(platform, mode, ticket);
  if (mode === "claim" && location.search) return finishSignIn(view);
  return offerCode(platform);
}

document.addEventListener("DOMContentLoaded", () => {
  loadFont().catch(() => {});
  boot().catch(() => stop(MESSAGES.unexpected));
});
