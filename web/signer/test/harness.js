"use strict";
// Runs the built glue, wasm and page script in one vm context with a fake DOM, a virtual clock,
// a fake network and a software passkey, so the page's flows are tested on the real wasm.

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const realSetTimeout = setTimeout;

const ROOT = path.resolve(__dirname, "../../..");
const ORIGIN = "https://signer.test";
const RP_ID = "signer.test";
const TICKET = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT";

function testdata(name) {
  return fs.readFileSync(path.join(ROOT, "testdata", name), "utf8");
}

function dist() {
  const dir = process.env.SIGNER_DIST;
  if (!dir) throw new Error("set SIGNER_DIST to a directory web/signer/build.sh wrote");
  const files = fs.readdirSync(dir);
  const find = (re) => {
    const name = files.find((f) => re.test(f));
    if (!name) throw new Error(`${dir} has no file matching ${re}`);
    return path.join(dir, name);
  };
  return {
    glue: fs.readFileSync(find(/^alpha_channel-[0-9a-f]{16}\.js$/), "utf8"),
    page: fs.readFileSync(find(/^page-[0-9a-f]{16}\.js$/), "utf8"),
    wasmName: path.basename(find(/^alpha_channel_bg-[0-9a-f]{16}\.wasm$/)),
    wasm: fs.readFileSync(find(/^alpha_channel_bg-[0-9a-f]{16}\.wasm$/)),
  };
}

let built;
function bundle() {
  built = built || dist();
  return built;
}

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const sha256 = (data) => crypto.createHash("sha256").update(data).digest();

// JCS for the documents these tests build: sorted keys, ECMAScript serialization of primitives.
function jcs(value) {
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function contextDigest(context, canonicalText) {
  return sha256(Buffer.concat([Buffer.from(context), Buffer.from([0]), Buffer.from(canonicalText)]));
}

// --- ECDSA helpers --------------------------------------------------------------------------

const P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

function toBig(bytes) {
  return BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);
}

function derInt(n) {
  let bytes = Buffer.from(n.toString(16).padStart(64, "0"), "hex");
  while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
}

function derSignature(r, s) {
  const body = Buffer.concat([derInt(r), derInt(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function rawToRs(raw) {
  return [toBig(raw.subarray(0, 32)), toBig(raw.subarray(32))];
}

// --- receipts -------------------------------------------------------------------------------

const KMS_LEAF = testdata("channel/kms-leaf.pem");
const KMS_KEY = crypto.createPrivateKey(testdata("channel/kms-leaf-key.pem"));
const FOREIGN_LEAF = testdata("channel/foreign-leaf.pem");
const RECEIPT_TIME = "2026-06-01T00:00:00Z";

function kmsRevision() {
  const san = new crypto.X509Certificate(KMS_LEAF).subjectAltName;
  const m = /urn:alphacompute:revision:(sha256:[0-9a-f]{64})/.exec(san);
  if (!m) throw new Error("the test KMS leaf names no Revision");
  return m[1];
}

// The receipt the KMS issues for a Control route, as `receipt::issue` builds it. `options.leaf`
// swaps the certificate and `options.key` the signing key, to build receipts that must fail.
function mintReceipt(route, requestText, response, options = {}) {
  const document = {
    route,
    request_sha256: `sha256:${sha256(requestText).toString("hex")}`,
    response,
    issued_at: RECEIPT_TIME,
  };
  const digest = contextDigest("alphacompute/kms-receipt/v1", jcs(document));
  const raw = crypto.sign("sha256", digest, {
    key: options.key || KMS_KEY,
    dsaEncoding: "ieee-p1363",
  });
  return {
    document,
    signature: { algorithm: "ecdsa-p256", signature: b64u(raw) },
    certificate_chain: [options.leaf || KMS_LEAF],
  };
}

// The catalog test key: Ed25519 from the seed of 32 bytes 11, as the CLI's catalog tests use.
const CATALOG_KEY = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 11)]),
  format: "der",
  type: "pkcs8",
});

// A catalog file whose entry the catalog test key signs.
function catalogFile(entry, template) {
  const signature = crypto.sign(null, contextDigest("alphacompute/catalog/v1", jcs(entry)), CATALOG_KEY);
  return JSON.stringify({ entry, signature: { algorithm: "ed25519", signature: b64u(signature) }, template });
}

function testView() {
  const catalog = JSON.parse(testdata("catalog/expected.json"));
  const view = {
    version: 11,
    issued_at: "2026-09-23T13:17:36Z",
    kms_ca_pem: testdata("channel/ca.pem"),
    kms_revisions: [{ compose_hash: kmsRevision() }],
    signer: {
      origins: [ORIGIN],
      rp_id: RP_ID,
      api_origin: ORIGIN,
      bundle_sha256: `sha256:${"0".repeat(64)}`,
    },
    catalog_key: catalog.catalog_key,
  };
  return { view, viewText: JSON.stringify(view) };
}

// --- software passkey -----------------------------------------------------------------------

class SoftwareAuthenticator {
  constructor(options = {}) {
    this.flags = options.flags === undefined ? 0x1d : options.flags;
    this.highS = false;
    this.credentials = [];
    this.log = [];
    // Consumed by the next ceremony: {create: "NotAllowedError"}, {publicKey: null | "raw"},
    // {algorithm: -8}, {tamper: true} (one bit of the signature), {otherChallenge: true}.
    this.fault = {};
  }

  // A credential made outside the page, as one from an earlier claim.
  enroll() {
    const credential = this.newCredential(RP_ID);
    return { id: b64u(credential.id), spki: b64u(credential.spki) };
  }

  newCredential(rpId) {
    const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const credential = {
      id: crypto.randomBytes(16),
      rpId,
      privateKey: pair.privateKey,
      spki: pair.publicKey.export({ type: "spki", format: "der" }),
    };
    this.credentials.push(credential);
    return credential;
  }

  authData(rpId) {
    return Buffer.concat([sha256(rpId), Buffer.from([this.flags]), Buffer.alloc(4)]);
  }

  async create(options) {
    this.log.push({ kind: "create", options });
    const refusal = this.fault.create;
    if (refusal) {
      delete this.fault.create;
      throw new DOMException("refused", refusal);
    }
    const excluded = (options.excludeCredentials || []).map((c) => b64u(c.id));
    if (this.credentials.some((c) => excluded.includes(b64u(c.id)) && c.rpId === options.rp.id)) {
      throw new DOMException("already registered", "InvalidStateError");
    }
    const credential = this.newCredential(options.rp.id);
    let publicKey = credential.spki;
    if (this.fault.publicKey === null) publicKey = null;
    if (this.fault.publicKey === "raw") publicKey = credential.spki.subarray(26);
    const algorithm = this.fault.algorithm === undefined ? -7 : this.fault.algorithm;
    delete this.fault.publicKey;
    delete this.fault.algorithm;
    const authData = this.authData(options.rp.id);
    const result = {
      id: b64u(credential.id),
      rawId: new Uint8Array(credential.id).buffer,
      type: "public-key",
      response: {
        getPublicKey: () => (publicKey ? new Uint8Array(publicKey).buffer : null),
        getPublicKeyAlgorithm: () => algorithm,
        getAuthenticatorData: () => new Uint8Array(authData).buffer,
      },
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    };
    this.log[this.log.length - 1].result = { id: b64u(credential.id), spki: b64u(credential.spki) };
    return result;
  }

  async get(options) {
    this.log.push({ kind: "get", options });
    const allowed = (options.allowCredentials || []).map((c) => b64u(c.id));
    const held = this.credentials.filter((c) => c.rpId === options.rpId);
    const choice = this.prefer
      ? held.find((c) => b64u(c.id) === this.prefer && allowed.includes(this.prefer))
      : held.find((c) => allowed.length === 0 || allowed.includes(b64u(c.id)));
    if (!choice) throw new DOMException("no credential", "NotAllowedError");
    let challenge = Buffer.from(options.challenge);
    if (this.fault.otherChallenge) {
      challenge = crypto.randomBytes(32);
      delete this.fault.otherChallenge;
    }
    const clientData = Buffer.from(
      JSON.stringify({
        type: "webauthn.get",
        challenge: b64u(challenge),
        origin: ORIGIN,
        crossOrigin: false,
      }),
    );
    const authData = this.authData(options.rpId);
    const signed = Buffer.concat([authData, sha256(clientData)]);
    let signature = crypto.sign("sha256", signed, { key: choice.privateKey, dsaEncoding: "der" });
    if (this.highS) {
      const raw = crypto.sign("sha256", signed, {
        key: choice.privateKey,
        dsaEncoding: "ieee-p1363",
      });
      let [r, s] = rawToRs(raw);
      if (s <= P256_N / 2n) s = P256_N - s;
      signature = derSignature(r, s);
    }
    if (this.fault.tamper) {
      signature = Buffer.from(signature);
      signature[signature.length - 1] ^= 1;
      delete this.fault.tamper;
    }
    const assertion = {
      id: b64u(choice.id),
      signature: b64u(signature),
      authenticator_data: b64u(authData),
      client_data_json: b64u(clientData),
    };
    this.log[this.log.length - 1].result = assertion;
    return {
      id: assertion.id,
      rawId: new Uint8Array(choice.id).buffer,
      type: "public-key",
      response: {
        authenticatorData: new Uint8Array(authData).buffer,
        clientDataJSON: new Uint8Array(clientData).buffer,
        signature: new Uint8Array(signature).buffer,
        userHandle: null,
      },
    };
  }
}

// --- fake DOM -------------------------------------------------------------------------------

class Node {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.own = "";
    this.listeners = {};
    this.className = "";
    this.id = "";
    this.type = "";
    this.value = "";
    this.disabled = false;
    this.autocomplete = "";
  }

  append(...nodes) {
    for (const n of nodes) {
      const node = typeof n === "string" ? Object.assign(new Node("#text"), { own: n }) : n;
      node.parent = this;
      this.children.push(node);
    }
  }

  replaceChildren(...nodes) {
    this.children = [];
    this.own = "";
    this.append(...nodes);
  }

  get textContent() {
    return this.own + this.children.map((c) => c.textContent).join("");
  }

  set textContent(value) {
    this.children = [];
    this.own = String(value);
  }

  addEventListener(type, listener) {
    (this.listeners[type] = this.listeners[type] || []).push(listener);
  }

  *walk() {
    yield this;
    for (const c of this.children) yield* c.walk();
  }

  // One line per block, for assertions and failure messages; a span is inline, part of its line.
  lines() {
    if (this.tagName === "#TEXT") return this.own ? [this.own] : [];
    if (this.children.every((c) => c.tagName === "#TEXT" || c.tagName === "SPAN")) {
      const t = this.textContent;
      return t ? [t] : [];
    }
    const out = this.own ? [this.own] : [];
    for (const c of this.children) out.push(...c.lines());
    return out;
  }
}

// --- the page -------------------------------------------------------------------------------

function jsonReply(status, body, headers = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return new Response(text, {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function memoryStorage(initial = {}) {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (k) => (data.has(k) ? data.get(k) : null),
    setItem: (k, v) => data.set(k, String(v)),
  };
}

// options: routes {"METHOD /path": (req) => {status, body, headers}}, authenticator, platform
// (text, Error or null), catalog {"<hex>.json": text}, origin, path, hash, framed,
// noPasskeys, localStorage, sessionStorage, now.
async function loadPage(options = {}) {
  const b = bundle();
  const clock = { now: options.now === undefined ? Date.now() : options.now };
  const fetches = [];
  const timers = [];
  const prompts = [];
  const clicks = [];
  const authenticator = options.authenticator || new SoftwareAuthenticator();
  // The passkey provider the next prompt reaches; `page.use` moves to another device.
  const device = { current: authenticator };
  const wasmSri = `sha256-${crypto.createHash("sha256").update(b.wasm).digest("base64")}`;
  const routes = options.routes || {};

  class FakeDate extends Date {
    constructor(...args) {
      super(...(args.length ? args : [clock.now]));
    }

    static now() {
      return clock.now;
    }
  }

  const document = new Node("#document");
  const main = new Node("main");
  main.id = "main";
  document.getElementById = (id) => (id === "main" ? main : null);
  document.createElement = (tag) => new Node(tag);
  document.listeners = {};
  document.currentScript = null;

  async function fakeFetch(resource, init = {}) {
    const url = String(resource);
    const method = (init.method || "GET").toUpperCase();
    fetches.push({ method, url, body: init.body, time: clock.now });
    if (url === b.wasmName) {
      assert.equal(init.integrity, wasmSri, "the page fetched the wasm without its integrity");
      return new Response(b.wasm, { headers: { "Content-Type": "application/wasm" } });
    }
    if (url === "./platform.json") {
      const p = options.platform;
      if (p === undefined || p === null) return new Response("not found", { status: 404 });
      if (p instanceof Error) throw new TypeError("network");
      return new Response(p, { status: 200 });
    }
    if (url.startsWith("./catalog/")) {
      const text = (options.catalog || {})[url.slice("./catalog/".length)];
      return text === undefined
        ? new Response("not found", { status: 404 })
        : new Response(text, { status: 200 });
    }
    if (url.startsWith(`${ORIGIN}/`)) {
      const pathname = url.slice(ORIGIN.length);
      const key = `${method} ${pathname}`;
      const prefix = Object.keys(routes).find(
        (k) => k.endsWith("*") && key.startsWith(k.slice(0, -1)),
      );
      const route = routes[key] || routes[prefix];
      if (!route) return jsonReply(404, { error: "no route", error_code: "SHROUD_NOT_FOUND" });
      const answer = await route({ method, path: pathname, body: init.body });
      if (answer instanceof Error) throw new TypeError("network");
      return jsonReply(answer.status, answer.body, answer.headers);
    }
    throw new Error(`the page fetched ${url}`);
  }

  const consoleCalls = [];
  const sandbox = {
    document,
    location: {
      origin: options.origin || ORIGIN,
      pathname: options.path || "/sign/claim",
      hash: `#${options.hash === undefined ? TICKET : options.hash}`,
    },
    localStorage: options.localStorage || memoryStorage(),
    sessionStorage: options.sessionStorage || memoryStorage(),
    navigator: {
      credentials: {
        create: (o) => {
          prompts.push({ kind: "create", fetches: fetches.length, click: clicks[clicks.length - 1] });
          return device.current.create(o.publicKey);
        },
        get: (o) => {
          prompts.push({ kind: "get", fetches: fetches.length, click: clicks[clicks.length - 1] });
          return device.current.get(o.publicKey);
        },
      },
    },
    PublicKeyCredential: options.noPasskeys ? undefined : function PublicKeyCredential() {},
    crypto: crypto.webcrypto,
    fetch: fakeFetch,
    setTimeout: (fn, ms) => {
      timers.push(ms);
      clock.now += ms;
      Promise.resolve().then(fn);
      return timers.length;
    },
    console: new Proxy(
      {},
      {
        get: (_, name) => (...args) => consoleCalls.push({ name, args }),
      },
    ),
    Date: FakeDate,
    TextEncoder,
    TextDecoder,
    Response,
    Headers,
    URL,
    DOMException,
    atob,
    btoa,
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.top = options.framed ? {} : sandbox;
  document.addEventListener = (type, listener) => {
    (document.listeners[type] = document.listeners[type] || []).push(listener);
  };

  const context = vm.createContext(sandbox);
  vm.runInContext(b.glue, context, { filename: "alpha_channel.js" });
  vm.runInContext(b.page, context, { filename: "page.js" });

  // No KMS-profile responder runs here, so `options.sealer` swaps the wasm sealer for one that
  // records its inputs and returns a fixed `sealed` member; sealing itself is tested in Rust.
  const seals = [];
  if (options.sealer) {
    class RecordingSealer {
      constructor() {
        this.record = { hello: `{"client_hello":${seals.length + 1}}` };
        seals.push(this.record);
      }

      hello() {
        return this.record.hello;
      }

      seal(serverHello, platform, payload, orgId, value, now) {
        if (this.record.sealed) throw new Error("malformed: the sealer already sealed");
        Object.assign(this.record, {
          serverHello,
          platform,
          payload,
          orgId,
          value: Buffer.from(value),
          now,
          sealed: true,
        });
        return JSON.stringify({ ticket: `ticket-${seals.length}`, frame: "sealed-frame" });
      }
    }
    vm.runInContext("wasm_bindgen", context).KmsSecretSealer = RecordingSealer;
  }

  const page = {
    context,
    clock,
    fetches,
    timers,
    prompts,
    authenticator,
    consoleCalls,
    seals,
    main,
    use(other) {
      device.current = other;
    },
    call(name, ...args) {
      context.__args = args;
      return vm.runInContext(`${name}(...__args)`, context);
    },
    wasm: () => vm.runInContext("wasm_bindgen", context),
    text: () => main.lines().join("\n"),
    buttons: () =>
      [...main.walk()].filter((n) => n.tagName === "BUTTON").map((n) => n.textContent),
    find(predicate) {
      return [...main.walk()].find(predicate);
    },
    async click(label) {
      const target = [...main.walk()].find(
        (n) => n.tagName === "BUTTON" && n.textContent === label && !n.disabled,
      );
      if (!target) {
        throw new Error(`no active button "${label}" in:\n${page.text()}\nbuttons: ${page.buttons()}`);
      }
      clicks.push(fetches.length);
      for (const listener of target.listeners.click || []) await listener({ target });
    },
    // The page's listener does not return boot()'s promise, so this waits, in real time, until
    // the page has left "Loading…".
    async boot() {
      for (const listener of document.listeners.DOMContentLoaded || []) listener({});
      for (let i = 0; i < 2000 && page.text() === "Loading…"; i += 1) {
        await new Promise((r) => realSetTimeout(r, 5));
      }
    },
    async init() {
      await vm.runInContext(
        "wasm_bindgen({ module_or_path: fetch(WASM_URL, { integrity: WASM_SRI }) })",
        context,
      );
    },
    async startClaim(ticket = TICKET, view = testView()) {
      await page.init();
      await page.call("startClaim", view.view, ticket);
    },
    async startApproval(ticket = TICKET, view = testView()) {
      await page.init();
      await page.call("startApproval", view.view, view.viewText, ticket);
    },
  };
  main.replaceChildren(Object.assign(new Node("p"), { own: "Loading…" }));
  return page;
}

function iso(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// shroud-go's claim routes for one ticket, with the KMS behind them answering every key
// registration with a receipt. `api.receiptFor(registrationText, response)` may be replaced to
// return a receipt that must fail.
function claimApi(options = {}) {
  const now = options.now === undefined ? Date.now() : options.now;
  const api = {
    org_id: crypto.randomUUID(),
    principal_id: crypto.randomUUID(),
    kind: options.kind || "root",
    state: options.state || "open",
    org_name: "Acme",
    expires_at: options.expires_at || iso(now + 72 * 3600 * 1000),
    server_time: options.server_time || iso(now),
    keys_left: options.keys_left === undefined ? 3 : options.keys_left,
    credentials: options.credentials || [],
    reveals: 0,
    registrations: [],
    read: options.read,
    receiptFor: (registrationText, response) =>
      mintReceipt("key.register", registrationText, response),
  };
  const base = `/v1/claims/${TICKET}`;
  api.routes = {
    [`GET ${base}`]: () =>
      api.read || {
        status: 200,
        body: {
          org_name: api.org_name,
          kind: api.kind,
          state: api.state,
          keys_left: api.keys_left,
          expires_at: api.expires_at,
          server_time: api.server_time,
          credentials: api.credentials,
        },
      },
    [`POST ${base}/org`]: () => {
      api.reveals += 1;
      if (api.reveals > 1) {
        return {
          status: 409,
          body: {
            error: "this claim's organization was already handed out",
            error_code: "SHROUD_CONFLICT",
          },
        };
      }
      return { status: 200, body: { org_id: api.org_id, principal_id: api.principal_id } };
    },
    [`POST ${base}/keys`]: (req) => {
      const prefix = /^\{"credential_id":("[A-Za-z0-9_-]+"),"registration":/.exec(req.body);
      assert.ok(prefix && req.body.endsWith("}"), `unexpected keys body ${req.body}`);
      const credentialId = JSON.parse(prefix[1]);
      const registrationText = req.body.slice(prefix[0].length, -1);
      const registration = JSON.parse(registrationText);
      api.registrations.push({ credentialId, registrationText, registration, body: req.body });
      if (api.keysReply) return api.keysReply(registrationText);
      const response = {
        id: crypto.randomUUID(),
        principal_id: registration.payload.principal_id,
        org_id: api.org_id,
        public_key: registration.payload.public_key,
        created_at: RECEIPT_TIME,
      };
      api.credentials.push({ credential_id: credentialId, key_id: response.id });
      api.keys_left -= 1;
      if (!registration.signature.key_id) api.state = "rooted";
      return {
        status: 200,
        body: { ...response, receipt: api.receiptFor(registrationText, response) },
      };
    },
  };
  return api;
}

// shroud-go's approval routes for one ticket, with the KMS behind them. Receipts come from
// `api.revisionReceipt` and `api.putReceipt`, which a test may replace; `api.reply[route]` may
// answer a route instead (route: "revision", "put").
function approvalApi(options = {}) {
  const now = options.now === undefined ? Date.now() : options.now;
  const compose = options.compose;
  const api = {
    org_id: crypto.randomUUID(),
    org_name: "Acme",
    app_id: options.app_id,
    title: "Production",
    compose_hash: options.compose_hash || `sha256:${sha256(compose || "").toString("hex")}`,
    catalog_template_sha256: options.catalog_template_sha256 || null,
    compose: options.catalog_template_sha256 ? null : compose,
    machine: "tdx.medium",
    credentials: options.credentials || [],
    current: options.current || null,
    expires_at: options.expires_at || iso(now + 24 * 3600 * 1000),
    state: options.state || "pending",
    server_time: options.server_time || iso(now),
    read: options.read,
    revisions: [],
    puts: [],
    channels: [],
    reply: {},
    revisionReceipt: (text, response) => mintReceipt("revision.register", text, response),
    putReceipt: (text, response) => mintReceipt("secret.put", text, response),
  };
  const base = `/v1/approval-requests/${TICKET}`;
  const fields = [
    "org_id",
    "org_name",
    "app_id",
    "title",
    "compose_hash",
    "catalog_template_sha256",
    "compose",
    "machine",
    "credentials",
    "current",
    "expires_at",
    "state",
    "server_time",
  ];
  api.routes = {
    [`GET ${base}`]: () =>
      api.read || { status: 200, body: Object.fromEntries(fields.map((k) => [k, api[k]])) },
    [`POST ${base}/decline`]: () => {
      if (api.state !== "pending") {
        return {
          status: 409,
          body: { error: "conflict", error_code: "SHROUD_CONFLICT", details: { state: api.state } },
        };
      }
      api.state = "cancelled";
      return { status: 200, body: { state: "cancelled" } };
    },
    [`POST ${base}/revision`]: (req) => {
      const body = JSON.parse(req.body);
      api.revisions.push({ text: req.body, body, puts: api.puts.length });
      if (api.reply.revision) return api.reply.revision(req.body);
      const response = {
        compose_hash: `sha256:${sha256(body.payload.compose).toString("hex")}`,
        app_id: body.payload.app_id,
        org_id: api.org_id,
        created_at: RECEIPT_TIME,
      };
      api.state = "approved";
      return {
        status: 200,
        body: { ...response, receipt: api.revisionReceipt(req.body, response) },
      };
    },
    [`POST ${base}/kms-channel`]: (req) => {
      api.channels.push(req.body);
      return { status: 200, body: { server_hello: api.channels.length } };
    },
    [`PUT ${base}/secrets/*`]: (req) => {
      const declared = req.path.slice(`${base}/secrets/`.length);
      const body = JSON.parse(req.body);
      api.puts.push({ declared, text: req.body, body });
      const answer = api.reply.put && api.reply.put(req.body, declared);
      if (answer) return answer;
      const p = body.payload;
      const response = {
        id: crypto.randomUUID(),
        name: p.name,
        org_id: api.org_id,
        app_ids: p.app_ids,
        content_sha256: p.content_sha256,
        issued_at: p.issued_at,
      };
      return { status: 200, body: { ...response, receipt: api.putReceipt(req.body, response) } };
    },
  };
  return api;
}

const NOT_CONFIRMED = "Not confirmed by the KMS.";
// Values made inside the page's context have that context's prototypes.
const plain = (value) => JSON.parse(JSON.stringify(value));
const ids = (list) => plain(list.map((c) => b64u(Buffer.from(c.id))));

module.exports = {
  NOT_CONFIRMED,
  plain,
  ids,
  approvalApi,
  catalogFile,
  RP_ID,
  TICKET,
  SoftwareAuthenticator,
  b64u,
  claimApi,
  contextDigest,
  iso,
  jcs,
  loadPage,
  memoryStorage,
  mintReceipt,
  sha256,
  testView,
  testdata,
  FOREIGN_LEAF,
};
