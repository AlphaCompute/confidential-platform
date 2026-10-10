"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  NOT_CONFIRMED,
  SoftwareAuthenticator,
  approvalApi,
  b64u,
  catalogFile,
  contextDigest,
  iso,
  jcs,
  loadPage,
  memoryStorage,
  mintReceipt,
  ids,
  plain,
  sha256,
  testView,
  testdata,
} = require("./harness.js");

const APPROVED = "Approved. You can close this tab.";
const MISMATCH =
  "What the service asked you to approve does not match what it would run. Nothing was signed.";

const WRAP = testdata("manifest/08-wrap/app-compose.json");
const WRAP_APP = JSON.parse(testdata("manifest/08-wrap/expected.json")).app_id;

// The wrapped compose of the vector with its Secrets list taken out of the measured runtime.
function withoutSecrets() {
  const compose = JSON.parse(WRAP);
  const lines = compose.docker_compose_file.split("\n");
  compose.docker_compose_file = lines.filter((l) => !l.includes("ALPHACOMPUTE_SECRETS")).join("\n");
  return jcs(compose);
}


// An organization with two passkeys on one laptop; the second answers.
function organization() {
  const laptop = new SoftwareAuthenticator();
  const a = laptop.enroll();
  const b = laptop.enroll();
  laptop.prefer = b.id;
  const credentials = [
    { credential_id: a.id, key_id: "01920000-0000-7000-8000-00000000000a" },
    { credential_id: b.id, key_id: "01920000-0000-7000-8000-00000000000b" },
  ];
  return { laptop, credentials };
}

async function approvalPage(apiOptions = {}, pageOptions = {}, view = undefined) {
  const { laptop, credentials } = organization();
  const api = approvalApi({ app_id: WRAP_APP, credentials, ...apiOptions });
  const page = await loadPage({
    routes: api.routes,
    authenticator: laptop,
    path: "/sign/approve",
    ...pageOptions,
  });
  await page.startApproval(undefined, view);
  return { api, page, laptop, credentials };
}

test("an uploaded compose is approved only after the registration receipt verifies", async () => {
  const compose = withoutSecrets();
  const { api, page, laptop, credentials } = await approvalPage({ compose });
  const text = page.text();
  for (const line of [
    "Production",
    "web",
    "Image: nginx:1.27",
    `Digest: sha256:${"ab".repeat(32)}`,
    "Image: postgres",
    "Named volumes: pgdata, alpha-secrets-db",
    "Named volumes: cachedata",
    "AlphaCompute runtime",
    "Image: ghcr.io/alphacompute/alpha-runtime",
    `Digest: sha256:${"7d".repeat(32)}`,
    "Endpoint: HTTPS on 443, forwarded to web:80",
    "Machine: tdx.medium (chosen by the service, not part of what you sign)",
  ]) {
    assert.ok(text.includes(line), `${line}\n${text}`);
  }
  assert.ok(!text.includes("Receives secrets"));
  assert.ok(!text.includes("Published ports"), "only the runtime publishes a port");
  const details = page.find((n) => n.tagName === "DETAILS");
  assert.ok(details && !details.open);
  const technical = details.lines().join("\n");
  assert.ok(technical.includes("Technical details"));
  assert.ok(technical.includes(compose));
  assert.ok(technical.includes(WRAP_APP));
  assert.ok(technical.includes(api.compose_hash));
  assert.ok(!text.includes(APPROVED));

  await page.click("Approve with passkey");
  const got = laptop.log[0];
  assert.deepEqual(ids(got.options.allowCredentials), credentials.map((c) => c.credential_id));
  const wasm = page.wasm();
  const payload = { app_id: WRAP_APP, compose };
  assert.deepEqual(
    Buffer.from(got.options.challenge),
    contextDigest("alphacompute/revision/v1", wasm.canonicalJson(JSON.stringify(payload))),
  );
  const assertion = got.result;
  const expected = wasm.canonicalJson(
    JSON.stringify({
      payload,
      signature: {
        key_id: credentials[1].key_id,
        algorithm: "webauthn-es256",
        signature: assertion.signature,
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
      },
    }),
  );
  assert.equal(api.revisions.length, 1);
  assert.equal(api.revisions[0].text, expected);
  assert.ok(page.text().includes(APPROVED), page.text());
});

// The approval page's text for the vector with each `[from, to]` replaced in its compose.
async function shown(...replacements) {
  const compose = JSON.parse(withoutSecrets());
  for (const [from, to] of replacements) {
    compose.docker_compose_file = compose.docker_compose_file.replace(from, to);
  }
  const { page } = await approvalPage({ compose: jcs(compose) });
  return page.text();
}

test("a runtime port is an endpoint only with an upstream, a host side and TCP", async () => {
  const upstream = ["      ALPHACOMPUTE_TLS_UPSTREAM: web:80\n", ""];
  const none = await shown(["    ports:\n    - 443:8443\n", ""], upstream);
  assert.ok(none.includes("AlphaCompute runtime"), none);
  assert.ok(!none.includes("Endpoint") && !none.includes("Published ports"), none);
  const noUpstream = await shown(upstream);
  assert.ok(noUpstream.includes("Published ports: 443:8443"), noUpstream);
  assert.ok(!noUpstream.includes("Endpoint"), noUpstream);
  for (const port of ["443:8443/udp", "8443", "443:1234"]) {
    const text = await shown(["    - 443:8443\n", `    - ${port}\n`]);
    assert.ok(text.includes(`Published ports: ${port}`), text);
    assert.ok(!text.includes("Endpoint"), text);
  }
  const bound = await shown(["    - 443:8443\n", "    - 127.0.0.1:443:8443\n"]);
  assert.ok(bound.includes("Endpoint: HTTPS on 127.0.0.1:443, forwarded to web:80"), bound);
  const mixed = await shown(["    - 443:8443\n", "    - 443:8443/tcp\n    - 8444:8444/udp\n"]);
  assert.ok(mixed.includes("Endpoint: HTTPS on 443, forwarded to web:80"), mixed);
  assert.ok(mixed.includes("Published ports: 8444:8444/udp"), mixed);
});

test("a registration receipt that does not verify never reads approved", async () => {
  const compose = withoutSecrets();
  const faults = {
    "other bytes": (text, response) => mintReceipt("revision.register", `${text} `, response),
    "another organization": (text, response) =>
      mintReceipt("revision.register", text, {
        ...response,
        org_id: "01920000-0000-7000-8000-0000000000ff",
      }),
    "another compose": (text, response) =>
      mintReceipt("revision.register", text, {
        ...response,
        compose_hash: `sha256:${"0".repeat(64)}`,
      }),
  };
  for (const [name, fault] of Object.entries(faults)) {
    const { api, page } = await approvalPage({ compose });
    api.revisionReceipt = fault;
    await page.click("Approve with passkey");
    assert.ok(page.text().includes(NOT_CONFIRMED), `${name}: ${page.text()}`);
    assert.ok(!page.text().includes(APPROVED), name);
  }
  const { api, page } = await approvalPage({ compose });
  api.reply.revision = () => ({
    status: 502,
    body: { error: "<script>x</script>", error_code: "SHROUD_UPSTREAM_INVALID" },
  });
  await page.click("Approve with passkey");
  assert.ok(page.text().includes(NOT_CONFIRMED));
  assert.ok(!page.text().includes("<script>"));
  assert.ok(!page.text().includes(APPROVED));
});

test("a compose that does not hash to the request is refused before any prompt", async () => {
  const compose = withoutSecrets();
  const changed = compose.replace("nginx:1.27", "nginx:1.28");
  assert.notEqual(changed, compose);
  const { page, laptop } = await approvalPage({
    compose: changed,
    compose_hash: approvalApi({ compose }).compose_hash,
  });
  assert.equal(page.text(), MISMATCH);
  assert.deepEqual(page.buttons(), []);
  assert.equal(laptop.log.length, 0);
});

test("a compose that hashes to the request but cannot be read is refused as unreadable", async () => {
  const compose = JSON.parse(withoutSecrets());
  compose.docker_compose_file = "services: [";
  const { page, laptop } = await approvalPage({ compose: jcs(compose) });
  assert.equal(
    page.text(),
    "This page cannot read what the service asked you to approve, so it cannot show it to you. Nothing was signed.",
  );
  assert.deepEqual(page.buttons(), []);
  assert.equal(laptop.log.length, 0);
});

test("a request without known passkeys is refused", async () => {
  const { page, laptop } = await approvalPage({ compose: withoutSecrets(), credentials: [] });
  assert.equal(
    page.text(),
    "No passkey of this organization is known. Ask your AlphaCompute contact.",
  );
  assert.equal(laptop.log.length, 0);
});

const CATALOG = JSON.parse(testdata("catalog/expected.json"));
const VALID = testdata("catalog/valid.json");
const VALID_FILE = JSON.parse(VALID);
const TEMPLATE_HEX = VALID_FILE.entry.template_sha256.slice("sha256:".length);
const CATALOG_COMPOSE = testdata("catalog/app-compose.json");
const CATALOG_REFUSED =
  "The catalog entry for this launch is not signed by AlphaCompute. Nothing was signed.";
const NIL_NAME = '"name":"00000000-0000-0000-0000-000000000000"';
const hex = (text) => sha256(text).toString("hex");

function catalogPage(files, apiOptions = {}, pageOptions = {}) {
  return approvalPage(
    {
      app_id: CATALOG.app_id,
      compose_hash: CATALOG.compose_hash,
      catalog_template_sha256: VALID_FILE.entry.template_sha256,
      ...apiOptions,
    },
    { catalog: files, ...pageOptions },
  );
}

test("a catalog app is rendered in wasm and its hash must match", async () => {
  const { api, page } = await catalogPage({ [`${TEMPLATE_HEX}.json`]: VALID });
  assert.ok(page.fetches.some((f) => f.url === `./catalog/${TEMPLATE_HEX}.json`));
  const text = page.text();
  for (const line of [
    "CPU App, version 1",
    "Machine: 1 vCPU, 2048 MiB",
    "Image: ghcr.io/alphacompute/alpha-cpu-app",
    `Digest: sha256:${"3a".repeat(32)}`,
    "Published ports: 443:8443",
    "Image: ghcr.io/alphacompute/alpha-runtime",
  ]) {
    assert.ok(text.includes(line), `${line}\n${text}`);
  }
  assert.ok(!text.includes("chosen by the service"));
  await page.click("Approve with passkey");
  assert.equal(api.revisions[0].body.payload.compose, CATALOG_COMPOSE);
  assert.ok(page.text().includes(APPROVED), page.text());
});

test("a catalog entry that does not verify is refused", async () => {
  for (const name of [
    "signed-by-other-key.json",
    "signed-by-release-key.json",
    "template-tampered.json",
    "name-repeated.json",
    "name-absent.json",
  ]) {
    const { page, laptop } = await catalogPage({ [`${TEMPLATE_HEX}.json`]: testdata(`catalog/${name}`) });
    assert.equal(page.text(), CATALOG_REFUSED, name);
    assert.equal(laptop.log.length, 0, name);
  }
  const missing = await catalogPage({});
  assert.equal(missing.page.text(), CATALOG_REFUSED);

  const { view } = testView();
  delete view.catalog_key;
  const { page } = await approvalPage(
    {
      app_id: CATALOG.app_id,
      compose_hash: CATALOG.compose_hash,
      catalog_template_sha256: VALID_FILE.entry.template_sha256,
    },
    { catalog: { [`${TEMPLATE_HEX}.json`]: VALID } },
    { view, viewText: JSON.stringify(view) },
  );
  assert.equal(page.text(), CATALOG_REFUSED);

  const other = await catalogPage(
    { [`${TEMPLATE_HEX}.json`]: VALID },
    { compose_hash: `sha256:${"0".repeat(64)}` },
  );
  assert.equal(other.page.text(), MISMATCH);
  assert.equal(other.laptop.log.length, 0);
});

test("a replacement names both versions only when the old entry verifies", async () => {
  const oldTemplate = VALID_FILE.template.replace(
    "alpha-cpu-app@sha256:3a",
    "alpha-cpu-app@sha256:4a",
  );
  assert.notEqual(oldTemplate, VALID_FILE.template);
  const oldEntry = { ...VALID_FILE.entry, version: "0", template_sha256: `sha256:${hex(oldTemplate)}` };
  const oldCompose = oldTemplate.replace(NIL_NAME, `"name":"${CATALOG.app_id}"`);
  const current = { compose_hash: `sha256:${hex(oldCompose)}`, compose: oldCompose };
  const files = (old) => ({ [`${TEMPLATE_HEX}.json`]: VALID, [`${hex(oldTemplate)}.json`]: old });

  const named = await catalogPage(files(catalogFile(oldEntry, oldTemplate)), { current });
  assert.ok(named.page.text().includes("CPU App, version 0 → 1"), named.page.text());
  assert.ok(!named.page.text().includes("not from this catalog"));

  const forged = JSON.parse(catalogFile(oldEntry, oldTemplate));
  forged.signature.signature = `A${forged.signature.signature.slice(1)}`;
  const elsewhere = catalogFile({ ...oldEntry, catalog_id: "gpu-app" }, oldTemplate);
  for (const [name, old] of [
    ["no catalog file", undefined],
    ["a forged signature", JSON.stringify(forged)],
    ["another catalog id", elsewhere],
  ]) {
    const { page } = await catalogPage(files(old), { current });
    const text = page.text();
    assert.ok(text.includes("replacing a launch not from this catalog"), `${name}: ${text}`);
    assert.ok(!text.includes("version 0"), name);
    assert.ok(text.includes("CPU App, version 1"), name);
    const line = text.split("\n").find((l) => l.startsWith("app: "));
    assert.ok(line, `${name}: ${text}`);
    assert.ok(line.includes("according to the service"), line);
    assert.ok(line.includes(`alpha-cpu-app@sha256:4a${"3a".repeat(31)}`), line);
    assert.ok(!text.split("\n").some((l) => l.startsWith("alpha-runtime: ")), name);
  }
});

test("decline cancels the request", async () => {
  const { api, page, laptop } = await approvalPage({ compose: withoutSecrets() });
  await page.click("Decline");
  assert.ok(page.text().includes("Declined. You can close this tab."), page.text());
  assert.equal(api.state, "cancelled");
  assert.equal(laptop.log.length, 0);
  assert.equal(api.revisions.length, 0);

  const late = await approvalPage({ compose: withoutSecrets() });
  late.api.state = "approved";
  await late.page.click("Decline");
  assert.ok(
    late.page.text().includes("This request was already approved, declined or cancelled."),
    late.page.text(),
  );
});

test("every refusal is one fixed sentence", async () => {
  const now = Date.now();
  const EXPIRED = "This approval link has expired.";
  const DECIDED = "This request was already approved, declined or cancelled.";
  const read = [
    [{ state: "expired" }, EXPIRED],
    [{ expires_at: iso(now - 1000) }, EXPIRED],
    [{ state: "approved" }, DECIDED],
    [{ state: "cancelled" }, DECIDED],
    [{ read: { status: 404, body: { error: "x", error_code: "SHROUD_NOT_FOUND" } } }, "This link is not valid."],
    [
      { read: { status: 503, body: { error: "x", error_code: "SHROUD_SERVICE_UNAVAILABLE" } } },
      "The service is unavailable. Try again in a minute.",
    ],
    [
      { server_time: iso(now + 7 * 60 * 1000) },
      "Your device clock is off by about 7 minutes. Correct it and reload.",
    ],
  ];
  for (const [options, sentence] of read) {
    const { page } = await approvalPage({ compose: withoutSecrets(), now, ...options }, { now });
    assert.equal(page.text(), sentence, JSON.stringify(options));
  }

  const { laptop, credentials } = organization();
  const api = approvalApi({ app_id: WRAP_APP, compose: withoutSecrets(), credentials });
  const get = api.routes[Object.keys(api.routes).find((k) => k.startsWith("GET "))];
  let reads = 0;
  api.routes[Object.keys(api.routes).find((k) => k.startsWith("GET "))] = (req) => {
    reads += 1;
    if (reads === 1) {
      return {
        status: 429,
        body: { error: "slow down", error_code: "SHROUD_RATE_LIMITED" },
        headers: { "Retry-After": "2" },
      };
    }
    return get(req);
  };
  const limited = await loadPage({ routes: api.routes, authenticator: laptop });
  await limited.startApproval();
  assert.equal(reads, 2);
  assert.ok(limited.timers.includes(2000), JSON.stringify(limited.timers));
  assert.ok(limited.buttons().includes("Approve with passkey"), limited.text());

  const kms = [
    [
      { status: 400, body: { error: { code: "signature_invalid", message: "<b>bad</b>" } } },
      "The KMS did not accept the passkey's signature. Nothing was changed.",
    ],
    [
      { status: 409, body: { error: { code: "revision_revoked", message: "revoked" } } },
      "The KMS refuses this launch because it was revoked before. Nothing was approved.",
    ],
    [
      { status: 400, body: { error: { code: "strange_thing", message: "<i>no</i>" } } },
      "The KMS refused this request (strange_thing).",
    ],
    [
      { status: 400, body: { error: "<img src=x onerror=alert(1)>", error_code: "<b>x</b>" } },
      "The service is unavailable. Try again in a minute.",
    ],
  ];
  for (const [reply, sentence] of kms) {
    const { api: kmsApi, page } = await approvalPage({ compose: withoutSecrets() });
    kmsApi.reply.revision = () => reply;
    await page.click("Approve with passkey");
    const text = page.text();
    assert.ok(text.includes(sentence), `${sentence}\n${text}`);
    assert.ok(!text.includes(APPROVED));
    for (const markup of ["<b>", "<i>", "<img"]) {
      assert.ok(!text.includes(markup), `${markup} in ${text}`);
    }
  }
});

const SECRET_VALUES = { db_password: "pw-correct-horse-1", session_key: "sk-battery-staple-2" };

function secretPage(apiOptions = {}, pageOptions = {}) {
  return approvalPage({ compose: WRAP, ...apiOptions }, { sealer: true, ...pageOptions });
}

const field = (page, name) => page.find((n) => n.id === `secret-${name}`);
const keepChoice = (page, name) => page.find((n) => n.id === `keep-${name}`);

function fill(page, values) {
  for (const [name, value] of Object.entries(values)) field(page, name).value = value;
}

// The same declared names, with only db_password delivered: the launch a re-approval replaces.
function currentWithDbPassword() {
  const compose = JSON.parse(WRAP);
  compose.docker_compose_file = compose.docker_compose_file.replace(
    `ALPHACOMPUTE_SECRETS: '{"db":["db_password"],"web":["db_password","session_key"]}'`,
    `ALPHACOMPUTE_SECRETS: '{"db":["db_password"]}'`,
  );
  const text = jcs(compose);
  assert.notEqual(text, WRAP);
  return { compose_hash: `sha256:${hex(text)}`, compose: text };
}

async function approveAll(page) {
  await page.click("Approve with passkey");
  await page.click("Sign 2 of 3");
  await page.click("Sign 3 of 3");
}

test("every secret is put and confirmed before the registration", async () => {
  // Exists so that offering the registration before the last put's receipt verified fails.
  const { api, page, laptop, credentials } = await secretPage();
  const text = page.text();
  assert.ok(text.includes("Receives secrets: db_password, session_key"), text);
  assert.ok(text.includes("Receives secrets: db_password"), text);
  for (const name of Object.keys(SECRET_VALUES)) {
    const input = field(page, name);
    assert.equal(input.type, "password");
    assert.equal(input.autocomplete, "off");
    assert.ok(text.includes(`Secret ${name}`));
  }
  fill(page, SECRET_VALUES);

  await page.click("Approve with passkey");
  assert.equal(api.puts.length, 1);
  assert.equal(api.revisions.length, 0);
  assert.ok(page.buttons().includes("Sign 2 of 3"), page.buttons());
  await page.click("Sign 2 of 3");
  assert.equal(api.puts.length, 2);
  assert.equal(api.revisions.length, 0);
  assert.ok(page.buttons().includes("Sign 3 of 3"), page.buttons());
  await page.click("Sign 3 of 3");
  assert.equal(api.revisions.length, 1);
  assert.equal(api.revisions[0].puts, 2);
  assert.ok(page.text().includes(APPROVED), page.text());

  const wasm = page.wasm();
  const gets = laptop.log.filter((l) => l.kind === "get");
  assert.equal(gets.length, 3);
  const names = Object.keys(SECRET_VALUES).sort();
  for (const [i, name] of names.entries()) {
    const sent = api.puts[i];
    assert.equal(sent.declared, name);
    const value = SECRET_VALUES[name];
    const payload = {
      name: `${WRAP_APP}.${name}`,
      app_ids: [WRAP_APP],
      content_sha256: `sha256:${hex(value)}`,
      issued_at: sent.body.payload.issued_at,
    };
    const document = wasm.canonicalJson(JSON.stringify(payload));
    assert.deepEqual(
      Buffer.from(gets[i].options.challenge),
      contextDigest("alphacompute/secret/v1", document),
    );
    const seal = page.seals[i];
    assert.equal(api.channels[i], seal.hello);
    assert.equal(seal.serverHello, wasm.canonicalJson(JSON.stringify({ server_hello: i + 1 })));
    assert.equal(seal.platform, testView().viewText);
    assert.equal(seal.payload, document);
    assert.equal(seal.orgId, api.org_id);
    assert.equal(seal.value.toString(), value);
    const assertion = gets[i].result;
    assert.equal(
      sent.text,
      wasm.canonicalJson(
        JSON.stringify({
          payload,
          signature: {
            key_id: credentials[1].key_id,
            algorithm: "webauthn-es256",
            signature: assertion.signature,
            authenticator_data: assertion.authenticator_data,
            client_data_json: assertion.client_data_json,
          },
          sealed: { ticket: `ticket-${i + 1}`, frame: "sealed-frame" },
        }),
      ),
    );
  }
});

test("later touches use the passkey of the first", async () => {
  const { page, laptop, credentials } = await secretPage();
  fill(page, SECRET_VALUES);
  await approveAll(page);
  assert.ok(page.text().includes(APPROVED));
  const gets = laptop.log.filter((l) => l.kind === "get");
  assert.deepEqual(ids(gets[0].options.allowCredentials), credentials.map((c) => c.credential_id));
  for (const later of gets.slice(1)) {
    assert.deepEqual(ids(later.options.allowCredentials), [credentials[1].credential_id]);
  }
});

test("a failed put stops before the registration", async () => {
  const faults = [
    [
      "a receipt over other bytes",
      (api) => {
        api.putReceipt = (text, response) => mintReceipt("secret.put", `${text} `, response);
      },
      NOT_CONFIRMED,
    ],
    [
      "a receipt for another name",
      (api) => {
        api.putReceipt = (text, response) =>
          mintReceipt("secret.put", text, { ...response, name: "db_password" });
      },
      NOT_CONFIRMED,
    ],
    [
      "a 400",
      (api) => {
        api.reply.put = () => ({ status: 400, body: { error: { code: "malformed", message: "x" } } });
      },
      "The KMS refused this request (malformed).",
    ],
    [
      "a 503",
      (api) => {
        api.reply.put = () => ({
          status: 503,
          body: { error: "down", error_code: "SHROUD_SERVICE_UNAVAILABLE" },
        });
      },
      "The service is unavailable. Try again in a minute.",
    ],
  ];
  for (const [name, fault, sentence] of faults) {
    const { api, page } = await secretPage();
    const original = api.putReceipt;
    fault(api);
    // The failed step is offered again as soon as it fails; two seconds later its issued_at is new.
    const putRoute = Object.keys(api.routes).find((k) => k.startsWith("PUT "));
    const relay = api.routes[putRoute];
    api.routes[putRoute] = (req) => {
      page.clock.now += 2000;
      return relay(req);
    };
    fill(page, SECRET_VALUES);
    await page.click("Approve with passkey");
    assert.ok(page.text().includes(sentence), `${name}: ${page.text()}`);
    assert.ok(!page.text().includes(APPROVED), name);
    assert.equal(api.revisions.length, 0, name);
    assert.deepEqual(page.buttons(), ["Approve with passkey", "Decline"], name);

    api.putReceipt = original;
    delete api.reply.put;
    await page.click("Approve with passkey");
    const tries = api.puts.filter((p) => p.declared === "db_password");
    assert.equal(tries.length, 2, name);
    assert.notEqual(tries[0].body.payload.issued_at, tries[1].body.payload.issued_at, name);
    await page.click("Sign 2 of 3");
    await page.click("Sign 3 of 3");
    assert.ok(page.text().includes(APPROVED), name);
  }

  const { api, page } = await secretPage();
  fill(page, SECRET_VALUES);
  await page.click("Approve with passkey");
  api.reply.put = () => ({ status: 400, body: { error: { code: "signature_invalid", message: "" } } });
  await page.click("Sign 2 of 3");
  assert.equal(api.revisions.length, 0);
  assert.ok(page.buttons().includes("Sign 2 of 3"));
  delete api.reply.put;
  await page.click("Sign 2 of 3");
  await page.click("Sign 3 of 3");
  assert.equal(api.puts.filter((p) => p.declared === "db_password").length, 1);
  assert.equal(api.puts.filter((p) => p.declared === "session_key").length, 2);
  assert.ok(page.text().includes(APPROVED));
});

test("secret values are never echoed or stored", async () => {
  const session = memoryStorage();
  const local = memoryStorage();
  const { page } = await secretPage({}, { sessionStorage: session, localStorage: local });
  const inputs = Object.keys(SECRET_VALUES).map((n) => field(page, n));
  fill(page, SECRET_VALUES);
  await approveAll(page);
  assert.ok(page.text().includes(APPROVED));
  for (const input of inputs) assert.equal(input.value, "");
  const haystacks = [
    ...page.fetches.map((f) => `${f.url}\n${f.body || ""}`),
    JSON.stringify([...session.data]),
    JSON.stringify([...local.data]),
    JSON.stringify(page.consoleCalls),
    page.text(),
  ];
  for (const value of Object.values(SECRET_VALUES)) {
    for (const form of [value, b64u(Buffer.from(value)), Buffer.from(value).toString("base64")]) {
      for (const h of haystacks) assert.ok(!h.includes(form), `${form} leaked`);
    }
  }
  assert.deepEqual(page.consoleCalls, []);
});

test("a re-approval keeps current values unless replaced", async () => {
  const current = currentWithDbPassword();
  const kept = await secretPage({ current });
  const choice = keepChoice(kept.page, "db_password");
  assert.ok(choice, kept.page.text());
  assert.equal(choice.value, "keep");
  assert.ok(kept.page.text().includes("Keep the current value"));
  assert.equal(keepChoice(kept.page, "session_key"), undefined);

  await kept.page.click("Approve with passkey");
  assert.ok(kept.page.text().includes("Enter a value for every secret."));
  assert.equal(kept.laptop.log.length, 0);

  fill(kept.page, { session_key: SECRET_VALUES.session_key });
  await kept.page.click("Approve with passkey");
  await kept.page.click("Sign 2 of 2");
  assert.ok(kept.page.text().includes(APPROVED), kept.page.text());
  assert.deepEqual(
    kept.api.puts.map((p) => p.declared),
    ["session_key"],
  );

  const replaced = await secretPage({ current });
  keepChoice(replaced.page, "db_password").value = "replace";
  fill(replaced.page, { session_key: SECRET_VALUES.session_key });
  await replaced.page.click("Approve with passkey");
  assert.ok(replaced.page.text().includes("Enter a value for every secret."));
  assert.equal(replaced.laptop.log.length, 0);
  assert.equal(field(replaced.page, "session_key").value, SECRET_VALUES.session_key);
  fill(replaced.page, { db_password: SECRET_VALUES.db_password });
  await approveAll(replaced.page);
  assert.ok(replaced.page.text().includes(APPROVED));
  assert.deepEqual(
    replaced.api.puts.map((p) => p.declared),
    ["db_password", "session_key"],
  );
});

test("relay calls are paced and a 429 is retried once", async () => {
  const { page } = await secretPage();
  fill(page, SECRET_VALUES);
  await approveAll(page);
  const calls = page.fetches.filter((f) => f.url.includes("/v1/"));
  assert.ok(calls.length >= 6);
  for (let i = 1; i < calls.length; i += 1) {
    assert.ok(calls[i].time - calls[i - 1].time >= 250, `${calls[i - 1].url} then ${calls[i].url}`);
  }

  const limited = await secretPage();
  let first = true;
  limited.api.reply.put = () => {
    if (!first) return null;
    first = false;
    return {
      status: 429,
      body: { error: "slow down", error_code: "SHROUD_RATE_LIMITED" },
      headers: { "Retry-After": "2" },
    };
  };
  fill(limited.page, SECRET_VALUES);
  await approveAll(limited.page);
  assert.ok(limited.page.text().includes(APPROVED));
  const tries = limited.api.puts.filter((p) => p.declared === "db_password");
  assert.equal(tries.length, 2);
  assert.equal(tries[0].text, tries[1].text);
  assert.ok(limited.page.timers.includes(2000));
});
