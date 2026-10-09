"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  SoftwareAuthenticator,
  approvalApi,
  b64u,
  catalogFile,
  contextDigest,
  iso,
  jcs,
  loadPage,
  mintReceipt,
  sha256,
  testView,
  testdata,
} = require("./harness.js");

const APPROVED = "Approved. You can close this tab.";
const NOT_CONFIRMED = "Not confirmed by the KMS.";
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

const plain = (value) => JSON.parse(JSON.stringify(value));
const ids = (list) => plain(list.map((c) => b64u(Buffer.from(c.id))));

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

async function approvalPage(apiOptions = {}, pageOptions = {}) {
  const { laptop, credentials } = organization();
  const api = approvalApi({ app_id: WRAP_APP, credentials, ...apiOptions });
  const page = await loadPage({
    routes: api.routes,
    authenticator: laptop,
    path: "/sign/approve",
    ...pageOptions,
  });
  await page.startApproval();
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
    "Published ports: 443:80",
    "Image: postgres",
    "Named volumes: pgdata, alpha-secrets-db",
    "Named volumes: cachedata",
    "AlphaCompute runtime",
    "Image: ghcr.io/alphacompute/alpha-runtime",
    `Digest: sha256:${"7d".repeat(32)}`,
    "Machine: tdx.medium (chosen by the service, not part of what you sign)",
  ]) {
    assert.ok(text.includes(line), `${line}\n${text}`);
  }
  assert.ok(!text.includes("Receives secrets"));
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

  const { laptop, credentials } = organization();
  const api = approvalApi({
    app_id: CATALOG.app_id,
    compose_hash: CATALOG.compose_hash,
    catalog_template_sha256: VALID_FILE.entry.template_sha256,
    credentials,
  });
  const page = await loadPage({
    routes: api.routes,
    authenticator: laptop,
    catalog: { [`${TEMPLATE_HEX}.json`]: VALID },
  });
  const { view } = testView();
  delete view.catalog_key;
  await page.startApproval(undefined, { view, viewText: JSON.stringify(view) });
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
