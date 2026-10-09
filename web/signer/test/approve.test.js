"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  SoftwareAuthenticator,
  approvalApi,
  b64u,
  contextDigest,
  jcs,
  loadPage,
  mintReceipt,
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
