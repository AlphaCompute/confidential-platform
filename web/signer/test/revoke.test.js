"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  FOREIGN_LEAF,
  NOT_CONFIRMED,
  SoftwareAuthenticator,
  contextDigest,
  ids,
  iso,
  loadPage,
  mintReceipt,
  revocationApi,
} = require("./harness.js");

const REVOKED = "Revoked. You can close this tab.";
const EFFECT =
  "Revoking stops the KMS from giving these launches keys, Secrets or certificates: no copy can start, and a running copy gets none again. It cannot be undone; the same launch can never be approved again.";
const RECEIPT_TIME = "2026-06-01T00:00:00Z";

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

async function revocationPage(apiOptions = {}, pageOptions = {}) {
  const { laptop, credentials } = organization();
  const api = revocationApi({ credentials, ...apiOptions });
  const page = await loadPage({
    routes: api.routes,
    authenticator: laptop,
    path: "/sign/revoke",
    ...pageOptions,
  });
  await page.startRevocation();
  return { api, page, laptop, credentials };
}

test("every Revision is revoked with its own touch, and only receipts make it revoked", async () => {
  const { api, page, laptop, credentials } = await revocationPage();
  const [first, second] = api.revisions;
  const text = page.text();
  for (const line of [
    "Revocation for Acme",
    "Production",
    EFFECT,
    `App: ${api.app_id}`,
    `To revoke: ${first}`,
    `To revoke: ${second}`,
  ]) {
    assert.ok(text.includes(line), `${line}\n${text}`);
  }
  assert.deepEqual(page.buttons(), ["Revoke with passkey"]);

  await page.click("Revoke with passkey");
  assert.equal(api.revokes.length, 1);
  const sent = api.revokes[0];
  const payload = sent.body.payload;
  assert.deepEqual(Object.keys(payload).sort(), ["compose_hash", "issued_at"]);
  assert.equal(payload.compose_hash, first);
  assert.ok(Math.abs(Date.parse(payload.issued_at) - Date.now()) < 60000, payload.issued_at);
  const got = laptop.log[0];
  assert.deepEqual(ids(got.options.allowCredentials), credentials.map((c) => c.credential_id));
  const wasm = page.wasm();
  assert.deepEqual(
    Buffer.from(got.options.challenge),
    contextDigest("alphacompute/control/v1", wasm.canonicalJson(JSON.stringify(payload))),
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
  assert.equal(sent.text, expected);
  assert.ok(page.text().includes(`Revoked at ${RECEIPT_TIME}: ${first}`), page.text());
  assert.ok(page.text().includes(`To revoke: ${second}`), page.text());
  assert.ok(!page.text().includes(REVOKED));

  await page.click("Sign 2 of 2");
  assert.deepEqual(ids(laptop.log[1].options.allowCredentials), [credentials[1].credential_id]);
  assert.deepEqual(api.revokes.map((r) => r.body.payload.compose_hash), [first, second]);
  assert.ok(page.text().includes(`Revoked at ${RECEIPT_TIME}: ${second}`), page.text());
  assert.ok(page.text().includes(REVOKED), page.text());
  assert.deepEqual(page.buttons(), []);
  // Each click's first await is its prompt, so the browser still sees the gesture.
  assert.deepEqual(page.prompts.map((p) => p.fetches - p.click), [0, 0]);
});

test("a revoke receipt that does not verify never reads revoked; the step is signed again", async () => {
  const faults = {
    "other bytes": (text, response) => mintReceipt("revision.revoke", `${text} `, response),
    "another route": (text, response) => mintReceipt("revision.register", text, response),
    "another Revision": (text, response) =>
      mintReceipt("revision.revoke", text, {
        ...response,
        compose_hash: `sha256:${"0".repeat(64)}`,
      }),
    "no time": (text, response) =>
      mintReceipt("revision.revoke", text, { compose_hash: response.compose_hash }),
    "another CA": (text, response) =>
      mintReceipt("revision.revoke", text, response, { leaf: FOREIGN_LEAF }),
  };
  for (const [name, fault] of Object.entries(faults)) {
    const { api, page } = await revocationPage();
    const honest = api.revokeReceipt;
    api.revokeReceipt = fault;
    await page.click("Revoke with passkey");
    assert.ok(page.text().includes(NOT_CONFIRMED), `${name}: ${page.text()}`);
    assert.ok(page.text().includes(`To revoke: ${api.revisions[0]}`), name);
    assert.ok(!page.text().includes("Revoked at"), name);
    api.revokeReceipt = honest;
    await page.click("Revoke with passkey");
    assert.equal(api.revokes.length, 2, name);
    assert.notEqual(api.revokes[0].text, api.revokes[1].text, `${name}: a fresh signature`);
    assert.deepEqual(page.buttons(), ["Sign 2 of 2"], name);
  }
});

test("every refusal is one fixed sentence", async () => {
  const now = Date.now();
  const EXPIRED = "This revocation link has expired.";
  const UNAVAILABLE = "The service is unavailable. Try again in a minute.";
  const hash = `sha256:${"ab".repeat(32)}`;
  const read = [
    [{ state: "expired" }, EXPIRED],
    [{ expires_at: iso(now - 1000) }, EXPIRED],
    [{ state: "revoked" }, "This link is not valid."],
    [{ read: { status: 404, body: { error: "x", error_code: "SHROUD_NOT_FOUND" } } }, "This link is not valid."],
    [{ read: { status: 503, body: { error: "x", error_code: "SHROUD_SERVICE_UNAVAILABLE" } } }, UNAVAILABLE],
    [{ revisions: [] }, UNAVAILABLE],
    [{ revisions: [hash, hash] }, UNAVAILABLE],
    [{ revisions: [hash.toUpperCase()] }, UNAVAILABLE],
    [{ revisions: hash }, UNAVAILABLE],
    [
      { server_time: iso(now + 7 * 60 * 1000) },
      "Your device clock is off by about 7 minutes. Correct it and reload.",
    ],
  ];
  for (const [options, sentence] of read) {
    const { page, laptop } = await revocationPage({ now, ...options }, { now });
    assert.equal(page.text(), sentence, JSON.stringify(options));
    assert.equal(laptop.log.length, 0);
  }
  const { page: none } = await revocationPage({ credentials: [] });
  assert.equal(none.text(), "No passkey of this organization is known. Ask your AlphaCompute contact.");

  const kms = [
    [
      { status: 400, body: { error: { code: "signature_invalid", message: "<b>bad</b>" } } },
      "The KMS did not accept the passkey's signature. Nothing was changed.",
    ],
    [
      { status: 404, body: { error: { code: "not_found", message: "<i>no such revision</i>" } } },
      "The KMS refused this request (not_found).",
    ],
    [
      { status: 409, body: { error: "x", error_code: "SHROUD_CONFLICT", details: { state: "expired" } } },
      EXPIRED,
    ],
    [{ status: 400, body: { error: "<img src=x onerror=alert(1)>", error_code: "<b>x</b>" } }, UNAVAILABLE],
    [new Error("network"), UNAVAILABLE],
  ];
  for (const [reply, sentence] of kms) {
    const { api, page } = await revocationPage();
    api.reply = () => reply;
    await page.click("Revoke with passkey");
    const text = page.text();
    assert.ok(text.includes(sentence), `${sentence}\n${text}`);
    assert.ok(!text.includes("Revoked at") && !text.includes(REVOKED), text);
    for (const markup of ["<b>", "<i>", "<img"]) {
      assert.ok(!text.includes(markup), `${markup} in ${text}`);
    }
    assert.deepEqual(page.buttons(), ["Revoke with passkey"]);
  }
});

test("a closed passkey prompt sends nothing", async () => {
  const { api, page, laptop } = await revocationPage();
  laptop.prefer = undefined;
  laptop.credentials = [];
  await page.click("Revoke with passkey");
  assert.ok(page.text().includes("The passkey prompt was closed. Try again."), page.text());
  assert.equal(api.revokes.length, 0);
});
