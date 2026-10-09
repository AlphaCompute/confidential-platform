"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  FOREIGN_LEAF,
  RP_ID,
  SoftwareAuthenticator,
  b64u,
  claimApi,
  contextDigest,
  iso,
  loadPage,
  mintReceipt,
  sha256,
} = require("./harness.js");

const YOURS = "This organization is yours.";
const NOT_CONFIRMED = "Not confirmed by the KMS.";
const SYNCED = "Synced passkey (backed up by your provider)";

async function claimPage(apiOptions = {}, pageOptions = {}) {
  const api = claimApi(apiOptions);
  const page = await loadPage({ routes: api.routes, ...pageOptions });
  await page.startClaim();
  return { api, page };
}

// Values made inside the page's context have that context's prototypes.
const plain = (value) => JSON.parse(JSON.stringify(value));

function grouped(spkiB64) {
  const hex = sha256(Buffer.from(spkiB64, "base64url")).toString("hex");
  return `sha256:${hex.match(/.{4}/g).join(" ")}`;
}

test("a root claim registers the first passkey and says the organization is yours only after the receipt verifies", async () => {
  const earlier = new SoftwareAuthenticator().enroll();
  const { api, page } = await claimPage({
    credentials: [{ credential_id: earlier.id, key_id: "01920000-0000-7000-8000-0000000000aa" }],
  });
  const text = page.text();
  assert.match(text, /Acme/);
  assert.match(text, /Claim this organization/);
  assert.ok(text.includes(api.expires_at));
  assert.equal(api.reveals, 0);

  await page.click("Create passkey");
  const created = page.authenticator.log[0];
  assert.equal(created.kind, "create");
  const o = created.options;
  assert.deepEqual(plain(o.rp), { id: RP_ID, name: "AlphaCompute" });
  assert.equal(o.user.id.length, 32);
  assert.equal(o.user.name, "Acme · AlphaCompute");
  assert.equal(o.user.displayName, "Acme · AlphaCompute");
  assert.deepEqual(plain(o.pubKeyCredParams), [{ type: "public-key", alg: -7 }]);
  assert.deepEqual(plain(o.authenticatorSelection), {
    residentKey: "required",
    requireResidentKey: true,
    userVerification: "required",
  });
  assert.equal(o.attestation, "none");
  assert.deepEqual(plain(o.extensions), { credProps: true });
  assert.deepEqual(
    plain(o.excludeCredentials.map((c) => [c.type, b64u(Buffer.from(c.id))])),
    [["public-key", earlier.id]],
  );
  assert.equal(api.reveals, 1);
  assert.ok(!page.text().includes(YOURS));

  await page.click("Confirm with passkey");
  const got = page.authenticator.log[1];
  assert.equal(got.kind, "get");
  const key = created.result;
  assert.deepEqual(
    plain(got.options.allowCredentials.map((c) => b64u(Buffer.from(c.id)))),
    [key.id],
  );
  assert.equal(got.options.rpId, RP_ID);
  assert.equal(got.options.userVerification, "required");

  assert.equal(api.registrations.length, 1);
  const sent = api.registrations[0];
  assert.equal(sent.credentialId, key.id);
  const issuedAt = sent.registration.payload.issued_at;
  assert.match(issuedAt, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  const payload = {
    org_id: api.org_id,
    principal_id: api.principal_id,
    public_key: key.spki,
    label: "passkey-1",
    issued_at: issuedAt,
  };
  const wasm = page.wasm();
  const assertion = got.result;
  const expected = wasm.canonicalJson(
    JSON.stringify({
      payload,
      signature: {
        algorithm: "webauthn-es256",
        signature: assertion.signature,
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
      },
    }),
  );
  assert.equal(sent.registrationText, expected);
  assert.equal(sent.body, `{"credential_id":${JSON.stringify(key.id)},"registration":${expected}}`);
  assert.ok(!("key_id" in sent.registration.signature));
  const digest = contextDigest(
    "alphacompute/org-root-key/v1",
    wasm.canonicalJson(JSON.stringify(payload)),
  );
  assert.deepEqual(Buffer.from(got.options.challenge), digest);

  const done = page.text();
  assert.ok(done.includes(YOURS), done);
  assert.ok(done.includes(grouped(key.spki)), done);
  assert.ok(done.includes(SYNCED), done);
});

test("a receipt that does not verify reads not confirmed", async () => {
  const faults = {
    "other bytes": (text, response) => mintReceipt("key.register", `${text} `, response),
    "another route": (text, response) => mintReceipt("secret.put", text, response),
    "another organization": (text, response) =>
      mintReceipt("key.register", text, { ...response, org_id: "01920000-0000-7000-8000-0000000000ff" }),
    "another key": (text, response) =>
      mintReceipt("key.register", text, { ...response, public_key: "AAAA" }),
    "a key outside the CA": (text, response) =>
      mintReceipt("key.register", text, response, { leaf: FOREIGN_LEAF }),
    "a signature by another key": (text, response) =>
      mintReceipt("key.register", text, response, {
        key: crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey,
      }),
    "no receipt": () => undefined,
  };
  for (const [name, fault] of Object.entries(faults)) {
    const api = claimApi();
    api.receiptFor = fault;
    const page = await loadPage({ routes: api.routes });
    await page.startClaim();
    await page.click("Create passkey");
    await page.click("Confirm with passkey");
    const text = page.text();
    assert.ok(text.includes(NOT_CONFIRMED), `${name}: ${text}`);
    assert.ok(!text.includes(YOURS), name);
  }
  const api = claimApi();
  api.keysReply = () => ({
    status: 502,
    body: { error: "<b>upstream</b>", error_code: "SHROUD_UPSTREAM_INVALID" },
  });
  const page = await loadPage({ routes: api.routes });
  await page.startClaim();
  await page.click("Create passkey");
  await page.click("Confirm with passkey");
  assert.ok(page.text().includes(NOT_CONFIRMED));
  assert.ok(!page.text().includes("upstream"));
  assert.ok(!page.text().includes(YOURS));
});

test("a cancelled or refused passkey prompt spends nothing", async () => {
  const cases = [
    [{ create: "NotAllowedError" }, "The passkey prompt was closed. Try again."],
    [
      { create: "InvalidStateError" },
      "This device already holds a passkey for this organization; use another device or provider.",
    ],
    [{ publicKey: null }, "This passkey cannot be used"],
    [{ algorithm: -8 }, "This passkey cannot be used"],
    [{ publicKey: "raw" }, "This passkey cannot be used"],
  ];
  for (const [fault, sentence] of cases) {
    const { api, page } = await claimPage();
    page.authenticator.fault = { ...fault };
    await page.click("Create passkey");
    assert.ok(page.text().includes(sentence), `${JSON.stringify(fault)}: ${page.text()}`);
    assert.equal(api.reveals, 0);
    assert.ok(page.buttons().includes("Create passkey"));
    assert.ok(page.find((n) => n.tagName === "BUTTON" && n.textContent === "Create passkey" && !n.disabled));
  }
});

test("a clock off by more than four minutes is refused before any prompt", async () => {
  const now = Date.now();
  const { page } = await claimPage({ server_time: iso(now + 5 * 60 * 1000) }, { now });
  assert.ok(
    page.text().includes("Your device clock is off by about 5 minutes. Correct it and reload."),
    page.text(),
  );
  assert.deepEqual(page.buttons(), []);
  assert.equal(page.authenticator.log.length, 0);

  const near = await claimPage({ server_time: iso(now - 3 * 60 * 1000) }, { now });
  assert.ok(near.page.buttons().includes("Create passkey"), near.page.text());
});

test("a closed, expired or unknown claim is refused", async () => {
  const now = Date.now();
  const cases = [
    [{ state: "closed" }, "This claim link is closed. Ask your AlphaCompute contact for a new link."],
    [{ state: "expired" }, "This claim link has expired. Ask your AlphaCompute contact for a new link."],
    [{ expires_at: iso(now - 1000) }, "This claim link has expired. Ask your AlphaCompute contact for a new link."],
    [{ keys_left: 0 }, "This claim link is closed. Ask your AlphaCompute contact for a new link."],
    [
      { read: { status: 404, body: { error: "claim not found", error_code: "SHROUD_NOT_FOUND" } } },
      "This link is not valid.",
    ],
    [
      { read: { status: 503, body: { error: "x", error_code: "SHROUD_SERVICE_UNAVAILABLE" } } },
      "The service is unavailable. Try again in a minute.",
    ],
  ];
  for (const [apiOptions, sentence] of cases) {
    const { page } = await claimPage({ now, ...apiOptions }, { now });
    assert.equal(page.text(), sentence, JSON.stringify(apiOptions));
    assert.deepEqual(page.buttons(), []);
  }
});

test("no network call happens between a click and its passkey prompt", async () => {
  const { page } = await claimPage();
  await page.click("Create passkey");
  await page.click("Confirm with passkey");
  assert.ok(page.text().includes(YOURS));
  assert.equal(page.prompts.length, 2);
  for (const prompt of page.prompts) assert.equal(prompt.fetches, prompt.click);
});
