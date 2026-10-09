"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  FOREIGN_LEAF,
  NOT_CONFIRMED,
  RP_ID,
  SoftwareAuthenticator,
  b64u,
  claimApi,
  contextDigest,
  iso,
  loadPage,
  memoryStorage,
  mintReceipt,
  ids,
  plain,
  sha256,
} = require("./harness.js");

const YOURS = "This organization is yours.";
const SYNCED = "Synced passkey (backed up by your provider)";

async function claimPage(apiOptions = {}, pageOptions = {}) {
  const api = claimApi(apiOptions);
  const page = await loadPage({ routes: api.routes, ...pageOptions });
  await page.startClaim();
  return { api, page };
}


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
    const { api, page } = await claimPage();
    api.receiptFor = fault;
    await page.click("Create passkey");
    await page.click("Confirm with passkey");
    const text = page.text();
    assert.ok(text.includes(NOT_CONFIRMED), `${name}: ${text}`);
    assert.ok(!text.includes(YOURS), name);
  }
  const { api, page } = await claimPage();
  api.keysReply = () => ({
    status: 502,
    body: { error: "<b>upstream</b>", error_code: "SHROUD_UPSTREAM_INVALID" },
  });
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

test("a claim read that never arrives reads unavailable", async () => {
  const api = claimApi();
  const read = Object.keys(api.routes).find((k) => k.startsWith("GET "));
  api.routes[read] = () => new Error("network");
  const page = await loadPage({ routes: api.routes });
  await page.startClaim();
  assert.equal(page.text(), "The service is unavailable. Try again in a minute.");
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

const SECOND = "Add a second passkey on another device or provider";
const TWO_KEYS = "Done. Your organization has two passkeys.";
const CHECK_FAILED = "This passkey did not sign as expected. Try again.";


// A root claim up to the check step: the first passkey on `page.authenticator`, the second on a
// phone.
async function twoKeys(apiOptions = {}, pageOptions = {}) {
  const { api, page } = await claimPage(apiOptions, pageOptions);
  const laptop = page.authenticator;
  const phone = new SoftwareAuthenticator();
  await page.click("Create passkey");
  await page.click("Confirm with passkey");
  page.use(phone);
  await page.click(SECOND);
  page.use(laptop);
  await page.click("Approve it with your first passkey");
  return { api, page, laptop, phone };
}

test("the second passkey is registered by the first", async () => {
  const { api, page, laptop, phone } = await twoKeys();
  const first = laptop.log[0];
  const second = phone.log[0];
  assert.equal(second.kind, "create");
  assert.deepEqual(ids(second.options.excludeCredentials), [first.result.id]);
  assert.equal(second.options.user.id.length, 32);
  assert.notDeepEqual(Buffer.from(second.options.user.id), Buffer.from(first.options.user.id));

  const approval = laptop.log[laptop.log.length - 1];
  assert.equal(approval.kind, "get");
  assert.deepEqual(ids(approval.options.allowCredentials), [first.result.id]);
  assert.equal(api.registrations.length, 2);
  const sent = api.registrations[1];
  assert.equal(sent.credentialId, second.result.id);
  const payload = {
    principal_id: api.principal_id,
    public_key: second.result.spki,
    label: "passkey-2",
    issued_at: sent.registration.payload.issued_at,
  };
  const wasm = page.wasm();
  const rootKeyId = api.credentials.find((c) => c.credential_id === first.result.id).key_id;
  const assertion = approval.result;
  const expected = wasm.canonicalJson(
    JSON.stringify({
      payload,
      signature: {
        key_id: rootKeyId,
        algorithm: "webauthn-es256",
        signature: assertion.signature,
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
      },
    }),
  );
  assert.equal(sent.registrationText, expected);
  const digest = contextDigest(
    "alphacompute/principal-key/v1",
    wasm.canonicalJson(JSON.stringify(payload)),
  );
  assert.deepEqual(Buffer.from(approval.options.challenge), digest);
  const text = page.text();
  assert.ok(text.includes("Second passkey:"), text);
  assert.ok(text.includes(grouped(second.result.spki)), text);
  assert.deepEqual(page.buttons(), ["Check passkey 1", "Check passkey 2"]);
});

test("done comes only after one assertion from each key verifies locally", async () => {
  const { page, laptop, phone } = await twoKeys();
  laptop.highS = true;
  phone.highS = true;
  await page.click("Check passkey 1");
  assert.ok(!page.text().includes(TWO_KEYS));
  assert.ok(page.text().includes("Check passkey 1: signed as expected."), page.text());
  page.use(phone);
  await page.click("Check passkey 2");
  assert.ok(page.text().includes(TWO_KEYS), page.text());

  const checks = [laptop.log[laptop.log.length - 1], phone.log[phone.log.length - 1]];
  assert.deepEqual(ids(checks[0].options.allowCredentials), [laptop.log[0].result.id]);
  assert.deepEqual(ids(checks[1].options.allowCredentials), [phone.log[0].result.id]);
  const challenges = checks.map((c) => Buffer.from(c.options.challenge));
  assert.equal(challenges[0].length, 32);
  assert.equal(challenges[1].length, 32);
  assert.notDeepEqual(challenges[0], challenges[1]);

  for (const fault of ["tamper", "otherChallenge"]) {
    const again = await twoKeys();
    again.laptop.fault[fault] = true;
    await again.page.click("Check passkey 1");
    assert.ok(again.page.text().includes(CHECK_FAILED), `${fault}: ${again.page.text()}`);
    again.page.use(again.phone);
    await again.page.click("Check passkey 2");
    assert.ok(!again.page.text().includes(TWO_KEYS), fault);
    assert.ok(again.page.buttons().includes("Check passkey 1"), fault);
  }
});

test("skipping the second passkey leaves a permanent warning", async () => {
  const { api, page } = await claimPage();
  await page.click("Create passkey");
  await page.click("Confirm with passkey");
  await page.click("Skip for now");
  const text = page.text();
  assert.ok(
    text.includes(
      `Your organization has one passkey. If you lose it you lose the organization. Your link stays open until ${api.expires_at}.`,
    ),
    text,
  );
  assert.ok(!text.includes("Done."));
  assert.deepEqual(page.buttons(), []);
  assert.equal(api.registrations.length, 1);
});

test("a reload in the same tab resumes and another tab is sent back to the contact", async () => {
  const api = claimApi();
  const tab = memoryStorage();
  const first = await loadPage({ routes: api.routes, sessionStorage: tab });
  await first.startClaim();
  await first.click("Create passkey");
  const confirming = await loadPage({
    routes: api.routes,
    sessionStorage: tab,
    authenticator: first.authenticator,
  });
  await confirming.startClaim();
  assert.deepEqual(confirming.buttons(), ["Confirm with passkey"]);
  await confirming.click("Confirm with passkey");
  assert.equal(api.reveals, 1);
  assert.equal(api.state, "rooted");

  const reloaded = await loadPage({ routes: api.routes, sessionStorage: tab });
  await reloaded.startClaim();
  assert.ok(reloaded.text().includes(YOURS), reloaded.text());
  assert.ok(reloaded.buttons().includes(SECOND));

  const other = await loadPage({ routes: api.routes, sessionStorage: memoryStorage() });
  await other.startClaim();
  assert.equal(
    other.text(),
    "This link was already opened in another tab or on another device. Ask your AlphaCompute contact for a new link.",
  );
});

test("a reload after the last key spent the link still offers the checks", async () => {
  const tab = memoryStorage();
  const { api } = await twoKeys({ keys_left: 2 }, { sessionStorage: tab });
  assert.equal(api.keys_left, 0);
  const reloaded = await loadPage({ routes: api.routes, sessionStorage: tab });
  await reloaded.startClaim();
  assert.deepEqual(reloaded.buttons(), ["Check passkey 1", "Check passkey 2"]);

  const other = await loadPage({ routes: api.routes, sessionStorage: memoryStorage() });
  await other.startClaim();
  assert.equal(
    other.text(),
    "This claim link is closed. Ask your AlphaCompute contact for a new link.",
  );
});

test("an add ticket registers a key signed by an existing passkey", async () => {
  const laptop = new SoftwareAuthenticator();
  const a = laptop.enroll();
  const b = laptop.enroll();
  const keyA = "01920000-0000-7000-8000-00000000000a";
  const keyB = "01920000-0000-7000-8000-00000000000b";
  const api = claimApi({
    kind: "add",
    credentials: [
      { credential_id: a.id, key_id: keyA },
      { credential_id: b.id, key_id: keyB },
    ],
  });
  const phone = new SoftwareAuthenticator();
  const page = await loadPage({ routes: api.routes, authenticator: phone });
  await page.startClaim();
  assert.ok(page.text().includes("Add a passkey to this organization"));
  await page.click("Create passkey");
  const created = phone.log[0];
  assert.deepEqual(ids(created.options.excludeCredentials), [a.id, b.id]);
  assert.equal(api.reveals, 1);

  laptop.prefer = b.id;
  page.use(laptop);
  await page.click("Approve it with a passkey of this organization");
  const approval = laptop.log[0];
  assert.deepEqual(ids(approval.options.allowCredentials), [a.id, b.id]);
  const sent = api.registrations[0];
  assert.equal(sent.credentialId, created.result.id);
  assert.equal(sent.registration.signature.key_id, keyB);
  assert.equal(sent.registration.payload.public_key, created.result.spki);
  assert.equal(sent.registration.payload.principal_id, api.principal_id);
  assert.ok(!("org_id" in sent.registration.payload));
  const digest = contextDigest(
    "alphacompute/principal-key/v1",
    page.wasm().canonicalJson(JSON.stringify(sent.registration.payload)),
  );
  assert.deepEqual(Buffer.from(approval.options.challenge), digest);
  assert.ok(page.text().includes("The new passkey is registered."), page.text());

  page.use(phone);
  await page.click("Check passkey 1");
  assert.ok(page.text().includes("Done. The new passkey signs as expected."), page.text());
});

test("a device-bound passkey is named as such", async () => {
  // 0x0d is eligible for backup but not backed up yet.
  for (const flags of [0x05, 0x0d]) {
    const { page } = await claimPage({}, { authenticator: new SoftwareAuthenticator({ flags }) });
    await page.click("Create passkey");
    await page.click("Confirm with passkey");
    const text = page.text();
    assert.ok(
      text.includes("Device-bound passkey: if you lose this device you lose this key"),
      `${flags}: ${text}`,
    );
    assert.ok(!text.includes(SYNCED), flags);
  }
});
