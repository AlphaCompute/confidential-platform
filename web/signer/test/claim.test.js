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
  failed,
  iso,
  loadPage,
  memoryStorage,
  mintReceipt,
  ids,
  plain,
  seedOwner,
  sha256,
  testView,
  TICKET,
} = require("./harness.js");

const YOURS = "This organization is yours.";
const SYNCED = "Synced passkey (backed up by your provider)";

// A claim page in a tab that holds the owner's session unless `apiOptions.session` is false.
async function claimPage(apiOptions = {}, pageOptions = {}) {
  const api = claimApi(apiOptions);
  const tab = pageOptions.sessionStorage || memoryStorage();
  if (api.session) seedOwner(tab, api);
  const page = await loadPage({ routes: api.routes, ...pageOptions, sessionStorage: tab });
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
  assert.ok(
    text.includes(`You, owner@acme.example, are making this passkey the root key of Acme (${api.org_id}).`),
    text,
  );

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
  assert.equal(sent.op, "root");
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
  api.keysReply = () => failed(502, "upstream_invalid");
  await page.click("Create passkey");
  await page.click("Confirm with passkey");
  assert.ok(page.text().includes(NOT_CONFIRMED));
  assert.ok(!page.text().includes("<b>"));
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
    assert.equal(api.registrations.length, 0);
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

test("a closed, expired, unknown or keyless claim is refused", async () => {
  const now = Date.now();
  const cases = [
    [{ state: "done" }, "This link was already used, declined or closed."],
    [{ state: "expired" }, "This link has expired."],
    [{ expires_at: iso(now - 1000) }, "This link has expired."],
    [{ read: failed(404, "ticket_not_found") }, "This link is not valid."],
    [{ read: failed(503, "unavailable") }, "The service is unavailable. Try again in a minute."],
    [{ rooted: true }, "No passkey of this organization is known. Ask your AlphaCompute contact."],
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

test("a reload in the same tab resumes, and another tab adds a key only with an existing one", async () => {
  const api = claimApi();
  const tab = seedOwner(memoryStorage(), api);
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
  assert.equal(api.rooted, true);

  const reloaded = await loadPage({ routes: api.routes, sessionStorage: tab });
  await reloaded.startClaim();
  assert.ok(reloaded.text().includes(YOURS), reloaded.text());
  assert.ok(reloaded.buttons().includes(SECOND));

  const other = await loadPage({ routes: api.routes, sessionStorage: memoryStorage() });
  await other.startClaim();
  assert.ok(other.text().includes("Add a passkey to this organization"), other.text());
  await other.click("Create passkey");
  assert.deepEqual(other.buttons(), ["Approve it with a passkey of this organization"]);
});

test("a reload after both keys are registered still offers the checks", async () => {
  const tab = memoryStorage();
  const { api } = await twoKeys({}, { sessionStorage: tab });
  const reloaded = await loadPage({ routes: api.routes, sessionStorage: tab });
  await reloaded.startClaim();
  assert.deepEqual(reloaded.buttons(), ["Check passkey 1", "Check passkey 2"]);
});

test("an add ticket registers a key signed by an existing passkey", async () => {
  const laptop = new SoftwareAuthenticator();
  const a = laptop.enroll();
  const b = laptop.enroll();
  const keyA = "01920000-0000-7000-8000-00000000000a";
  const keyB = "01920000-0000-7000-8000-00000000000b";
  const api = claimApi({
    rooted: true,
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

  laptop.prefer = b.id;
  page.use(laptop);
  await page.click("Approve it with a passkey of this organization");
  const approval = laptop.log[0];
  assert.deepEqual(ids(approval.options.allowCredentials), [a.id, b.id]);
  const sent = api.registrations[0];
  assert.equal(sent.op, "key");
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

test("a root claim makes no passkey until the owner's sign-in is bound to the ticket", async () => {
  const tab = memoryStorage();
  const { api, page } = await claimPage({ session: false }, { sessionStorage: tab });
  const SIGN_IN = "Sign in as owner@acme.example to claim this organization.";
  assert.deepEqual(page.buttons(), [SIGN_IN]);
  await page.click(SIGN_IN);
  assert.equal(page.authenticator.log.length, 0);
  const url = new URL(page.assigned[0]);
  assert.equal(`${url.origin}${url.pathname}`, "https://id.example/authorize");
  const { view } = testView();
  delete view.signer.oidc;
  const unnamed = await loadPage({ routes: api.routes });
  await unnamed.startClaim(undefined, { view, viewText: JSON.stringify(view) });
  assert.equal(unnamed.text(), "The service is unavailable. Try again in a minute.");
  const q = url.searchParams;
  assert.equal(q.get("response_type"), "code");
  assert.equal(q.get("client_id"), "signer");
  assert.equal(q.get("redirect_uri"), "https://signer.test/sign/claim");
  assert.equal(q.get("code_challenge_method"), "S256");
  const key = `alphacompute-oidc-${q.get("state")}`;
  const saved = JSON.parse(tab.getItem(key));
  assert.equal(saved.ticket, TICKET);
  assert.equal(q.get("code_challenge"), b64u(sha256(saved.verifier)));

  const back = async (code) => {
    tab.setItem(key, JSON.stringify(saved));
    const search = `?code=${code}&state=${q.get("state")}`;
    const p = await loadPage({ routes: api.routes, sessionStorage: tab, hash: "", search });
    await p.init();
    await p.call("finishSignIn", testView().view);
    return p;
  };
  const stranger = await back("someone-elses-code");
  assert.ok(stranger.text().includes("That sign-in is not the owner of this organization."), stranger.text());
  assert.deepEqual(stranger.buttons(), [SIGN_IN]);

  const owner = await back(api.owner_code);
  assert.deepEqual(plain(api.sessions[1]), {
    code: api.owner_code,
    code_verifier: saved.verifier,
    redirect_uri: "https://signer.test/sign/claim",
  });
  assert.deepEqual(owner.replaced, [`/sign/claim#${TICKET}`]);
  assert.equal(tab.getItem(key), null);
  assert.deepEqual(owner.buttons(), ["Create passkey"]);

  // Another holder of the ticket, after the owner signed in elsewhere, is still only asked to sign in.
  const other = await loadPage({ routes: api.routes, sessionStorage: memoryStorage() });
  await other.startClaim();
  assert.deepEqual(other.buttons(), [SIGN_IN]);

  await owner.click("Create passkey");
  await owner.click("Confirm with passkey");
  assert.ok(owner.text().includes(YOURS), owner.text());
  const root = owner.fetches.find((f) => f.url.endsWith("/kms/root"));
  assert.equal(root.headers["Alpha-Claim-Session"], api.owner_session);
});

test("a root whose answer was lost is confirmed again, never added as a second key", async () => {
  const api = claimApi();
  const tab = seedOwner(memoryStorage(), api);
  const first = await loadPage({ routes: api.routes, sessionStorage: tab });
  await first.startClaim();
  await first.click("Create passkey");
  const honest = api.receiptFor;
  api.receiptFor = () => undefined;
  await first.click("Confirm with passkey");
  assert.ok(first.text().includes(NOT_CONFIRMED), first.text());
  assert.equal(api.rooted, true);

  api.receiptFor = honest;
  const reloaded = await loadPage({ routes: api.routes, sessionStorage: tab, authenticator: first.authenticator });
  await reloaded.startClaim();
  assert.deepEqual(reloaded.buttons(), ["Confirm with passkey"]);
  await reloaded.click("Confirm with passkey");
  assert.deepEqual(api.registrations.map((r) => r.op), ["root", "root"]);
  assert.ok(reloaded.text().includes(YOURS), reloaded.text());
});

test("a root another key holds stops, and a refused owner session asks to sign in again", async () => {
  const taken = await claimPage();
  taken.api.keysReply = () => failed(409, "already_exists");
  await taken.page.click("Create passkey");
  await taken.page.click("Confirm with passkey");
  assert.equal(
    taken.page.text(),
    "Your organization was claimed by another key. Do not continue. Contact AlphaCompute.",
  );

  const tab = memoryStorage();
  const stale = await claimPage({}, { sessionStorage: tab });
  stale.api.owner_session = "another-session";
  await stale.page.click("Create passkey");
  await stale.page.click("Confirm with passkey");
  assert.ok(stale.page.text().includes("That sign-in is not the owner of this organization."));
  assert.deepEqual(stale.page.buttons(), ["Sign in as owner@acme.example to claim this organization."]);
  assert.ok(!tab.getItem(`alphacompute-claim-sha256:${sha256(TICKET).toString("hex")}`).includes("owner"));
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
