"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { TICKET, loadPage, memoryStorage, testView, testdata } = require("./harness.js");

// Release-signed, version 11, with no signer: the compiled-in key verifies it.
const PLATFORM = testdata("channel/platform-document.json");
const VERSION_KEY = "alphacompute-platform-version";

const FRAMED = "This page cannot run inside another page. Open the link in its own tab.";
const NO_PASSKEYS =
  "This browser cannot use passkeys. Open this link in Safari, Chrome, Edge or Firefox.";
const NOT_VERIFIED = "The platform document did not verify. Do not continue; contact AlphaCompute.";
const OLDER =
  "This page was given an older platform document than one seen before. Do not continue.";
const NOT_SIGNER = "This page is not served from an AlphaCompute signer address.";
const BAD_LINK = "This link is not valid.";

async function booted(options) {
  const page = await loadPage({ path: "/sign/approve", platform: PLATFORM, ...options });
  await page.boot();
  return page;
}

test("a framed page does nothing", async () => {
  const page = await booted({ framed: true });
  assert.equal(page.text(), FRAMED);
  assert.deepEqual(page.fetches, []);
});

test("a browser without passkeys is told which browsers work", async () => {
  const page = await booted({ noPasskeys: true });
  assert.equal(page.text(), NO_PASSKEYS);
  assert.deepEqual(page.fetches, []);
});

test("a platform document that does not verify stops the page", async () => {
  const changed = PLATFORM.replace('"version": 11', '"version": 12');
  assert.notEqual(changed, PLATFORM);
  assert.equal(changed.length, PLATFORM.length);
  for (const platform of [changed, new Error("unreachable"), null]) {
    const page = await booted({ platform });
    assert.equal(page.text(), NOT_VERIFIED, String(platform).slice(0, 40));
  }
});

test("an older platform document than one seen before is refused", async () => {
  const seen = memoryStorage({ [VERSION_KEY]: "12" });
  const older = await booted({ localStorage: seen });
  assert.equal(older.text(), OLDER);
  assert.equal(seen.getItem(VERSION_KEY), "12");

  for (const stored of [{ [VERSION_KEY]: "11" }, {}]) {
    const storage = memoryStorage(stored);
    const page = await booted({ localStorage: storage });
    assert.equal(page.text(), NOT_SIGNER, JSON.stringify(stored));
    assert.equal(storage.getItem(VERSION_KEY), "11");
  }

  const refusing = {
    getItem() {
      throw new Error("denied");
    },
    setItem() {
      throw new Error("denied");
    },
  };
  const page = await booted({ localStorage: refusing });
  assert.equal(page.text(), NOT_SIGNER);
});

test("a document without a signer or from another origin is refused", async () => {
  const page = await booted({});
  assert.equal(page.text(), NOT_SIGNER);
  assert.ok(page.fetches.some((f) => f.url === "./platform.json"));
  assert.ok(!page.fetches.some((f) => f.url.includes("/v1/")));

  const { view } = testView();
  const here = await loadPage({});
  assert.equal(here.call("servedBySigner", view), true);
  const elsewhere = await loadPage({ origin: "https://elsewhere.test" });
  assert.equal(elsewhere.call("servedBySigner", view), false);
  assert.equal(elsewhere.call("servedBySigner", { ...view, signer: undefined }), false);
});

test("a link with another path or a malformed ticket is not valid", async () => {
  const cases = [
    { path: "/sign/other" },
    { path: "/sign/" },
    { hash: "short" },
    { hash: `${TICKET}A` },
    { hash: `${TICKET.slice(1)}+` },
    { hash: "" },
  ];
  for (const options of cases) {
    const page = await booted(options);
    assert.equal(page.text(), BAD_LINK, JSON.stringify(options));
    assert.ok(!page.fetches.some((f) => f.url === "./platform.json"), JSON.stringify(options));
  }
  const claim = await booted({ path: "/sign/claim" });
  assert.equal(claim.text(), NOT_SIGNER);
});
