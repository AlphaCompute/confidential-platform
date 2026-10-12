"use strict";

// S5 (PRD-03, draft): the read-only approval view a portal may frame, /sign/embed#<ticket>.

const test = require("node:test");
const assert = require("node:assert/strict");
const { TICKET, approvalApi, loadPage, testView, testdata } = require("./harness.js");

const PORTAL = "https://console.rafay.example";
const ORIGIN = testView().view.signer.origins[0];
const FRAMED = "This page cannot run inside another page. Open the link in its own tab.";
const NOT_VERIFIED = "The platform document did not verify. Do not continue; contact AlphaCompute.";
const DISABLED =
  "This approval cannot be shown inside another page. Open the approval link in its own tab.";
const NOT_FRAMED = "This view is shown inside your portal. Open the approval link instead.";
const ANCESTOR =
  "This page is not allowed to show this approval. Open the approval link in its own tab.";
const DECIDED = "This request was already approved, declined or cancelled.";

function embedView(ancestors = [PORTAL]) {
  const { view } = testView();
  view.signer.embed_ancestors = ancestors;
  return { view, viewText: JSON.stringify(view) };
}

async function embedPage(pageOptions = {}, apiOptions = {}) {
  const api = approvalApi({
    app_id: "01920000-0000-7000-8000-0000000000aa",
    compose: "{}",
    credentials: [{ credential_id: "a", key_id: "b" }],
    ...apiOptions,
  });
  const page = await loadPage({
    routes: api.routes,
    path: "/sign/embed",
    framed: true,
    ancestorOrigins: [PORTAL],
    ...pageOptions,
  });
  return { page, api };
}

test("only the embed view may run framed, and it asks for no passkey", async () => {
  const platform = testdata("channel/platform-document.json");
  for (const [path, want] of [
    ["/sign/approve", FRAMED],
    ["/sign/claim", FRAMED],
    // Past the frame check to the platform check: this one serves no platform document.
    ["/sign/embed", NOT_VERIFIED],
  ]) {
    const page = await loadPage({ path, framed: true, noPasskeys: true, platform: path === "/sign/embed" ? null : platform });
    await page.boot();
    assert.equal(page.text(), want, path);
  }
});

test("the view shows the waiting launch and opens the approval page in its own window", async () => {
  const { page, api } = await embedPage();
  await page.startEmbed(TICKET, embedView());
  const text = page.text();
  assert.match(text, /Launch approval for Acme/);
  assert.match(text, new RegExp(api.app_id));
  assert.match(text, new RegExp(api.compose_hash.slice("sha256:".length)));
  assert.deepEqual(page.buttons(), ["Review and approve"]);
  const before = page.fetches.length;
  await page.click("Review and approve");
  assert.equal(page.opened.length, 1);
  assert.deepEqual(page.opened[0].args, [`${ORIGIN}/sign/approve#${TICKET}`, "_blank", "noopener"]);
  // It neither signs, nor declines, nor asks for a passkey; the click only opened the window.
  assert.equal(page.fetches.length, before);
  assert.deepEqual(page.prompts, []);
  assert.deepEqual(page.buttons(), ["Check again"]);

  // Approved in the other window: checking again shows the request decided.
  api.state = "approved";
  await page.click("Check again");
  assert.equal(page.text(), DECIDED);
  assert.ok(page.fetches.every((f) => f.method === "GET"), "the view only reads");
});

test("the view refuses unless the platform document lets this portal frame it", async () => {
  for (const [name, ancestors, options, want] of [
    ["no embed_ancestors", [], {}, DISABLED],
    ["opened top-level", [PORTAL], { framed: false }, NOT_FRAMED],
    ["another portal", ["https://other.example"], {}, ANCESTOR],
    ["a page around the portal", [PORTAL], { ancestorOrigins: [PORTAL, "https://evil.example"] }, ANCESTOR],
    ["no ancestors listed", [PORTAL], { ancestorOrigins: [] }, ANCESTOR],
  ]) {
    const { page } = await embedPage(options);
    await page.startEmbed(TICKET, embedView(ancestors));
    assert.equal(page.text(), want, name);
    assert.deepEqual(page.fetches.filter((f) => f.url.includes("/v1/")), [], name);
    assert.deepEqual(page.opened, [], name);
  }
});

// Firefox has no location.ancestorOrigins: the host's frame-ancestors is then the only check
// (QUESTION(PRD-03 Q17)), and the view runs.
test("without ancestorOrigins the view relies on frame-ancestors", async () => {
  const { page } = await embedPage({ ancestorOrigins: undefined });
  await page.startEmbed(TICKET, embedView());
  assert.deepEqual(page.buttons(), ["Review and approve"]);
});

test("a decided or expired request is not offered", async () => {
  for (const state of ["approved", "cancelled", "expired"]) {
    const { page } = await embedPage({}, { state });
    await page.startEmbed(TICKET, embedView());
    assert.deepEqual(page.buttons(), [], state);
    assert.deepEqual(page.opened, [], state);
  }
});
