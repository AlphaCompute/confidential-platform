"use strict";

const WASM_URL = "@WASM_URL@";
const WASM_SRI = "@WASM_SRI@";
const WASM_SHA256 = "@WASM_SHA256@";
const REVISION = "@REVISION@";
const PLATFORM_URL = "@PLATFORM_URL@";

const VERSION_KEY = "alphacompute-verify-platform-version";
const BINDING_PATH = "/.well-known/alphacompute/binding";
const ATTESTATION_PATH = "/.well-known/alphacompute/attestation";
const CT_URL = "https://api.certspotter.com/v1/issuances";
const CT_PAGES = 10;
const NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

const LABELS = {
  platform_document: "Platform document",
  tdx_quote: "Intel TDX quote",
  instance_key: "Key held by the TD",
  measurements: "Measured boot",
  init_data: "Revision and agent policy",
  binding: "Certificate bound to the TD",
  certificate_transparency: "Every certificate for the name",
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function storedVersion() {
  try {
    return Number(localStorage.getItem(VERSION_KEY)) || 0;
  } catch {
    return 0;
  }
}

function storeVersion(version) {
  try {
    localStorage.setItem(VERSION_KEY, String(version));
  } catch {}
}

async function get(url) {
  const reply = await fetch(url, { cache: "no-store", credentials: "omit", redirect: "error" });
  if (!reply.ok) throw new Error(`HTTP ${reply.status}`);
  return reply.text();
}

async function issuances(name) {
  const all = [];
  let after = "";
  for (let page = 0; page < CT_PAGES; page++) {
    const query = new URLSearchParams({ domain: name, match_wildcards: "true", expand: "dns_names" });
    if (after) query.set("after", after);
    const list = JSON.parse(await get(`${CT_URL}?${query}`));
    if (!Array.isArray(list)) throw new Error("not a list");
    if (list.length === 0) return JSON.stringify(all);
    all.push(...list);
    after = list[list.length - 1].id;
  }
  throw new Error(`more than ${CT_PAGES} pages`);
}

function fact(list, term, value) {
  if (value === undefined || value === null || value === "") return;
  list.append(el("dt", "", term), el("dd", "mono", String(value)));
}

function images(initData) {
  try {
    return Object.entries(JSON.parse(wasm_bindgen.composeServices(initData)))
      .map(([name, service]) => `${name}: ${service.image}`)
      .join("\n");
  } catch {
    return "";
  }
}

function render(root, name, report, fetched) {
  const verdict = el("section", report.verified ? "verdict ok" : "verdict bad");
  verdict.append(
    el("h1", "", report.verified ? `${name} is verified` : `${name} is not verified`),
    el(
      "p",
      "",
      report.verified
        ? "It runs the Revision below in an Intel TDX confidential VM, and every certificate a browser accepts for the name is held inside it."
        : "At least one check below failed. Do not rely on this App's confidentiality.",
    ),
  );

  const facts = el("dl", "facts");
  fact(facts, "App", report.app_id);
  fact(facts, "Revision", report.revision);
  fact(facts, "Containers", report.init_data ? images(report.init_data) : "");
  fact(facts, "Runtime class", report.runtime_class);
  fact(facts, "TCB status", report.tcb_status);
  fact(facts, "Advisories", report.advisories.join(", "));
  fact(facts, "Platform document", report.platform_document_version);
  fact(facts, "Served key", report.served_spki_sha256);

  const checks = el("ol", "checks");
  for (const check of report.checks) {
    const item = el("li", check.ok ? "ok" : "bad");
    item.append(el("span", "mark", check.ok ? "✓" : "✗"), el("strong", "", LABELS[check.name] || check.name));
    item.append(el("p", "detail", check.detail));
    checks.append(item);
  }

  const notes = el("ul", "notes");
  for (const [what, error] of fetched) notes.append(el("li", "", `Could not read ${what}: ${error}`));

  const about = el("details", "about");
  about.append(
    el("summary", "", "What this page checks and trusts"),
    el(
      "p",
      "",
      "This page talks to no AlphaCompute server. It reads the App's evidence from the App itself, the platform document from GitHub, and certificates from Cert Spotter's Certificate Transparency index. It checks the quote against Intel's root, the measurements against the platform document signed by the release keys built into this page, and the binding with the key the quote attests. The KMS's certificate is not consulted.",
    ),
    el(
      "p",
      "",
      "A page cannot see the certificate of its own connection. Another valid certificate for the name could let its holder serve the name from elsewhere, so every current certificate in Certificate Transparency must hold the key the TD signed for. Cert Spotter is trusted to list them all; browsers accept only logged certificates.",
    ),
    el("p", "mono", `Built from ${REVISION}; wasm sha256:${WASM_SHA256}`),
  );

  root.replaceChildren(verdict, facts, checks, notes, about);
}

async function main() {
  const root = document.getElementById("main");
  const name = (new URLSearchParams(location.search).get("name") || "").trim().toLowerCase();
  if (!NAME.test(name)) {
    return root.replaceChildren(el("p", "", "Open this page with ?name=<the App's public name>."));
  }
  root.replaceChildren(el("p", "muted", `Checking ${name}…`));

  await wasm_bindgen({ module_or_path: fetch(WASM_URL, { integrity: WASM_SRI }) });
  const sources = [
    ["the App's binding", get(`https://${name}${BINDING_PATH}`)],
    ["the App's evidence", get(`https://${name}${ATTESTATION_PATH}`)],
    ["the platform document", get(PLATFORM_URL)],
    ["Certificate Transparency", issuances(name)],
  ];
  const settled = await Promise.allSettled(sources.map(([, promise]) => promise));
  const value = (i) => (settled[i].status === "fulfilled" ? settled[i].value : undefined);
  const fetched = settled
    .map((result, i) => [sources[i][0], result.reason && result.reason.message])
    .filter(([, error]) => error);

  const report = JSON.parse(
    wasm_bindgen.verifyPublicName(
      name,
      value(0) || "",
      value(1) || "",
      value(2) || "",
      value(3),
      storedVersion(),
      Date.now(),
    ),
  );
  if (report.checks[0].ok) storeVersion(report.platform_document_version);
  render(root, name, report, fetched);
}

main().catch((e) => {
  document.getElementById("main").replaceChildren(el("p", "verdict bad", `The check could not run: ${e.message}`));
});
