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
const FETCH_MS = 20000;
const NAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

const LABELS = {
  platform_document: "Platform document",
  attestation: "Intel TDX attestation",
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

// Null when the browser keeps no storage for the page; then nothing refuses an older document.
function storedVersion() {
  try {
    return Number(localStorage.getItem(VERSION_KEY)) || 0;
  } catch {
    return null;
  }
}

function storeVersion(version) {
  try {
    localStorage.setItem(VERSION_KEY, String(version));
    return true;
  } catch {
    return false;
  }
}

function asciiName(raw) {
  try {
    return new URL(`https://${raw.trim()}`).hostname;
  } catch {
    return "";
  }
}

async function get(url) {
  const reply = await fetch(url, { cache: "no-store", credentials: "omit", redirect: "error", signal: AbortSignal.timeout(FETCH_MS) });
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
  if (value == null || value === "") return;
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

function render(root, name, report, warnings) {
  const verdict = el("section", report.verified ? "verdict ok" : "verdict bad");
  verdict.append(
    el("h1", "", report.verified ? `${name} is verified` : `${name} is not verified`),
    el(
      "p",
      "",
      !report.verified
        ? "At least one check below failed. Do not rely on this App's confidentiality."
        : report.live
          ? "It runs the Revision below in an Intel TDX confidential VM: the key attested there answered this page's challenge just now, and every certificate for the name in Certificate Transparency holds that key."
          : "Its key was attested in an Intel TDX confidential VM running the Revision below, and every certificate for the name in Certificate Transparency holds that key. It did not answer this page's challenge, so the evidence may come from a TD that has since stopped.",
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
  for (const warning of warnings) notes.append(el("li", "", warning));

  const about = el("details", "about");
  about.append(
    el("summary", "", "What this page checks and trusts"),
    el(
      "p",
      "",
      `This page was served by ${location.origin}. Trust it only as far as you trust that origin: compare the SHA-256 that the command below prints with the bundle_sha256 that the verify-page CI job prints for the commit below, or rebuild that commit with web/verify/build.sh. verify.alphacompute.cc serves this bundle from an attested App whose init-data pins it. Once loaded, it talks to no other AlphaCompute server. It reads the App's evidence from the App itself, the platform document from GitHub, and certificates from Cert Spotter's Certificate Transparency index. It checks the quote against Intel's root, the measurements against the platform document signed by the release keys built into this page, and the binding with the key the quote attests. The KMS's certificate is not consulted.`,
    ),
    el("p", "mono", `curl -s ${location.origin}${location.pathname} | sha256sum`),
    el(
      "p",
      "",
      "A page cannot see the certificate of its own connection. Another valid certificate for the name could let its holder serve the name from elsewhere, so every current certificate in Certificate Transparency must hold the key the TD signed for. Cert Spotter is trusted to list them all. Browsers require CT only for publicly trusted CAs: a certificate from a CA your device trusts locally, such as a corporate proxy's, or from a CA exempt from CT, is not logged, so this check cannot see a proxy that uses one.",
    ),
    el(
      "p",
      "",
      "The App picks the quote's nonce, so the quote shows that the key was attested in a TD, not that the TD is up now. The page sends a random challenge with the binding request; a signature over it by the attested key shows that the TD answered after the page asked. The App also serves Intel's collateral, and collateral still within its validity can predate Intel's newest TCB levels.",
    ),
    el("p", "mono", `Built from ${REVISION}; wasm sha256:${WASM_SHA256}`),
  );

  root.replaceChildren(verdict, facts, checks, notes, about);
}

async function main() {
  const root = document.getElementById("main");
  const name = asciiName(new URLSearchParams(location.search).get("name") || "");
  if (!NAME.test(name)) {
    return root.replaceChildren(el("p", "", "Open this page with ?name=<the App's public name>."));
  }
  root.replaceChildren(el("p", "muted", `Checking ${name}…`));
  const floor = storedVersion();

  await wasm_bindgen({ module_or_path: fetch(WASM_URL, { integrity: WASM_SRI }) });
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const token = btoa(String.fromCharCode(...challenge)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const sources = [
    ["the App's binding", get(`https://${name}${BINDING_PATH}?challenge=${token}`)],
    ["the App's evidence", get(`https://${name}${ATTESTATION_PATH}`)],
    ["the platform document", get(PLATFORM_URL)],
    ["Certificate Transparency", issuances(name)],
  ];
  const settled = await Promise.allSettled(sources.map(([, promise]) => promise));
  const [binding, attestation, platform, ct] = settled.map((r) => r.value);
  const warnings = settled.flatMap((r, i) => (r.status === "rejected" ? [`Could not read ${sources[i][0]}: ${r.reason?.message}`] : []));

  const report = JSON.parse(
    wasm_bindgen.verifyPublicName(name, challenge, binding ?? "", attestation ?? "", platform ?? "", ct, floor ?? 0, Date.now()),
  );
  const stored = floor !== null && (!report.platform_document_version || storeVersion(report.platform_document_version));
  if (!stored) {
    warnings.push("This browser keeps no storage for this page, so an older signed platform document would not be refused: rollback protection is off.");
  }
  render(root, name, report, warnings);
}

main().catch((e) => {
  document.getElementById("main").replaceChildren(el("p", "verdict bad", `The check could not run: ${e.message}`));
});
