"use strict";

const WASM_URL = "@WASM_URL@";
const WASM_SRI = "@WASM_SRI@";

const VERSION_KEY = "alphacompute-platform-version";
const TICKET = /^[A-Za-z0-9_-]{43}$/;

const MESSAGES = {
  framed: "This page cannot run inside another page. Open the link in its own tab.",
  no_passkeys: "This browser cannot use passkeys. Open this link in Safari, Chrome, Edge or Firefox.",
  bad_link: "This link is not valid.",
  platform: "The platform document did not verify. Do not continue; contact AlphaCompute.",
  older_platform: "This page was given an older platform document than one seen before. Do not continue.",
  not_signer: "This page is not served from an AlphaCompute signer address.",
  unexpected: "Something went wrong on this page. Nothing was signed. Reload to try again.",
};

function refuse(key) {
  const p = document.createElement("p");
  p.className = "refusal";
  p.textContent = MESSAGES[key];
  document.getElementById("main").replaceChildren(p);
}

function storedVersion() {
  try {
    const v = Number(localStorage.getItem(VERSION_KEY));
    return Number.isSafeInteger(v) ? v : 0;
  } catch (_) {
    return 0;
  }
}

function storeVersion(version) {
  try {
    localStorage.setItem(VERSION_KEY, String(version));
  } catch (_) {
    // Private modes may refuse storage; the check is best effort by design.
  }
}

async function verifiedPlatform() {
  try {
    const reply = await fetch("./platform.json", { cache: "no-store" });
    if (!reply.ok) return null;
    const viewText = wasm_bindgen.verifyPlatform(await reply.text(), Date.now());
    return { view: JSON.parse(viewText), viewText };
  } catch (_) {
    return null;
  }
}

async function boot() {
  if (window.top !== window.self) return refuse("framed");
  if (!window.PublicKeyCredential) return refuse("no_passkeys");

  await wasm_bindgen({ module_or_path: fetch(WASM_URL, { integrity: WASM_SRI }) });

  const mode = location.pathname.split("/").pop();
  const ticket = location.hash.slice(1);
  if ((mode !== "claim" && mode !== "approve") || !TICKET.test(ticket)) return refuse("bad_link");

  const platform = await verifiedPlatform();
  if (!platform) return refuse("platform");
  const { view, viewText } = platform;

  if (view.version < storedVersion()) return refuse("older_platform");
  storeVersion(view.version);

  if (!view.signer || !view.signer.origins.includes(location.origin)) return refuse("not_signer");

  if (mode === "claim") return startClaim(view, viewText, ticket);
  return startApproval(view, viewText, ticket);
}

document.addEventListener("DOMContentLoaded", () => {
  boot().catch(() => refuse("unexpected"));
});
