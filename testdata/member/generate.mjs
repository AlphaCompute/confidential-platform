// Writes webcrypto.json: documents signed by one non-extractable P-256 key made by WebCrypto, the
// way a page signs them, for the Rust side to verify. Node 20 or later, no packages:
//   node testdata/member/generate.mjs

import { writeFileSync } from "node:fs";

const { subtle } = globalThis.crypto;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const randomNonce = () => b64url(crypto.getRandomValues(new Uint8Array(32)));

// Values are plain ASCII strings and small integers, so JSON.stringify of a key-sorted object is
// its JCS form.
const jcs = (doc) =>
  JSON.stringify(Object.fromEntries(Object.entries(doc).sort(([a], [b]) => (a < b ? -1 : 1))));

const digest = async (context, text) =>
  new Uint8Array(
    await subtle.digest(
      "SHA-256",
      Buffer.concat([Buffer.from(context), Buffer.from([0]), Buffer.from(text)]),
    ),
  );

const highS = (sig) => BigInt("0x" + Buffer.from(sig.slice(32)).toString("hex")) > N / 2n;

const key = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const memberKey = b64url(new Uint8Array(await subtle.exportKey("spki", key.publicKey)));

const sign = async (context, document, wantHighS = false) => {
  const text = jcs(document);
  const d = await digest(context, text);
  for (;;) {
    const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, d));
    if (!wantHighS || highS(sig)) {
      return {
        context,
        document,
        member_key: memberKey,
        signature: { algorithm: "ecdsa-p256", signature: b64url(sig) },
        high_s: highS(sig),
        jcs: text,
      };
    }
  }
};

const issued_at = "2026-09-25T12:00:00Z";
const REQUEST = "alphacompute/connector-request/v1";
const entries = [
  await sign(REQUEST, { v: 1, op: "connect", provider: "google", nonce: randomNonce(), issued_at }),
  await sign(REQUEST, { v: 1, op: "list", nonce: randomNonce(), issued_at }, true),
  await sign("alphacompute/connector-write/v1", {
    v: 1,
    connection_id: "01999999-0000-7000-8000-000000000001",
    method: "POST",
    url: "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart",
    body_sha256: "sha256:" + Buffer.from(await subtle.digest("SHA-256", Buffer.from("hello"))).toString("hex"),
    nonce: randomNonce(),
    issued_at,
  }),
  await sign("alphacompute/connector-grant/v1", {
    v: 1,
    aud: "sha256:" + "ab".repeat(32),
    connections: ["01999999-0000-7000-8000-000000000001", "01999999-0000-7000-8000-000000000002"],
    exp: "2026-09-25T12:15:00Z",
    nonce: randomNonce(),
    issued_at,
  }),
];

const grant = entries[3];
const out = {
  entries: entries.map(({ jcs, ...entry }) => entry),
  grant_wire: b64url(Buffer.from(grant.jcs)) + "." + grant.signature.signature,
};
writeFileSync(new URL("./webcrypto.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
