"use strict";

// A Revision v2 (a Kata confidential pod) on the approval page: shown from the Revision itself and
// from init-data that rebuilds it, and registered exactly as the KMS's check_registration accepts.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  NOT_CONFIRMED,
  SoftwareAuthenticator,
  approvalApi,
  contextDigest,
  ids,
  jcs,
  loadPage,
  mintReceipt,
  sha256,
  testdata,
} = require("./harness.js");

const APPROVED = "Approved. You can close this tab.";
const MISMATCH =
  "What the service asked you to approve does not match what it would run. Nothing was signed.";
const UNREADABLE =
  "This page cannot read what the service asked you to approve, so it cannot show it to you. Nothing was signed.";
const NO_INITDATA =
  "The service did not send this pod's init-data, so this page cannot show its images or agent policy. Approving registers them by the digests under Technical details.";

const INITDATA = testdata("coco/b300x1/initdata.toml");
const REVISION = testdata("coco/b300x1/revision.json");
const APP = JSON.parse(REVISION).app_id;
const b64 = (text) => Buffer.from(text).toString("base64");
const label = (text) => `sha256:${sha256(text).toString("hex")}`;

function organization() {
  const laptop = new SoftwareAuthenticator();
  const key = laptop.enroll();
  return {
    laptop,
    credentials: [{ credential_id: key.id, key_id: "01920000-0000-7000-8000-00000000000a" }],
  };
}

async function revisionPage(apiOptions = {}) {
  const { laptop, credentials } = organization();
  const api = approvalApi({
    app_id: APP,
    compose: REVISION,
    machine: "b300x1",
    credentials,
    ...apiOptions,
  });
  const page = await loadPage({ routes: api.routes, authenticator: laptop, path: "/sign/approve" });
  await page.startApproval();
  return { api, page, laptop, credentials };
}

// The init-data with `[from, to]` replaced and the Revision v2 it stands for, in the KMS's form.
function edited(from, to) {
  const initdata = INITDATA.replace(from, to);
  assert.notEqual(initdata, INITDATA);
  const policy = /"policy.rego" = '''\n([\s\S]*?)'''/.exec(initdata)[1];
  const revision = JSON.parse(REVISION);
  revision.initdata_sha256 = label(initdata);
  revision.policy_sha256 = label(policy);
  return { initdata: b64(initdata), compose: jcs(revision) };
}

test("a Revision v2 with its init-data shows the pod and registers the Revision", async () => {
  const { api, page, laptop, credentials } = await revisionPage({ initdata: b64(INITDATA) });
  const text = page.text();
  for (const line of [
    "Confidential pod",
    "Runtime class: kata-qemu-nvidia-gpu-tdx",
    "GPUs: 1 × B300, in confidential computing mode",
    "Images the agent policy names",
    "Image: registry.k8s.io/pause",
    `Digest: sha256:${"5c".repeat(32)}`,
    "Image: ghcr.io/alphacompute/alpha-runtime",
    `Digest: sha256:${"7d".repeat(32)}`,
    "Image: docker.io/vllm/vllm-openai",
    `Digest: sha256:${"e1".repeat(32)}`,
    "Run commands in a container (exec): denied",
    "Read a container's output (logs): denied",
    "Machine: b300x1 (chosen by the service, not part of what you sign)",
  ]) {
    assert.ok(text.includes(line), `${line}\n${text}`);
  }
  assert.ok(!text.includes(NO_INITDATA));
  const technical = page.find((n) => n.tagName === "DETAILS").lines().join("\n");
  const revision = JSON.parse(REVISION);
  for (const line of [
    REVISION,
    `compose_hash: ${api.compose_hash}`,
    `initdata_sha256: ${revision.initdata_sha256}`,
    `policy_sha256: ${revision.policy_sha256}`,
    "default ExecProcessRequest := false",
  ]) {
    assert.ok(technical.includes(line), `${line}\n${technical}`);
  }
  assert.deepEqual(page.buttons(), ["Approve with passkey", "Decline"]);

  await page.click("Approve with passkey");
  const got = laptop.log[0];
  assert.deepEqual(ids(got.options.allowCredentials), [credentials[0].credential_id]);
  const wasm = page.wasm();
  const payload = { app_id: APP, compose: REVISION };
  assert.deepEqual(
    Buffer.from(got.options.challenge),
    contextDigest("alphacompute/revision/v1", wasm.canonicalJson(JSON.stringify(payload))),
  );
  assert.equal(api.revisions.length, 1);
  assert.deepEqual(api.revisions[0].body.payload, payload);
  assert.equal(api.revisions[0].body.signature.key_id, credentials[0].key_id);
  assert.equal(label(api.revisions[0].body.payload.compose), api.compose_hash);
  assert.equal(api.puts.length, 0);
  assert.ok(page.text().includes(APPROVED), page.text());
});

test("without init-data the Revision is shown by its digests and can still be approved", async () => {
  const { api, page } = await revisionPage();
  const text = page.text();
  for (const line of [
    "Runtime class: kata-qemu-nvidia-gpu-tdx",
    "GPUs: 1 × B300, in confidential computing mode",
    NO_INITDATA,
  ]) {
    assert.ok(text.includes(line), `${line}\n${text}`);
  }
  for (const absent of ["Images the agent policy names", "exec", "Image:"]) {
    assert.ok(!text.includes(absent), `${absent}\n${text}`);
  }
  await page.click("Approve with passkey");
  assert.equal(api.revisions[0].body.payload.compose, REVISION);
  assert.ok(page.text().includes(APPROVED), page.text());
});

test("a CPU-class Revision names no GPU", async () => {
  const { initdata, compose } = edited(
    '"gpu":{"count":1,"model":"B300"},"runtime_class":"kata-qemu-nvidia-gpu-tdx"',
    '"runtime_class":"kata-qemu-tdx"',
  );
  const revision = JSON.parse(compose);
  delete revision.gpu;
  revision.runtime_class = "kata-qemu-tdx";
  const { page } = await revisionPage({ compose: jcs(revision), initdata });
  const text = page.text();
  assert.ok(text.includes("Runtime class: kata-qemu-tdx"), text);
  assert.ok(text.includes("GPUs: none"), text);
  assert.ok(text.includes("Run commands in a container (exec): denied"), text);
});

test("the policy summary is read from the Rego, never assumed", async () => {
  const cases = [
    [
      ["default ExecProcessRequest := false", "default ExecProcessRequest := true"],
      "Run commands in a container (exec): not denied: the policy has rules that may allow it",
    ],
    [
      ["default ReadStreamRequest := false", "ReadStreamRequest := true"],
      "Read a container's output (logs): not denied: the policy has rules that may allow it",
    ],
    [
      ["default SetPolicyRequest := false", "default SetPolicyRequest := true"],
      "Run commands in a container (exec): not denied: the policy lets the host replace the policy",
    ],
    [
      ["default AllowRequestsFailingPolicy := false", "AllowRequestsFailingPolicy := true"],
      "Read a container's output (logs): not denied: the policy lets refused requests through",
    ],
  ];
  for (const [[from, to], line] of cases) {
    const { page } = await revisionPage(edited(from, to));
    const text = page.text();
    assert.ok(text.includes(line), `${to}: ${line}\n${text}`);
    assert.ok(page.buttons().includes("Approve with passkey"), text);
  }
  const { page } = await revisionPage(edited(/\npolicy_data := [\s\S]*\n'''/, "\n'''"));
  assert.ok(page.text().includes("None that this page can read."), page.text());
});

test("init-data that does not rebuild the Revision is refused before any prompt", async () => {
  const other = edited("default ExecProcessRequest := false", "default ExecProcessRequest := true");
  const refusals = [
    // Another pod's init-data under this Revision.
    [{ initdata: other.initdata }, MISMATCH],
    [{ initdata: b64(`${INITDATA}\n`) }, MISMATCH],
    // The init-data whose own hash this Revision names, but another policy digest.
    [
      {
        compose: jcs({ ...JSON.parse(REVISION), policy_sha256: label("other") }),
        initdata: b64(INITDATA),
      },
      MISMATCH,
    ],
    // A Revision that does not hash to the request.
    [{ compose_hash: label("other") }, MISMATCH],
    [{ initdata: "not base64!" }, UNREADABLE],
    [{ initdata: 7 }, UNREADABLE],
    // What check_registration refuses.
    [{ compose: REVISION.replace(",", ", ") }, UNREADABLE],
    [{ app_id: "01920000-0000-7000-8000-000000000002" }, UNREADABLE],
    [{ compose: REVISION.replace('"count":1', '"count":2') }, UNREADABLE],
    [edited("package agent_policy", "package other"), UNREADABLE],
  ];
  for (const [options, sentence] of refusals) {
    const { page, laptop } = await revisionPage(options);
    assert.equal(page.text(), sentence, JSON.stringify(options));
    assert.deepEqual(page.buttons(), []);
    assert.equal(laptop.log.length, 0);
  }
});

test("a Revision v2 reads approved only after the registration receipt verifies", async () => {
  const { api, page } = await revisionPage({ initdata: b64(INITDATA) });
  api.revisionReceipt = (text, response) =>
    mintReceipt("revision.register", text, { ...response, compose_hash: label("other") });
  await page.click("Approve with passkey");
  assert.ok(page.text().includes(NOT_CONFIRMED), page.text());
  assert.ok(!page.text().includes(APPROVED));
});
