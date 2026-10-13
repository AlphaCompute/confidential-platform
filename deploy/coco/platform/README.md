# Platform services on confidential containers (PRD-05, D2)

Pod-spec templates for the platform's own services on owned hardware. Each runs as a Kata TDX pod
VM on the CPU class `kata-qemu-tdx`. Each template is rendered by `alpha coco render` into a
versioned manifest, its Revision v2 is listed or registered by our own keys, and Rafay deploys the
manifest as a workload. These templates follow `deploy/coco/model-server.yaml` (PRD-04):

- `${NAME}` placeholders are filled from the env files.
- The one Kata annotation, `io.katacontainers.config.hypervisor.cc_init_data`, is `${CC_INIT_DATA}`. The renderer computes it.
- The pod's init-data is projected through the downward API at `/run/alpha-pod/cc_init_data`.
- No service-account token, no service links.
- Images are pinned by digest, and every container's requests equal its limits. The pod VM is sized from the limits.
- Probes are HTTPS GETs from the kubelet. The agent policy refuses exec.

| File | What it is |
|---|---|
| `alpha-kms.yaml` | the KMS: a StatefulSet of two nodes on the verifier pool (`alphacompute.ai/role: verifier`), one per zone, rolled one at a time; a headless Service naming every node, a Service for the serving ones, a PodDisruptionBudget |
| `alpha-broker.yaml` | the connector broker, `alpha-runtime` as a native sidecar |
| `alpha-guard.yaml` | the content judge, `alpha-runtime` as a native sidecar |
| `alpha-inference.yaml` | the inference front, `alpha-runtime` as a native sidecar. It matches `services/alpha-inference` on this branch. PRD-04 (#69, #70) changes its environment; the spec changes with it |
| `env/cluster.env` | per cluster: the runtime image, its share of the VM, the KMS pins |
| `env/<service>.env` | per service: App id, image, shape, configuration |

**All configuration that matters is in the measured environment.** It sits in the container's `env`, so it is in the agent policy, the init-data and the Revision. No value comes from a ConfigMap or a Kubernetes Secret: the host writes both, and attested namespaces refuse Secrets (alpha-infra admission). Secret values are released by the KMS to the service's Revision and read over the runtime socket. The KMS's own Secrets are its custodian-held keys. Changing any value is a new Revision.

The env files are examples. Every value still written `<like this>` is refused by `alpha coco render` until it is filled. Values may not hold `"`, `'`, `` ` ``, `\`, `$` or a newline, so JSON configuration (`UPSTREAM_POLICY`) is written in the spec itself.

## Render, list or register, deploy

The KMS goes first, because every other service pins it. Its build is listed in the platform document, not registered at the KMS:

```sh
# 1. The input for genpolicy 4.1.0 (in its pinned container), with an empty init-data annotation:
alpha coco render --spec deploy/coco/platform/alpha-kms.yaml --for-genpolicy \
  --env deploy/coco/platform/env/alpha-kms.env > alpha-kms.genpolicy.yaml
# 2. genpolicy on that file, then the policy review: no exec, no log readback, no file copy,
#    the environment above exactly. The result is kms.rego.
# 3. The manifest to deploy; stderr has the Revision v2 and its hash:
alpha coco render --spec deploy/coco/platform/alpha-kms.yaml --policy kms.rego \
  --env deploy/coco/platform/env/alpha-kms.env > alpha-kms.rendered.yaml
```

4. **The release-key holder** adds the build to `kms_revisions` as `{"compose_hash": "<the hash>", "build": "kms <tag> (kata)", "source_url": "<the release>", "kind": "kata-tdx"}`. Without `kind`, a Kata node is refused as a prototype build. The holder also adds the `kata-tdx` reference values captured for the CPU guest at this VM shape, raises `version`, signs with `alpha sign --release-key` and publishes the document. `alpha sign --check` then prints the KMS CA and every listed Revision; those are `KMS_CA_SPKI_SHA256` and `KMS_REVISIONS` in `env/cluster.env`.
5. **Rafay** deploys `alpha-kms.rendered.yaml`, committed to the platform GitOps repository under its version, as a workload of the `alpha-verifier` project into the namespace `alpha-kms`. No one else can write there. `alpha-kms migrate` runs once beforehand as the schema owner (`deploy/README.md`, Day 0).
6. The node comes up sealed. What happens next depends on the case:
   - **Production genesis.** The custodians run `alpha bootstrap --custodians c1.pub c2.pub c3.pub --endpoint https://alpha-kms-0.alpha-kms-nodes.alpha-kms.svc:8443`, from inside the site (the PCCS answers only there), through `kubectl port-forward` or the site ingress (ponytail: Q2). The CLI appraises the node's Kata evidence before it seals anything (`crates/alpha-cli/README.md`) and prints the node's Revision and policy digest for their record. The second node then joins the first. The release-key holder re-signs the document with `kms_ca_pem`.
   - **Migration (PRD-05 step 5).** The Kata node joins a prototype node over the existing protocol, keeping the CA and every key. Its `KMS_NODE_ENDPOINTS` lists the prototype nodes too, and the document lists both builds. After the second Kata node joins, the prototype nodes are stopped one at a time, never both. A later build without the prototype endpoints joins from a Kata node.

Then each service. On this branch alpha-guard pins alpha-inference's Revision, so alpha-inference goes first:

```sh
alpha coco render --spec deploy/coco/platform/alpha-inference.yaml --for-genpolicy \
  --env deploy/coco/platform/env/cluster.env --env deploy/coco/platform/env/alpha-inference.env > inference.genpolicy.yaml
# genpolicy, review → inference.rego
alpha coco render --spec deploy/coco/platform/alpha-inference.yaml --policy inference.rego \
  --env deploy/coco/platform/env/cluster.env --env deploy/coco/platform/env/alpha-inference.env > alpha-inference.rendered.yaml
```

7. **The platform organization registers the Revision v2** the renderer printed, under its own admin key: `alpha call register-revision --key platform-admin.key --key-id <id> payload.json` with `{"app_id": "<the service's App>", "compose": "<the Revision v2 JCS>"}`. It also puts the service's Secrets (`alpha call put-secret`, names in each env file). A pod whose Revision is not registered gets no leaf.
8. **Rafay** deploys the rendered manifest, versioned in the GitOps repository, as a workload of the restricted platform project into an attested namespace of the CPU-CC cluster.
9. Put the Revision where its callers pin it (alpha-inference's into alpha-guard's `INFERENCE_REVISIONS`), render the caller, and repeat.

The manifests in the GitOps repository are the record: each one's init-data is in its annotation, so anyone can recompute its Revision from the file.

## For review

- **The database credential (ponytail: M2).** The KMS reads `ALPHACOMPUTE_DATABASE_URL` from its measured environment. Its init-data is served to anyone by `GET /v1/node/evidence`, which custodians call unauthenticated, so a password in that URL would be public. Kubernetes Secrets are refused in the verifier namespace, and the KMS cannot fetch its own credential before it is unsealed, because it needs the database to join or unseal. `env/alpha-kms.env` therefore holds the URL without a password, and `alpha coco render` refuses the example as it stands. A Kata node refuses to start if `ALPHACOMPUTE_DATABASE_URL` holds a password, in its userinfo or as `password=` (`alpha_kms::measured_env`, the same rule as the D10 draft's `db_auth::check_url`). `services/alpha-kms/tests/platform_templates.rs` renders every template here with its env files and refuses any URL value that holds one. The choice is Ryan Tharp's, with the M2 encryption decision. Options:
  - Authentication the trust-zone Postgres grants by network alone, to the KMS pods. The database is an untrusted store under M2(b), and the KMS checks every row it releases on.
  - A client certificate.
  - Accepting a published password with network isolation.
- **Signer hosting.** The signer page has no service binary in this repository. It is a static bundle that verifies itself: `signer.bundle_sha256` is pinned in the platform document, and the page verifies the document with the compiled-in release key. So it has no template here. PRD-05 lists "signer hosting" among the platform services, and D7 puts every platform service in a confidential namespace. Whether a static file server must run as a Kata pod, or may sit in the infra pool like the PCCS, is to be decided. shroud-go has its own repository.
- **Not yet in `alpha-kms.yaml`:** `ALPHACOMPUTE_FORTANIX_CCM_URL` (F8) and `ALPHACOMPUTE_KBS_HOSTNAME` (#80). Each is a new KMS build when added.
- **Exposure.** Clients in other clusters reach the KMS and these services through alpha-infra's SNI-passthrough ingress. Its names wait on the site domain (ponytail: Q2). Clients pin the KMS CA and the Revisions, never a name.
