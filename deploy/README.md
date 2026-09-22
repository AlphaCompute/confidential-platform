# The KMS nodes on Phala Cloud

Two CVMs in two regions run one Revision of `alpha-kms` over one trust-zone Postgres. The
production nodes are deployed neither by CI nor by shroud-go's deploy route: the operator creates
and upgrades the two CVMs by hand through the Phala Cloud API (or the `phala` CLI), one at a
time, with an operator-rendered compose bound to an approved published image digest.
Only the dev node is deployed by a workflow (below). This directory is the runbook;
release candidates must pass acceptance before their images can be published and
used to render a production compose.

## What a release candidate produces

A `v*` tag or explicit dispatch runs `.github/workflows/release.yml` after
mandatory CI. Separate runners build each runtime, KMS, development KMS and
CPU application candidate without shared build caches. The comparison job
requires identical image fingerprints, source commits and recorded materials.
Artifacts contain the image archive, inspection data, Cargo dependency
inventory and a provenance attestation. They remain unqualified candidates.

The workflow does not push a registry image or render a published release
manifest. A separately authorized release process must verify the candidate
attestations, complete OS/native/Python dependency locks and SBOM, customer
approvals and offering acceptance before publishing any digest. See
[release provenance](../docs/release-provenance.md).

After an approved image digest exists, the operator can render a node compose:
`cargo run -p alpha-cli --example kms_compose -- <app_id> <image@sha256:...> out/`.
The output binds the image and five operational variables, including
`ALPHACOMPUTE_DATABASE_INTEGRITY`; the development variant also carries
`ALPHACOMPUTE_KMS_DEV_ROOT_KEK`. The `06-kms-node` fixture pins this shape.
Production and development Apps remain distinct, and production platform
documents must never admit the development root-KEK feature.

## Pulling from ghcr

The images are public, so a CVM pulls them anonymously and no credential is delivered to one.
Every compose, the node's and every tenant's, still carries a one-line `pre_launch_script` that
does nothing: without one the API inserts its own, which prunes every image before pulling, and
a CVM rebooted afterwards would lose the image it runs. `deploy/phala.py` is the create/update
call itself (exact compose, `compose_hash` check, encrypted env) for a deploy run by hand.

## Deploying the dev node

`.github/workflows/deploy.yml` renders the dev node's compose from an `alpha-kms-dev` image,
creates or updates the CVM through `deploy/phala.py`, and waits until the container runs. The
image is a release tag (`v…`) or a dev-image tag: `.github/workflows/dev-image.yml` builds
`alpha-kms-dev` and `alpha-runtime` once with the build cache and pushes `dev-<commit>`, minutes
instead of a release's double build. Dev images are never listed in a production platform
document.

`deploy/phala.py` sends every `allowed_envs` name on each commit and then reads back the compose
Phala stored: a commit that carries env can rewrite the stored `allowed_envs` (drop names,
reorder them), which changes what the CVM measures after the provision-time check passed. When
the stored compose is not the file, the script refuses; recreate that CVM rather than updating it
again, since an env update does not restore the order.

## Signing the Revision

The release-key holder adds `{ "compose_hash": "<from manifest.json>", "build": "kms <tag>",
"source_url": "<the release>" }` to `kms_revisions[]` of the platform document, raises
`version`, signs with `alpha sign --release-key`, and publishes the artifact at the URL the
nodes read as `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL`. The document must also carry a
`reference_values` entry for the dstack guest image and CVM shape the nodes will run on. On
day 0 `kms_ca_pem` is still empty; it is filled in after bootstrap (below).

## Day 0

Before anything: the trust-zone Postgres CVM is up and addressed by our CNAME; the PCCS URL and
the platform-document URL are served; the signed document lists the Revision.

0. **The trust-zone Postgres CVM**: `deploy/postgres/docker-compose.yml`, deployed with
   `POSTGRES_PASSWORD` (`openssl rand -hex 32`: hex needs no percent-encoding in a URL) in the
   encrypted env; it creates the owner `postgres` and the database `alpha`. Every client, the
   KMS included, reaches it through the gateway at `<pg app id>-5432s.<gateway base>:443` and
   must open with TLS:
   `postgres://<user>:<password>@<pg app id>-5432s.<gateway base>:443/alpha?sslmode=require&sslnegotiation=direct`
   (below, `<pg>` stands for everything after the password). The gateway routes by the SNI of
   the first bytes and drops a connection that starts with Postgres's plaintext `SSLRequest`, so
   a client without direct negotiation (`psql` before 17, an unpatched sqlx) hangs or is
   refused. `sslmode=require` does not verify the server certificate; whoever routes the
   connection could relay it, which is Phala, already the holder of the volume.
1. **Migrate once**, as the owner, from a machine that reaches the trust-zone Postgres:
   `docker run --rm -e ALPHACOMPUTE_DATABASE_URL=postgres://postgres:<POSTGRES_PASSWORD>@<pg>
   ghcr.io/<owner>/alpha-kms@sha256:<digest> migrate`. The migration creates the `alpha_kms`
   role (`nologin`) and its grants; the nodes connect as a login that is a member of it.
   Create that login with a second generated password (psql 17 or newer):
   `psql "postgres://postgres:<POSTGRES_PASSWORD>@<pg>" -c "create role alpha_kms_node login
   password '<node password>' in role alpha_kms"`. The owner password then stays with the
   operator; the nodes only ever get `postgres://alpha_kms_node:<node password>@<pg>`.
2. **Create the first CVM.** Provision through the Phala Cloud API with `compose_file` set to the
   object in `app-compose.json` (the API serializes it itself; the `compose_hash` in the provision
   reply must equal `manifest.json`'s — if it does not, stop: the bytes Phala would measure are
   not the signed Revision), the dstack image and instance type the document has reference values
   for, and a region. Install `integrations/dstack-tee` and provision `PHALA_KMS_SIGNER`
   independently. Verify the fresh app-bound v1 signed key matches `app_env_encrypt_pubkey`
   before encrypting or committing. Unsigned keys and legacy-only signatures are refused:
   `ALPHACOMPUTE_DATABASE_URL` (as the service user), `ALPHACOMPUTE_KMS_ENDPOINTS` (both nodes'
   URLs, `https://<app id>-8443s.<gateway base>`, so provision the second CVM first to learn its
   app id: the values are not measured, but a later env update rewrites the stored
   `allowed_envs` and changes what the CVM measures, see "Deploying the dev node"),
   `ALPHACOMPUTE_PCCS_URL`, `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL`,
   `ALPHACOMPUTE_DATABASE_INTEGRITY=trusted-operators-v1` (see `docs/database-trust.md`),
   and after the commit check that
   the stored compose still hashes to `manifest.json`'s `compose_hash`. The node comes up
   `sealed`: `GET /ready` answers 503 `{"sealed": true}`.
3. **Bootstrap** on the first node: `alpha bootstrap --custodians c1.pub c2.pub c3.pub
   --endpoint https://<node 1>` (`crates/alpha-cli/README.md`). The CLI verifies the
   node's evidence against the signed document before it seals anything; it writes one share
   file per custodian (hand each over, delete it) and prints `kms_ca_pem`. Genesis carries no
   organization: custodians hold the platform's key material and have nothing to do with tenants.
   The node commits genesis before it answers, and the shares exist only in that answer: if
   the CLI does not get it (connection lost, CLI killed), do not retry — the retry is refused
   as `already_exists` and nothing can unseal the row it wrote. Drop the database, recreate it
   (step 1) and bootstrap again; nothing else has been written yet.
4. **Re-sign the document** with `kms_ca_pem` filled in; both nodes pick it up on their
   five-minute timer. From now on `alpha sign --check` prints the two values a tenant pins.
5. **The organization registers its root key** against the `org_id` the console shows, by
   posting `{payload, signature}` to `POST /v1/keys`: the payload is
   `{org_id, principal_id, public_key, label, issued_at}`, signed by the key it names under
   `alphacompute/org-root-key/v1` and with no `key_id` in the signature object. An `org_id` is
   claimed once; re-sending the same document answers 200 with the stored row, which is how the
   organization checks that the key against its identifier is its own. It then registers the
   everyday admin key (`alpha call register-key --key root.key --key-id <the reply's id> …`) and
   the root key goes offline.
6. **Create the second CVM** in the other region with the same compose and env. On start it walks
   `ALPHACOMPUTE_KMS_ENDPOINTS`, finds the first node ready, writes `node.join.request` and
   joins; `GET /ready` on it answers 200 `{"sealed": false}`. A node that started before the
   first was serving must be restarted: the walk happens once, at start.

Both nodes now serve; a restart of either is a `join` from the other; losing both means
`alpha unseal` with two of the three shares.

## Upgrade

1. Release; sign a document whose `kms_revisions[]` lists the old and the new Revision; every
   tenant App that pins the KMS gets a Revision with `ALPHACOMPUTE_KMS_REVISIONS` listing both.
2. Update the compose of **one** CVM through the Phala API (provision the compose-file update
   with the new `app-compose.json`, check `compose_hash` again, commit). It restarts `sealed`,
   joins the other node, and `GET /ready` turns 200.
3. Only then the other CVM, the same way. Updating both at once loses both, which is an
   unseal ceremony, not an upgrade.
4. When no tenant pins the old Revision any more, drop it from the document.

## The dev App

The same steps with `alpha-kms-dev`, its own App id, its own Postgres, its own platform
document at its own URL (signed by the same release key: both images compile in the one
`release-key.pub`; it lists the dev Revision and never a production one), and
`ALPHACOMPUTE_KMS_DEV_ROOT_KEK` (64 hex digits) in the encrypted env. `alpha bootstrap` still runs once on the empty database (with three throwaway custodian
keys: the root is the env value, so the shares it writes protect nothing and can be deleted);
after that every restart serves without `unseal` or `join`. Production shares and the
production release key never touch it.
