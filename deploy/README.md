# The KMS nodes on Phala Cloud

Two CVMs in two regions run one Revision of `alpha-kms` over one trust-zone Postgres. The
production nodes are deployed neither by CI nor by shroud-go's deploy route: the operator creates
and upgrades the two CVMs by hand through the Phala Cloud API (or the `phala` CLI), one at a
time, with the compose the release workflow rendered. Only the dev node is deployed by a
workflow (below). This directory is the runbook; the compose itself is a
release artifact, because it names the image by digest and the digest exists only after the
build.

## What a release produces

A tag `v*` runs `.github/workflows/release.yml`: every image (`alpha-runtime`, `alpha-kms`,
`alpha-kms-dev`) is built twice, the second time with `--no-cache`, and the job fails unless
both builds give one image id and one layer set; the images are pushed as
`ghcr.io/<owner>/<name>:<tag>`. For the two KMS images the workflow then renders the node's
`app-compose.json` from the pushed digest (`cargo run -p alpha-cli --example kms_compose`,
which is `alpha_cli::deploy::kms_compose` over `alpha_core::phala::canonicalize`, the same
serializer Phala's API applies) and publishes the unsigned release manifest as the artifact
`<name>-release-manifest` and in the job summary:

- `app-compose.json` — the exact bytes Phala measures into RTMR3: the envelope, one service
  `alpha-kms` with the image by digest, port 8443 published for the gateway's TLS passthrough,
  the three evidence mounts, `restart: always`, and the four configuration variables as
  `allowed_envs` (`alpha-kms-dev` adds `ALPHACOMPUTE_KMS_DEV_ROOT_KEK`);
- `manifest.json` — `image` (`ghcr.io/…@sha256:…`) and `compose_hash` (`sha256:` of the bytes
  above).

Anyone can reproduce it: `cargo run -p alpha-cli --example kms_compose -- <app_id>
<image@sha256:…> out/` gives the same bytes and hash (`sha256sum out/app-compose.json`). The
App ids are constants of the workflow matrix (production `01a09f07-8d09-7640-94c1-bbdb74200a1e`,
dev `01a09f07-8d09-7aff-b257-83dbd9e6e641`); `testdata/manifest/06-kms-node` pins the shape.

`alpha-kms-dev` is the image of the dev KMS App: the `dev-root` cargo feature, compiled in, takes
the root KEK from `ALPHACOMPUTE_KMS_DEV_ROOT_KEK` instead of the custodians' shares. It is a
different image with a different `compose_hash`; a production platform document never lists it.

## Pulling from ghcr

The images are private. Every compose, the node's and every tenant's, carries a one-line
`pre_launch_script` that logs in to ghcr with `ALPHACOMPUTE_GHCR_TOKEN` from the encrypted env
when it is set; the script and the variable name are measured, the token is not. The deploy
that starts a new image supplies a token that can read the package: `.github/workflows/deploy.yml`
passes the job's own `github.token` and waits until the container runs, because the token
expires with the job. A reboot starts from the image already on the CVM's disk and needs no
token. `deploy/phala.py` is the create/update call itself (exact compose, `compose_hash` check,
encrypted env) for a deploy run by hand with a token of your own.

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
   for, and a region. Encrypt the environment to the reply's `app_env_encrypt_pubkey` and commit:
   `ALPHACOMPUTE_DATABASE_URL` (as the service user), `ALPHACOMPUTE_KMS_ENDPOINTS` (both nodes'
   URLs, `https://<app id>-8443s.<gateway base>`, so provision the second CVM first to learn its
   app id: the values are not measured, but a later env update rewrites the stored
   `allowed_envs` and changes what the CVM measures, see "Deploying the dev node"),
   `ALPHACOMPUTE_PCCS_URL`, `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL`, and after the commit check that
   the stored compose still hashes to `manifest.json`'s `compose_hash`. The node comes up
   `sealed`: `GET /ready` answers 503 `{"sealed": true}`.
3. **Bootstrap** on the first node: `alpha bootstrap --custodians c1.pub,c2.pub,c3.pub --anchor
   anchor.json --endpoint https://<node 1>` (`crates/alpha-cli/README.md`). The CLI verifies the
   node's evidence against the signed document before it seals anything; it writes one share
   file per custodian (hand each over, delete it) and prints `kms_ca_pem` and `anchor_key_id`.
   The node commits genesis before it answers, and the shares exist only in that answer: if
   the CLI does not get it (connection lost, CLI killed), do not retry — the retry is refused
   as `already_exists` and nothing can unseal the row it wrote. Drop the database, recreate it
   (step 1) and bootstrap again; nothing else has been written yet.
4. **Re-sign the document** with `kms_ca_pem` filled in; both nodes pick it up on their
   five-minute timer. From now on `alpha sign --check` prints the two values a tenant pins.
5. **Register the everyday admin key** of the pilot organization with the anchor key
   (`alpha call register-key --key anchor.key --key-id <anchor_key_id> …`); the anchor goes
   offline.
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
