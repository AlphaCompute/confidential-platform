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
`alpha-kms-dev`, `alpha-inference`, `alpha-broker`) is built twice, the second time with `--no-cache`, and the job fails unless
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
   for, and a region. Encrypt the environment to the reply's `app_env_encrypt_pubkey` and commit:
   `ALPHACOMPUTE_DATABASE_URL` (as the service user), `ALPHACOMPUTE_KMS_ENDPOINTS` (both nodes'
   URLs, `https://<app id>-8443s.<gateway base>`, so provision the second CVM first to learn its
   app id: the values are not measured, but a later env update rewrites the stored
   `allowed_envs` and changes what the CVM measures, see "Deploying the dev node"),
   `ALPHACOMPUTE_PCCS_URL`, `ALPHACOMPUTE_PLATFORM_DOCUMENT_URL`, and after the commit check that
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

## The broker's database

`alpha-broker` keeps its connections in its own database on the same trust-zone Postgres, and no
one opens a database connection to create it. The Postgres compose carries a one-shot service,
`alpha-broker-init`, on the same pinned image: on every start of the CVM it waits for Postgres,
creates the login role `alpha_broker` and the database `alpha_broker` owned by it when they are
absent, and exits 0. Rerunning it changes nothing, so the password it set the first time stays
the role's password. It grants nothing else; the role has no access to the KMS's tables.

The Postgres CVM's encrypted env holds `ALPHA_BROKER_PASSWORD` (`openssl rand -hex 32`) beside
`POSTGRES_PASSWORD`, and its `allowed_envs` lists both. An empty `ALPHA_BROKER_PASSWORD` makes
the service exit 1 naming it; Postgres itself is unaffected.

To add the broker to a running Postgres CVM, update that CVM through the Phala API: its
`app-compose.json` with `docker_compose_file` set to this compose and `allowed_envs` set to
`["POSTGRES_PASSWORD", "ALPHA_BROKER_PASSWORD"]`, then `deploy/phala.py update <pg cvm id>
<app-compose.json>` with both variables in the environment. A commit that carries env rewrites
the stored `allowed_envs`, so every name goes out, and `POSTGRES_PASSWORD` must be the value the
volume was created with. The update restarts Postgres; the KMS nodes reconnect. `deploy/phala.py
wait` does not apply to this CVM, because the init container exits by design.

The broker's Secret `database-url` is
`postgres://alpha_broker:<ALPHA_BROKER_PASSWORD>@<pg app id>-5432s.<gateway base>:443/alpha_broker?sslmode=require&sslnegotiation=direct`,
put for the broker's App with
`alpha call put-secret`. The broker applies its own migrations when it starts, and its `/ready`
answers 200 only once it reaches that database.

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
