# Compose vectors

The KMS registers a Revision as the exact bytes the admin signed and checks three things
about them: they parse as a JSON object, `name` equals the `app_id`, every `image:` in
`docker_compose_file` carries an `@sha256:` digest. The form of the bytes belongs to the
provider that writes them into the CVM.

- `01-canonical` — `input.json` is the compose as the tenant wrote it (unsorted keys, two-space
  indent); `app-compose.json` is the same compose as Phala Cloud's API writes it
  (`dumpAppCompose` from `phala-cloud-sdks`, `js/src/utils/get_compose_hash.ts`, run under node
  over `input.json`); `expected.json` holds its `compose_hash` and the signing digest of
  `{app_id, compose}` under `alphacompute/revision/v1`. `alpha_core::phala::canonicalize` must
  reproduce `app-compose.json` byte for byte.
- `02-reject-image-tag` — the `app` image is `ghcr.io/acme/app:latest`.
- `03-reject-name` — `name` is not the `app_id`.
- `04-trailing-newline` — `01`'s bytes with a trailing newline, as an editor would leave them:
  the KMS accepts them as a distinct Revision; `canonicalize` maps them back to `01`.
- `05-deploy` — `app.yaml` is what a tenant hands to `alpha deploy`; `app-compose.json` is the
  compose the generator builds from it (envelope, the `alpha-runtime` service last with its three
  host mounts and pins, the socket volume on the containers that asked for it), already in
  Phala's form; `expected.json` holds its `compose_hash`. Produced by the generator itself, so it
  pins the generator's output; Phala's serialization is what `01` proves.
- `06-kms-node` — the KMS node's own compose as `kms_compose` renders it for the `app_id` and
  image in `expected.json` (a placeholder digest; the release workflow renders the real one from
  the pushed image): the same envelope with one service, the four `allowed_envs`, port 8443
  published, the three evidence mounts. `expected.json` holds its `compose_hash`; the dev image's
  compose differs only by `ALPHACOMPUTE_KMS_DEV_ROOT_KEK` and is not pinned.
