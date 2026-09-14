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
