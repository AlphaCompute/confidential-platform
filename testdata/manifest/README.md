# Compose vectors

The KMS registers a Revision as the exact bytes the admin signed and checks three things
about them: they parse as a JSON object, `name` equals the `app_id`, every `image:` in
`docker_compose_file` carries an `@sha256:` digest. The form of the bytes belongs to the
provider that writes them into the CVM.

- `01-canonical` — `input.json` is a compose the API stores unchanged (the fields it would fill
  in spelled out, a `pre_launch_script`, no `key_provider`; confirmed by provisioning it) as the
  tenant wrote it (unsorted keys, two-space indent); `app-compose.json` is the same compose in the form Phala Cloud's API stores it
  and dstack measures it: keys sorted recursively, no whitespace between tokens (checked against
  a running CVM, whose `tcb_info.app_compose` hashes to the API's `compose_hash`; the SDK's
  `dumpAppCompose` indents and is not that form); `expected.json` holds its `compose_hash` and the signing digest of
  `{app_id, compose}` under `alphacompute/revision/v1`. `alpha_core::phala::canonicalize` must
  reproduce `app-compose.json` byte for byte.
- `02-reject-image-tag` — the `app` image is `ghcr.io/acme/app:latest`.
- `03-reject-name` — `name` is not the `app_id`.
- `04-trailing-newline` — `01`'s bytes with a trailing newline, as an editor would leave them:
  the KMS accepts them as a distinct Revision; `canonicalize` maps them back to `01`.
- `05-deploy` — `app.yaml` is what a tenant hands to `alpha deploy`; `app-compose.json` is the
  compose the generator builds from it (envelope, the `alpha-runtime` service last with its three
  host mounts and pins, the socket volume on the containers that asked for it, a `pre_launch_script`
  that does nothing, the fields Phala's
  API would otherwise fill in, no `key_provider`), already in Phala's form; `expected.json` holds its `compose_hash`. Produced by the generator itself, so it
  pins the generator's output; Phala's serialization is what `01` proves.
- `06-kms-node` — the KMS node's own compose as `kms_compose` renders it for the `app_id` and
  image in `expected.json` (a placeholder digest; the release workflow renders the real one from
  the pushed image): the same envelope with one service, the four configuration variables as `allowed_envs`, port 8443
  published, the three evidence mounts. `expected.json` holds its `compose_hash`; the dev image's
  compose differs only by `ALPHACOMPUTE_KMS_DEV_ROOT_KEK` and is not pinned.
