# Encrypted storage, encrypted images and sealed secrets on Kata (PRD-02 deliverables 25 and 26)

A Kata confidential pod has two ways to keep data it writes to disk from the host, and Option B adds two more CoCo features that need a key broker. This page says which does what, which key each uses, and what the init-data generator (`alpha coco render`, `alpha coco wrap`, [coco-generator.md](coco-generator.md)) writes for each. Its last part is the contract between the generator and Trustee's KBS.

| | Option A: `alpha-volume` | Option B: the Confidential Data Hub (CDH) |
|---|---|---|
| Volume type | **persistent**: a block-mode claim that outlives the pod | **scratch**: a disk-backed `emptyDir`, gone with the pod |
| Who encrypts | the `alpha-volume` init container (LUKS2, device-mapper in the TD) | CDH, when the Kata agent mounts the block device (LUKS2, dm-integrity by default) |
| Key | the App's derived key for `volume.<name>`, from `alpha-runtime` after attestation | 4096 random bytes generated in the TD; never leaves it, never stored |
| Key authority | alpha-kms (`POST /v1/keys/derive`) | none |
| Generator input | `x-alphacompute-volumes: {<v>: {size}}`, `render --volume` | `x-alphacompute-scratch: {<v>: {size}}`, or an `emptyDir` without `medium: Memory` in a render template |
| Needs the KBS | no | no |

Every other `emptyDir` the generators write is `medium: Memory`, in TD memory.

## Why there is one path per volume type

The pinned Kata (4.1.0, guest-components `d4dce5ce62294cfa741225f7e5b4527ea276f326`) calls CDH's `secure_mount` in two places only: for a block `emptyDir` whose storage carries `encryption_key=ephemeral` (the runtime classes' `emptydir_mode = "block-encrypted"`), and for the trusted image store `/dev/trusted_store`. Both pass no `key`, so CDH generates one. CDH itself can open a block device under a `kbs://` key (`storage/volume_type/blockdevice`), but no request the Kata agent sends at this version names one. A KBS-keyed persistent volume through CDH would need a Kata agent change, or a container that calls CDH's socket, which the baseline refuses (no mount of `/run/confidential-containers`, see `tests/cdh_policy.rs`).

So persistent volumes have one path, Option A, and scratch volumes have one, Option B. Neither generator offers a second way to make the same kind of volume.

If a later Kata lets a pod name a key for a CDH mount, that key is `kbs:///<app>/key/volume.<name>`. The contract below makes it the same 32 bytes as Option A's `volume.<name>`, because both are the App's derived key for that purpose. A volume then keeps its key when it moves from one path to the other. Its on-disk format does not carry over: `alpha-volume` labels its LUKS2 header, and CDH formats with dm-integrity. Moving a volume between the paths is a copy.

## The agent policy (both options)

The baseline (`alpha_core::coco::policy::verify`) accepts a container storage only if it is in TD memory (`ephemeral`, tmpfs) or encrypted in the guest: driver options exactly `["encryption_key=ephemeral", "create_filesystem"]` and ext4. It also requires `emptydir_type: block-encrypted`. So a host that serves a scratch volume through shared-fs, or as a plain block device, is refused, and genpolicy settings that would write such a policy are refused too. Option A's claim is a `volumeDevice` of the privileged `alpha-volume-*` container, not a storage. `tests/cdh_policy.rs` shows the refusals: the device without CDH's encryption option, with another key option, mounted from a host directory, or mounted from somewhere other than its own device.

## Option B: the KBS, encrypted images and sealed secrets

Option B's key broker is **Trustee's KBS** (v0.21.0, KBS + Attestation Service + RVPS in the verifier pool), fed from alpha-kms. An App opts in, and only then does its init-data carry the guest components' configuration:

- `wrap`: the compose says `x-alphacompute-kbs: true`, and the adapter passes `--kbs-url` and `--kbs-cert`. A compose that opts in without them is refused.
- `render`: `--kbs-url https://<host>[:<port>]` and `--kbs-cert <pem>`, together or not at all.

The init-data then has two more entries, which the Kata agent writes to `/run/confidential-containers/initdata/` and starts the attestation agent (AA) and CDH with (`alpha_core::coco::kbs`):

```toml
"aa.toml" = '''
[token_configs.kbs]
url = "https://kbs.example:8080"
cert = """
-----BEGIN CERTIFICATE-----
...
"""
tee_key_algorithm = "ECDH-ES+A256KW-P256"
'''
"cdh.toml" = '''
[kbc]
name = "cc_kbc"
url = "https://kbs.example:8080"
kbs_cert = """
-----BEGIN CERTIFICATE-----
...
"""
'''
```

These are the only settings written. `cdh.toml` has no `[image]` section, so guest pull keeps the configuration it has without one, and no `credentials`. Sealed-secret signature checks stay on. `aa.toml` changes nothing but the KBS token configuration.

**Measured.** Both entries are part of the init-data, so they are in MRCONFIGID and in the Revision v2's `initdata_sha256`. A host that points the guest at its own KBS, or swaps the certificate, boots a TD whose MRCONFIGID no Revision names. The Revision v2 also states them, so the KMS, `alpha verify` and the signer page can show them without the init-data:

```json
"kbs": {"cert_spki_sha256": "sha256:<SHA-256 of the certificate's SubjectPublicKeyInfo>", "url": "https://kbs.example:8080"}
```

The section is present exactly when both entries are. `InitData::revision` refuses init-data with only one of them, with either written in any other form (another key, a comment, other whitespace, a second KBS), or with an entry other than `alpha.json`, `policy.rego`, `aa.toml` and `cdh.toml`. A Revision without Option B has no `kbs` section, so its bytes and hash are unchanged.

**Encrypted images.** The pod spec, policy and init-data are those of any image. The image is pinned by digest, and CDH pulls it in the guest and unwraps each layer key with the key-encryption key its annotation names (`kid`). That KEK must be `kbs:///<app>/image-key/<name>` with `provider` `kbs`. genpolicy 4.1.0 reads only gzip layers, so for an encrypted image it cannot read `/etc/passwd`. Give such a service a numeric `user`.

**Sealed secrets.** A literal environment value `sealed.<header>.<payload>.<signature>` (guest-components' `secret` tool). The Kata agent has CDH unseal it before the container starts. The generator accepts one only with the KBS, and only of this form:

- header: exactly `{"alg": "ES256", "kid": "kbs:///<app>/sealed-secret-key/<name>"}`;
- payload: exactly `{"version": "0.1.0", "type": "vault", "name": "kbs:///<app>/secret/<name>", "provider": "kbs", "provider_settings": {}, "annotations": {}}`;
- a 64-byte signature, which CDH verifies against that key.

Envelope secrets and other KMS providers are refused, since they would have CDH contact a KMS other than the KBS. The policy pins the sealed value like any other variable, and the generator checks that it does.

A sealed value is not secret: anyone who reads the policy can copy it. genpolicy's own output would let the host set `HOSTNAME` to any value (its rules accept anything for `$(host-name)`, and its `$(dns_label)` pattern accepts dots). A host could then put the App's sealed value in `HOSTNAME` and have the agent unseal the Secret into a container that was never given it. `tests/cdh_policy.rs` (`genpolicys_policy_alone_lets_…`) shows this. The generators close it in two ways:

- they rewrite genpolicy's `HOSTNAME=$(host-name)` to `HOSTNAME=$(sandbox-name)`, which the rules match against the policy's sandbox-name pattern;
- the `50-alpha-hostname.json` settings drop-in narrows the host-settable `HOSTNAME` to one lowercase DNS label.

The baseline refuses any policy that still lists `$(host-name)`, `$(node-name)` or `$(pod-uid)`, or that admits genpolicy's `HOSTNAME` pattern.

## The resource contract with Trustee's KBS

The generator writes resource URIs, and Trustee's KBS releases them. Both sides hold to this layout (`alpha_core::coco::kbs::Resource`):

```
kbs:///<repository>/<type>/<tag>
```

| Part | Value |
|---|---|
| repository | the App id of the pod asking, canonical lowercase hyphenated form. No `default`, no other App's id. |
| type | `secret`, `key`, `image-key` or `sealed-secret-key`. Nothing else. |
| tag | for `key`, a key purpose in the KMS's alphabet (`[a-z0-9][a-z0-9._-]{0,63}`; `.` for `:`, so `volume.<name>`, never `volume:<name>`). For the other types, a Secret name (`[a-z0-9][a-z0-9._-]{0,100}`). Never `/` or `:`. |

| Type | Released value | Used by |
|---|---|---|
| `secret/<name>` | the organization's tenant-signed Secret `<name>`, if its signed document lists the App | a sealed secret's `name` (the unsealed value) |
| `key/<purpose>` | the App's derived key for `<purpose>`, 32 bytes, the same as `POST /v1/keys/derive` returns to the App | storage keys (`volume.<name>`, see above) |
| `image-key/<name>` | the tenant-provided key-encryption key `<name>`, 32 raw bytes (A256GCM key wrap) | an encrypted image's layer annotations (`kid`) |
| `sealed-secret-key/<name>` | the tenant's P-256 public JWK `<name>` | a sealed secret's `kid` (signature check) |

What the server side must hold to, for the security review of the Trustee feed:

- A resource is released only to a pod whose attested init-data's Revision v2 is registered, unrevoked and validly signed for the App in the repository. Trustee must check MRCONFIGID against the init-data the AA sends, and that Revision's App against `<repository>`. Any other repository, type or tag is not found.
- `key/*` values come from alpha-kms's derivation, never from a store an operator can write. `secret/*`, `image-key/*` and `sealed-secret-key/*` come only from tenant-signed documents.
- Resources are sealed to the TEE key in the attestation (`tee_key_algorithm = "ECDH-ES+A256KW-P256"`).

## What is fail-closed pending G0

- *ponytail: G0*: the guest components on the NVIDIA guest image read `aa.toml` and `cdh.toml` from the init-data as Kata 4.1.0's `initdata.rs` writes them, and CDH unseals, decrypts images and formats the scratch device on a B300 pod. Until then, an opted-in pod's AA or CDH fails to start or fetch, and the pod does not start.
- *ponytail: G0*: the runtime classes' `emptydir_mode` is `block-encrypted` on our nodes (kata 4.1.0's CoCo default), and the size Kata gives the device. Under any other mode the policy refuses the scratch volume.
- *ponytail: G0*: the `HOSTNAME` containerd 2.3.x sets is the full pod name. Under a pod name over 63 characters, or any other value, every container is refused.
- *ponytail: G0*: TLS from the guest's KBS client (reqwest 0.13, rustls) to Trustee's KBS listener with the certificate given.

## For security sign-off

- **TLS roots.** The guest's KBS client adds `--kbs-cert` as a TLS root (`kbs_protocol::KbsClientBuilder::add_kbs_cert`) and does not turn off the built-in roots. So a publicly trusted certificate for the KBS hostname may also be accepted. Whoever controls that name's DNS and can get such a certificate could stand up a KBS of their own. That KBS cannot open a tenant Secret. It could hand back values of its own choosing for sealed secrets (the sealed value pins the Secret's name and the signing key's name, not the value). To be confirmed on the guest image at G0. Until then, the KBS hostname should be one no public CA issues for, for example under `.internal`.
- The Revision names the certificate by its SPKI hash. A tenant compares it with the KBS's published certificate, the way it compares `kms_ca_spki_sha256` today.
- The `HOSTNAME` hole above is in genpolicy 4.1.0's rules (`allow_var`, "always_allowed") and affects any Kata pod whose agent can unseal. The generators close it for every pod, with or without Option B.
