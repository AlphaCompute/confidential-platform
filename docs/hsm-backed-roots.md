# HSM-backed Alpha roots in our own Fortanix DSM (PRD-06 I3)

PRD-06 I3: "AlphaCompute's release-signing key, and a wrap of the KMS root key, are held in an
on-prem DSM we control, alongside the custodian shares. Custodian X-Wing shares stay as they
are." Both parts are optional, and both ship disabled: nothing changes without the flags and
variables below. PRD-06 schedules I3 after Dec 1.

The DSM here is AlphaCompute's own. It is not a customer's DSM (that is I1,
`fortanix-dsm-keys.md`), and it never holds tenant keys.

## The client (`alpha_dsm::own`)

`OwnDsm` talks to our DSM with a DSM App's API key. Fortanix documents this as `POST
/sys/v1/session/auth` with `Authorization: Basic <API key>`, then the bearer token
(support.fortanix.com, "App Authentication with an API Key"). It makes three calls from DSM's
REST reference:

| Call | Use | Body |
|---|---|---|
| `POST /crypto/v1/sign` | release signing | `{key, hash_alg: "SHA512", data}` |
| `POST /crypto/v1/encrypt` | root co-factor | `{key, alg: "AES", mode: "GCM", plain, ad, tag_len: 128}` → `{kid, cipher, iv, tag}` |
| `POST /crypto/v1/decrypt` | root co-factor | `{key, alg: "AES", mode: "GCM", cipher, iv, tag, ad, tag_len: 128}` → `{plain}` |

Byte fields are standard base64. A token DSM stops honouring is replaced, and the call retried
once.

Transport:

- TLS 1.3 with `X25519MLKEM768` only, unless the config says `"key_exchange":
  "classical-allowed"` (F6).
- Only the configured `ca_pem` is trusted.
- No proxy and no redirect.

The config (`OwnDsmConfig`) is `{endpoint, ca_pem, key: {kid} | {name}, key_exchange?}`. It holds
no secret, and the API key is always passed separately.

## Release signing: `alpha sign --release-key-dsm`

```
alpha sign --release-key-dsm release-dsm.json --dsm-api-key-file api.key document.json
```

`release-dsm.json` is `{"dsm": {endpoint, ca_pem, key}, "public_key": "<Ed25519, base64url>"}`.
`alpha sign` then:

1. checks that the document is a platform document, as with `--release-key`;
2. has DSM sign the same 32-byte digest a local key signs (`signing_digest("alphacompute/platform/v1", document)`);
3. checks the signature under `public_key` with `verify_strict`;
4. verifies the artifact as every reader does.

Only then does it print the artifact. A DSM that signs with another key, another algorithm or
another request shape therefore yields nothing. Ed25519 is deterministic, so the artifact is
byte for byte the one the same key held locally would sign (tested). `alpha sign --check` and
the KMS read it unchanged.

**Ed25519 on DSM.** DSM's algorithm table lists EdDSA over Ed25519 ("standard", with SHA-512)
and DSM's sign reference gives no Ed25519 example. The request shape (`data` with
`hash_alg: SHA512`) is therefore confirmed against our DSM at the first ceremony. It is marked
`ponytail` in `OwnDsm::sign`, and it fails closed if it is wrong.

If DSM cannot hold an Ed25519 signing key, the release key stays a key file, and moving the
release format to another algorithm is a separate decision. Every reader pins Ed25519: KMS
nodes, runtimes, the signer page and `alpha`.

## The KMS root: a DSM co-factor, in addition to the custodians

Today genesis draws a random root KEK and splits it 2-of-3 among the custodians, sealed to their
X-Wing keys. The two intermediates (`tenant-kek-root`, `ca`) are wrapped under that root.

With `ALPHACOMPUTE_KMS_ROOT_DSM` in the node's measured configuration
(`OwnDsmConfig` naming an AES-256 key with ENCRYPT and DECRYPT), the bootstrap does more:

1. `alpha bootstrap --root-dsm-api-key-file api.key` puts the DSM App's API key in the bootstrap
   body, which is sealed to the attested node only.
2. The node splits the root among the custodians exactly as before.
3. It draws a 32-byte co-factor, has DSM encrypt it under the AES key (with associated data
   `alphacompute/kms-root-cofactor/v1`), and decrypts it once to prove DSM can give it back
   before storing anything.
4. It wraps the intermediates under `HKDF-SHA256(salt = "alphacompute/kms-root-cofactor/v1",
   root ‖ co-factor)` instead of under the root.
5. In the same transaction it stores `root_cofactor`:
   - the DSM endpoint and key;
   - the API key, AES-GCM under the custodians' root;
   - DSM's ciphertext of the co-factor.

An unseal then needs both halves:

- two custodian shares combine to the root;
- the root unwraps the API key;
- DSM decrypts the co-factor;
- the HKDF gives the KEK that unwraps the intermediates.

Any mismatch keeps the node sealed and drops the shares it was given:

- the database's root has a co-factor but the node has no `ALPHACOMPUTE_KMS_ROOT_DSM`;
- the node names another DSM or key;
- the node expects a co-factor the root was bootstrapped without;
- DSM refuses or is unreachable.

### What this buys, and what it does not

**What it buys:**

- **Never instead of the custodians.** DSM alone opens nothing. The API key and every
  intermediate are under the custodians' root, and DSM holds only the co-factor.
- **Hardware custody and a kill switch.** The co-factor's key never leaves our HSM. Disabling
  that key or the DSM App stops every unseal, so the custodians cannot bring the KMS back
  without our DSM either. DSM logs every decryption.
- **A copied database with two shares is not enough**, unless the copier can also reach our
  on-prem DSM with the stored API key.

**What it does not buy:**

- **Not attestation-bound.** Whoever holds two shares and the database can unwrap the API key
  and ask DSM. DSM decrypts for the API key, not for an attested KMS TD. Binding the decryption
  to the TD's attestation needs DSM to trust an attestation (Fortanix's F8), and is the next
  step if we want it.
- **Fixed at genesis.** A KMS bootstrapped without a co-factor cannot add one later, and one
  bootstrapped with it cannot drop it. Either change needs a re-wrap ceremony, which is not
  built.
- **Joining is unchanged.** A node joining a serving node receives the intermediates from it
  and never asks DSM.

### Separation of duties

- DSM administrators (who can disable the key) must not be custodians.
- Rafay and infrastructure admins hold no DSM role (PRD-06).
- The API key file is handed to the bootstrap operator and destroyed after genesis. Its only
  copy is then inside the database, under the custodians' root.

## Tests

- `alpha-dsm`:
  - `tests/own.rs` against the stand-in DSM (`alpha_dsm::stand_in`, feature `stand-in`):
    - GCM round trips bound to their associated data;
    - a tampered tag;
    - Ed25519 signing;
    - each key used for the other's operation;
    - a disabled key (403);
    - a wrong API key (401);
    - a DSM under another CA, never reached.
  - Config parsing.
- `alpha-cli`:
  - `sign::tests::the_release_key_in_dsm_signs_what_a_local_key_would_and_nothing_unverified`;
  - the flag rules (one release key: a file or DSM).
- `alpha-kms`:
  - `tests/cofactor.rs` (DB):
    - bootstrap with the co-factor (the audit row says so);
    - the shares alone do not unwrap `ca`;
    - the API key is not stored in the clear;
    - a second node unseals with two shares and DSM;
    - a disabled DSM key keeps a node sealed until it is re-enabled;
    - a node without the variable, or naming another key, stays sealed;
    - a node expecting a co-factor refuses a root that has none, without calling DSM.
  - `cofactor` unit tests: the KEK needs both inputs, and half-configured bootstraps are refused.
