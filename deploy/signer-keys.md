# The release signers' keys

Three release signers hold one Ed25519 key each ([Release keys](README.md#release-keys)), and a
document needs two of them. Each signer generates their key on their own offline machine, with
another signer as witness, and the ceremony has a written record. A shared machine would see
every key, so one compromised machine would satisfy the threshold alone: no two keys ever touch
the same machine.

## Before the ceremony

- **Each signer's offline machine.** A laptop the signer controls, with a fresh install of a
  Linux release whose image checksum was verified, full-disk encryption, the wireless cards
  disabled in firmware or removed and no network cable. It stays offline from now on: it is
  also where that signer signs documents later.
- **The `alpha` binary.** The binary that generates and later decrypts every key must be the
  reviewed source, not whatever an online build host produced. Two signers each build it on an
  online machine of their own, from the same commit of `main`, in the pinned image the release
  builds `alpha-runtime` in, which fixes the toolchain and the build paths. The production build
  refuses the placeholder key set, so this is the dev build; `keygen` is the same code in both
  and reads no release key.

  ```sh
  git rev-parse HEAD
  mkdir -p out
  docker run --rm --platform linux/amd64 -e RUSTUP_TOOLCHAIN=1.95.0 -e CARGO_PROFILE_RELEASE_STRIP=true \
    -v "$PWD":/src:ro -v "$PWD/out":/out -w /src \
    rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 \
    sh -c 'cargo build --release --locked -p alpha-cli --features dev --target-dir /tmp/target &&
      cp /tmp/target/release/alpha /out/alpha'
  sha256sum out/alpha
  ```

  The two commits and the two SHA-256s are equal, or nobody carries a binary offline until the
  difference is explained. Both values go in the record, and each signer copies the binary
  from one of the two builds to a new USB drive and `sha256sum`s it again on their own offline
  machine before running it.
- **Per signer:** two new USB drives, encrypted with a passphrase of their own (LUKS or the
  equivalent), and an envelope. One more plain USB drive for the public key.

## Each signer, on their own machine, with a witness

1. Generate the key. Only the signer sees the passphrase; `alpha` asks for it twice.

   ```sh
   alpha keygen --admin --out release.key
   ```

   It prints `public_key`: the key's SubjectPublicKeyInfo in base64url.
2. Turn it into the line `prod.pub` takes, the raw 32-byte key in hex. The command refuses
   anything but an Ed25519 SubjectPublicKeyInfo.

   ```sh
   KEY='PASTE_PUBLIC_KEY'   # the public_key value keygen printed
   python3 -c 'import base64,sys; d=base64.urlsafe_b64decode(sys.argv[1]+"=="); assert len(d)==44 and d[:12].hex()=="302a300506032b6570032100"; print(d[12:].hex())' "$KEY"
   ```

   Write that line to the plain drive and in the record by hand. The signer and the witness read
   it back against the screen.
3. Copy `release.key` to both encrypted drives and `cmp` each copy with the original, then
   delete the original from the offline machine (`shred -u release.key`).
4. The signer writes the passphrase on a card, seals it in the envelope and signs across the
   seal. The two drives go to two different places, and the envelope is kept apart from both.

## What never leaves the signer

The key file exists only on the signer's two encrypted drives and, while a document is being
signed, on the signer's own offline machine. It never touches an online machine, another
signer's machine, a cloud drive, a password manager or a backup that syncs. The passphrase
exists only in the signer's memory and in the sealed envelope, and is never typed with anyone
watching the keyboard or a camera in the room. Only the hex public key leaves the ceremony.

## The key set into `prod.pub`

On an online machine, one signer opens a pull request against `main` that replaces
`crates/alpha-channel/release-keys/prod.pub` with the three lines from the plain drives, nothing
else in the file. Each of the other two signers approves only after checking the file at the
pull request's head against all three keys of the record, typed from the record, not copied
from the diff:

```sh
printf '%s\n' RECORDED_KEY_1 RECORDED_KEY_2 RECORDED_KEY_3 | sort |
  diff - <(sort crates/alpha-channel/release-keys/prod.pub) && echo "the three recorded keys"
```

The build alone is not enough: it accepts any two or more distinct keys, so a file holding only
the two approvers' keys would build and give them the whole threshold without the third signer.
Before it merges, one approver checks that the production `alpha` builds: the `docker run`
command in [Before the ceremony](#before-the-ceremony) without `--features dev`.

After the merge, the same two signers build the production `alpha` at the merged commit the
same way and compare the SHA-256s; that binary replaces the dev build on every signer's offline
machine, checked there with `sha256sum`. The dev build only signs for the dev set.

The record keeps the commits, the binaries' SHA-256s, the three hex keys with the signer of
each, and where each key's drives and envelope are kept. It contains no passphrase. A lost key
is a planned rotation of the set; two lost keys mean a new genesis.
