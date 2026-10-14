# The release signers' keys

Three release signers hold one Ed25519 key each ([Release keys](README.md#release-keys)). The
keys are generated on one offline machine, one signer at a time, each with another signer as
witness, and the ceremony has a written record.

## Before the ceremony

- **The offline machine.** A laptop with a fresh install of a Linux release whose image checksum
  was verified, full-disk encryption, the wireless cards disabled in firmware or removed and no
  network cable. It stays offline from now on: it is also where later documents are signed.
- **The `alpha` binary.** Build it on an online machine of the same Linux release from a commit
  of `main`. The production build refuses the placeholder key set, so this is the dev build;
  `keygen` is the same code in both and reads no release key.

  ```sh
  git rev-parse HEAD
  cargo build --release --locked -p alpha-cli --features dev
  sha256sum target/release/alpha
  ```

  Write both values in the record and copy the binary to a new USB drive. On the offline machine
  `sha256sum` it again before running it.
- **Per signer:** two new USB drives, encrypted with a passphrase of their own (LUKS or the
  equivalent), and an envelope. One more plain USB drive for the public keys.

## Each signer, with a witness

1. Generate the key. Only the signer sees the passphrase; `alpha` asks for it twice.

   ```sh
   alpha keygen --admin --out release-<n>.key
   ```

   It prints `public_key`: the key's SubjectPublicKeyInfo in base64url.
2. Turn it into the line `prod.pub` takes, the raw 32-byte key in hex. The command refuses
   anything but an Ed25519 SubjectPublicKeyInfo.

   ```sh
   python3 -c 'import base64,sys; d=base64.urlsafe_b64decode(sys.argv[1]+"=="); assert len(d)==44 and d[:12].hex()=="302a300506032b6570032100"; print(d[12:].hex())' <public_key>
   ```

   Append that line to `prod.pub` on the plain drive, and write it in the record by hand. The
   signer and the witness read it back against the screen.
3. Copy `release-<n>.key` to both encrypted drives and `cmp` each copy with the original, then
   delete the original from the offline machine (`shred -u release-<n>.key`).
4. The signer writes the passphrase on a card, seals it in the envelope and signs across the
   seal. The two drives go to two different places, and the envelope is kept apart from both.

## What never leaves the signer

The key file exists only on the signer's two encrypted drives and, while a document is being
signed, on the offline machine. It never touches an online machine, a cloud drive, a password
manager or a backup that syncs. The passphrase exists only in the signer's memory and in the
sealed envelope, and is never typed with anyone watching the keyboard or a camera in the room.
Only the hex public key leaves the ceremony.

## The key set into `prod.pub`

On an online machine, one signer opens a pull request against `main` that replaces
`crates/alpha-channel/release-keys/prod.pub` with the three lines from the plain drive, nothing
else in the file. Each of the other two signers checks that the file in the diff holds their
line exactly as written in the record and approves. Before it merges, the production `alpha` now
builds:

```sh
cargo build --release --locked -p alpha-cli
```

After the merge, that production `alpha`, built at the merged commit, replaces the dev build on
the offline machine, checked there with `sha256sum`: the dev build only signs for the dev set.

The record keeps the commit, the binary's SHA-256, the three hex keys with the signer of each,
and where each key's drives and envelope are kept. It contains no passphrase. A lost key is a
planned rotation of the set; two lost keys mean a new genesis.
