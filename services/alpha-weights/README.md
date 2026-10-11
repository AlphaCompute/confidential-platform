# alpha-weights

Model weights at rest under the model server App's own key. The key is derived by the KMS for purpose `weights` (`GET /v1/keys/weights` on the runtime socket) and released only to an attested Instance of that App — on a confidential-GPU node, after the KMS appraised its CPU and GPU evidence (PRD-02). A sealed directory is useless anywhere else, including to the host or the storage that holds it, so sealed weights can sit on an ordinary volume.

The key is the App's, the same for every Revision of the App: a new model-server Revision opens weights an older one sealed, and the seal Job (a Revision of the same App) seals for all of them. It changes only with the organization's root key.

## Use

Run inside an Instance of the model server App, next to its `alpha-runtime`:

```sh
alpha-weights seal <plain dir> <sealed dir>   # once, in the seal Job
alpha-weights open <sealed dir> <plain dir>   # in every model-server pod, before the server starts
```

It waits for the runtime to attest, reads the key, and works across every core. Exit 0 on success; 1 naming the step otherwise (`usage`, `key`, a file that does not open, a length or digest that does not match).

## Format v1

Every plain file `<p>` becomes `<p>.sealed`: the magic `ALPHAWT1`, a random 32-byte salt, then the file in 4 MiB chunks, each AES-256-GCM under a per-file key `HMAC-SHA256(App key, "alpha-weights/v1/file\0" ‖ salt)`, with nonce = chunk counter (u64 BE) ‖ `00 00 00` ‖ last-chunk flag, and AAD = `"alpha-weights/v1\0" ‖ <p>`. Every file ends with exactly one chunk flagged last (empty for an empty file). `MANIFEST.sealed`, sealed the same way under the path `MANIFEST`, lists every file's path, length and SHA-256.

`open` writes exactly the files the manifest lists, each through a `.partial` name renamed into place, mode 0444, only after its length and digest verified. A truncated, extended, reordered, renamed, swapped or missing file refuses; a manifest path that is absolute or climbs with `..` refuses.

`seal` reads every regular file under the plain directory, following file symlinks (a Hugging Face snapshot is made of them) but not directory symlinks, and refuses a plain directory that already holds `MANIFEST` or a `*.sealed` file.

**What this leaves open:** the opened weights live in the pod VM's memory (`emptyDir` with `medium: Memory`), encrypted by TDX but readable by anything in the pod VM, which the agent policy confines to the Revision's own containers. Nothing here hides which files exist or their sealed sizes.

## Tests

`cargo test -p alpha-weights` — round trips at every chunk edge, a wrong key or path, truncation, extension and a flipped byte refusing, a directory round trip landing read-only, a swapped or missing file refusing without leaving a final name, and escaping manifest paths.
