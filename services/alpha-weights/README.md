# alpha-weights

Model weights at rest under the model server App's own key. The key is derived by the KMS for purpose `weights` (`GET /v1/keys/weights` on the runtime socket) and released only to an attested Instance of that App — on a confidential-GPU node, after the KMS appraised its CPU and GPU evidence (PRD-02). A sealed directory is useless anywhere else, including to the host or the storage that holds it, so sealed weights can sit on an ordinary volume.

The key is the App's, the same for every Revision of the App: a new model-server Revision opens weights an older one sealed, and the seal Job (a Revision of the same App) seals for all of them. It changes only with the organization's root key. What keeps one model's weights out of another model's server is the binding below, not the key.

## Use

Run inside an Instance of the model server App, next to its `alpha-runtime`:

```sh
alpha-weights seal <model id> <source> <plain dir> <sealed dir>        # once, in the seal Job
alpha-weights open <model id> <manifest sha256> <sealed dir> <plain dir>  # in every model-server pod, before the server starts
```

`seal` prints `seal: <n> files of <model id>, manifest sha256:<hex>` and writes the same digest, in plain, to `<sealed dir>/MANIFEST.sha256`. That digest and the model id go into the model server's spec as literal arguments of `open`, so the agent policy in its init-data pins them and they are part of its Revision. `open` refuses any other model's sealing and any other sealing of the model before it writes a byte.

It waits for the runtime to attest, reads the key, and works across every core. Exit 0 on success; 1 naming the step otherwise (`usage`, `key`, a model id that is empty, longer than 256 bytes or holds a NUL, a manifest that is not the expected one, a file that does not open, a length or digest that does not match).

## Format v2

A sealing is bound to one model. Every plain file `<p>` of model `<m>` becomes `<p>.sealed`: the magic `ALPHAWT2`, a random 32-byte salt, then the file in 4 MiB chunks, each AES-256-GCM under a per-file key `HMAC-SHA256(App key, "alpha-weights/v2/file\0" ‖ <m> ‖ "\0" ‖ salt)`, with nonce = chunk counter (u64 BE) ‖ `00 00 00` ‖ last-chunk flag, and AAD = `"alpha-weights/v2\0" ‖ <m> ‖ "\0" ‖ <p>`. Every file ends with exactly one chunk flagged last (empty for an empty file). `MANIFEST.sealed`, sealed the same way under the path `MANIFEST`, holds `{version: 2, model, source, files: [{path, len, sha256}]}`.

`open <m> <digest>` opens the manifest under `<m>` (another model's does not open), compares the SHA-256 of its plain bytes with `<digest>` (an older or other sealing of `<m>` does not match), checks its model, then writes exactly the files it lists, each through a `.partial` name renamed into place, mode 0444, only after its length and digest verified. A truncated, extended, reordered, renamed, swapped or missing file refuses; a manifest path that is absolute or climbs with `..` refuses before any file is opened.

The manifest digest names the content, not the salts: the same checkpoint sealed twice gives the same digest, and anyone holding the published checkpoint can compute it from the file list, lengths and SHA-256s.

`seal` reads every regular file under the plain directory, following file symlinks (a Hugging Face snapshot is made of them) but not directory symlinks, and refuses a plain directory that already holds `MANIFEST`, `MANIFEST.sha256` or a `*.sealed` file.

**What this leaves open:** the opened weights live in the pod VM's memory (`emptyDir` with `medium: Memory`), encrypted by TDX but readable by anything in the pod VM, which the agent policy confines to the Revision's own containers. Nothing here hides which files exist or their sealed sizes. Who may add a model and own its key (Q17) is decided outside this tool.

## Tests

`cargo test -p alpha-weights`:
- round trips at every chunk edge;
- a wrong key, model id or path, truncation, extension and a flipped byte refusing;
- two chunks swapped refusing;
- a directory round trip under its manifest digest, landing read-only, with the same digest when the same weights are sealed again;
- another model's sealing refusing under the expected digest, and an older sealing of the same model refusing before any file is written;
- a swapped or missing file refusing without leaving a final name;
- escaping paths refused by the path check, and a correctly sealed manifest that names `../escaped` refused before any file is written.
