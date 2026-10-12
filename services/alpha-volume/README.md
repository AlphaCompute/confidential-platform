# alpha-volume

The init container that gives a Kata confidential pod an encrypted persistent volume (PRD-02
deliverable 25, Option A). `alpha coco render --volume` and `alpha coco wrap` (a compose's
`x-alphacompute-volumes`) add it to the pod with a block-mode claim; see
`docs/coco-generator.md`.

```
alpha-volume open <name> <device> <mount dir>
```

1. Waits for `alpha-runtime` (the pod's sidecar) to attest, then reads the App's key for purpose
   `volume.<name>` from `/run/alpha/runtime.sock` (`keys/derive` at the KMS; the KMS's purpose
   alphabet has no `:`, so PRD-02's `volume:<name>` is `volume.<name>`). The key is the App's, so
   a new Revision of the App opens the same volume.
2. Reads the device's LUKS headers itself (the primary and every LUKS2 secondary offset):
   - none at all: formats LUKS2 (`aes-xts-plain64`, 512-bit key, `hmac(sha256)` integrity,
     PBKDF2 at cryptsetup's minimum since the key is 256 bits from the KMS) labelled
     `av:<name>:new`, opens it, makes ext4, relabels it `av:<name>`, mounts it;
   - a LUKS2 header labelled `av:<name>` whose one segment is that cipher and integrity: opens
     and mounts it, nothing else;
   - anything else (another volume's label, `av:<name>:new` from an interrupted format, LUKS1, a
     secondary header without its primary, another cipher): refuses before the key is offered.
3. Any failure (a key the header refuses, a filesystem that does not mount, a tool error) exits
   1 naming the step. A device with a header is never formatted, and an opened one is never
   re-made.

It mounts the filesystem on `<mount dir>`, an `emptyDir` in the TD's memory that it mounts with
`Bidirectional` propagation; the App's containers mount the same `emptyDir` with
`HostToContainer` and see the volume. It runs privileged inside the TD (device-mapper and
mount); the agent policy admits that for `alpha-volume-*` containers only, pinned by image digest
and arguments.

cryptsetup, mkfs.ext4 and mount run from fixed paths in the image (`images/volume/Dockerfile`),
with an empty environment; the key reaches cryptsetup on stdin only.

What it does not do: detect the host replaying an older copy of the whole device, or swapping in
a blank device (which this would format as new). Both lose data at most; neither discloses it.

## Tests

`cargo test -p alpha-volume` runs the decisions against fake tools and device images: a fresh
device formatted then finished, an existing one opened and never formatted (also when the key or
the mount fails), every foreign header refused with no tool run, and a failed format step leaving
the `:new` label and nothing mounted. Opening real LUKS2 volumes needs root and device-mapper; it
is a G0 check on the pinned Kata guest, with the mount propagation below.
