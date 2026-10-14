# Kata TD measurement vectors

Read by `crates/alpha-cli/src/coco/measure.rs`.

- `kata-qemu-tdx.cmdline`, `kata-qemu-nvidia-gpu-tdx.cmdline` — the guest command lines, byte for byte as
  QEMU's `-append` and the guest's `/proc/cmdline` showed them, of the pods whose quotes gave the RTMR2 of the two
  classes in `testdata/attest/b300-kata-4.0.0/platform-document.json`. The CPU line is Kata 4.0.0's default for
  `kata-qemu-tdx` with `kernel_params = "agent.guest_components_rest_api=all"`; the GPU line is the default for
  `kata-qemu-nvidia-gpu-tdx` with that parameter appended to its `kernel_params`. Each embeds the dm-verity root
  hash of the class's rootfs from the same release (`root_hash_confidential.txt`,
  `root_hash_nvidia-gpu-confidential.txt`), so RTMR2 binds the rootfs too.
- `tdvf.bin`, `pe.bin` — a synthetic three-section TDVF image and a synthetic PE32+ image (sections out of file
  order, trailing data, a certificate table). Their expected MRTD and RTMR1 come from a separate Python
  implementation that reproduced the B300 quotes, not from this code.

## Reproducing the platform document from the release

The tarball is 1.9 GB, so no test reads it. On a machine with `curl`, `zstd` and `sha256sum`:

```sh
d=$(mktemp -d)
curl -fsSL -o "$d/kata.tar.zst" \
  https://github.com/kata-containers/kata-containers/releases/download/4.0.0/kata-static-4.0.0-amd64.tar.zst
echo "2c3b9dfeba355582b40aee462b12916c9740654d0230f696adf719d67b063a8c  $d/kata.tar.zst" | sha256sum -c -
zstd -dc "$d/kata.tar.zst" | tar -xf - -C "$d" ./opt/kata/share/ovmf/OVMF.inteltdx.fd \
  ./opt/kata/share/kata-containers/vmlinuz-6.18.35-200 \
  ./opt/kata/share/kata-containers/vmlinuz-6.18.35-200-nvidia-gpu
k=$d/opt/kata/share
alpha coco measure --firmware "$k/ovmf/OVMF.inteltdx.fd" --kernel "$k/kata-containers/vmlinuz-6.18.35-200" \
  --cmdline "$(cat testdata/coco/measure/kata-qemu-tdx.cmdline)"
alpha coco measure --firmware "$k/ovmf/OVMF.inteltdx.fd" \
  --kernel "$k/kata-containers/vmlinuz-6.18.35-200-nvidia-gpu" \
  --cmdline "$(cat testdata/coco/measure/kata-qemu-nvidia-gpu-tdx.cmdline)"
```

Both outputs equal the `mrtd`, `rtmr1` and `rtmr2` of their class in the platform document. The extracted files
are `OVMF.inteltdx.fd` sha256 `2af9e5e9…0fb0c0b6`, `vmlinuz-6.18.35-200` `f1041521…4977ea34` and
`vmlinuz-6.18.35-200-nvidia-gpu` `08064a9b…7d22a4f4`, the files the B300 pods booted.

RTMR0 is not computed: it measures the ACPI tables, the table loader and SMBIOS that Kata's QEMU generates for
each VM's vCPUs, memory and devices, and the event log holds only their digests. Its values stay captured per shape.
