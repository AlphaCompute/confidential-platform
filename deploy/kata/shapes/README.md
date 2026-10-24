# RTMR0 of each VM shape

`../reference-values.json` is the `kata_reference_values` list of the platform document.
The `reference-values` workflow computes the `kata-qemu-tdx` entry again from Kata 4.0.0
and fails if a value differs. The GPU entries are captured, so the workflow does not check them.

## Terms

- **VM shape**: the vCPU count and memory of the TD that Kata boots. On `kata-qemu-tdx`, Kata adds
  `default_vcpus` (1) and `default_memory` (2048 MiB) to the summed container limits of the pod.
  A pod with no limits gets 1 vCPU and 2048 MiB.
- **RTMR0**: one value for each VM shape. The KMS refuses a TD whose RTMR0 is not in the document.

## Files

- `shapes.tsv`: one VM shape on each line, in the order of the `rtmr0` list of `kata-qemu-tdx`.
  `quote` marks a shape whose value a TD quote on the B300 host gave; `computed` marks a shape
  that only `rtmr0.py` gave.
- `qemu.args`: the QEMU command line of a live `kata-qemu-tdx` pod (1 vCPU, 2048 MiB, init-data),
  one argument on each line, with the paths of the kata-static tarball.
- `capture/`: the event log (`acpi_tables_data_CCEL`), the SMBIOS table (`dmi_tables_DMI`) and
  the PCI configuration space (`pci.txt`) of one TD of the class on the B300 host.
- `rtmr0.py`: computes RTMR0 for each line of `shapes.tsv`.

## Method

RTMR0 has 18 events. 13 events do not change with the shape, and `rtmr0.py` copies them from the
captured log. 5 events change: the TD HOB, the three ACPI blobs and SMBIOS.

1. `rtmr0.py` sets `-m`, the `dimm1` size, `-smp` and the virtio-net vectors in `qemu.args`, as
   Kata does. It removes TDX and sets `smm=off,pic=off`, as QEMU's TDX code does.
2. QEMU boots on a 64 KiB stub BIOS. The stub writes the PCI state that TDVF leaves before it
   reads the ACPI tables. Then the stub copies the fw_cfg files into RAM. QEMU makes the ACPI
   tables from that PCI state.
3. `rtmr0.py` hashes the three ACPI blobs, makes the TD HOB from the RAM size as QEMU's
   `tdvf-hob.c` does, and makes the SMBIOS table as SmbiosMeasurementDxe hashes it. The Type 4
   processor ID and the Type 0 structure come from the captured table.

Run it on Linux, from the repository root. The user needs access to `/dev/kvm` and to
`/dev/vhost-vsock` (`modprobe vhost_vsock`). QEMU reserves the guest memory of each shape, so set
`vm.overcommit_memory=1` on a host with less memory than the largest shape.

```sh
python3 -I deploy/kata/shapes/rtmr0.py OPT_KATA --check deploy/kata/reference-values.json
```

`OPT_KATA` is `opt/kata` of the extracted kata-static tarball (the workflow names the files).

## Add a shape

1. Add the VM shape to `shapes.tsv` with `computed`.
2. Run `rtmr0.py` without `--check`. Add the value at the same position in the `rtmr0` list.
3. The next release lists the value. Do not offer the shape before the signed document lists it.

## Capture again

Capture again when OVMF, QEMU, the device list of the class or the host CPU model changes.
Boot one `kata-qemu-tdx` pod with no limits, init-data and a privileged container. In the pod, copy
`/sys/firmware/acpi/tables/data/CCEL` and `/sys/firmware/dmi/tables/DMI` to `capture/`. Write
the PCI configuration space to `capture/pci.txt`:

```sh
for d in /sys/bus/pci/devices/*; do
  echo "PCI ${d##*/} $(head -c 256 "$d/config" | od -An -tx1 -v | tr -d ' \n')"
done
```

Update `qemu.args` from the `/proc/<pid>/cmdline` of the pod's QEMU on the host. Then confirm
three or more shapes of the grid with a TD quote each, and mark them `quote`.

## GPU classes

The workflow cannot compute RTMR0 of `kata-qemu-nvidia-gpu-tdx`. Kata puts one PCIe expander and
one guest NUMA node for each host NUMA node that has an allocated GPU. The ACPI tables contain the
windows that TDVF assigns to the GPU BARs. Thus each GPU layout needs its own capture. The GPU
entries of `../reference-values.json` come from TD quotes of the 1-GPU and 8-GPU pods.
