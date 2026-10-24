"""RTMR0 of a kata-qemu-tdx TD for each VM shape in shapes.tsv, computed without a TD launch.

usage: python3 -I rtmr0.py OPT_KATA [--check REFERENCE_VALUES_JSON]
  OPT_KATA: opt/kata of the extracted kata-static tarball; needs /dev/kvm.
  prints `vcpus memory_mib rtmr0` for each shape. With --check, exits 1 unless the
  kata-qemu-tdx rtmr0 list of the file equals the computed list, in the order of shapes.tsv.
See README.md.
"""
import hashlib, json, os, socket, struct, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
CLASS = "kata-qemu-tdx"
FILES = ["etc/table-loader", "etc/acpi/rsdp", "etc/acpi/tables", "etc/smbios/smbios-tables"]
BASE_SEG = 0x1000  # 0x10000, up to 0x9ffff
DONE_AT, DONE = 0x6000, 0xCAFE  # the stub writes DONE at DONE_AT when every file is in RAM
EV_ACPI, EV_TD_HOB, EV_SMBIOS = 0xA, 0x8000000B, 0x80000009
SHA384 = 0xC
FOOTER = bytes.fromhex("de82b596b21ff745baeaa366c55a082d")
META = bytes.fromhex("35657ae44a989847865e4685a7bf8ec2")


def shape_argv(argv, kata, vcpus, mem, work):
    """Kata's argv for this shape, without TDX. Kata (static sizing, flat NUMA on the CPU class)
    changes only -m, the dimm1 backend, -smp and the virtio-net vectors with the shape. TDX is
    replaced by what QEMU's TDX code forces: no SMM, no PIC. Host-fd devices are re-created
    without the fds; their PCI functions stay identical. Disk contents are not measured."""
    argv = [a.replace("/opt/kata/", kata + "/") for a in argv]
    out, i = [argv[0], "-L", f"{kata}/share/kata-qemu-tdx-experimental/qemu"], 1
    while i < len(argv):
        a = argv[i]
        v = argv[i + 1] if i + 1 < len(argv) else None
        if a in ("-qmp", "-pidfile"):
            i += 2
            continue
        if a == "-object" and v.startswith("{") and json.loads(v).get("qom-type") == "tdx-guest":
            i += 2
            continue
        if a == "-machine":
            v = v.replace(",confidential-guest-support=tdx", "") + ",smm=off,pic=off"
        elif a == "-m":
            v = f"{mem}M"
        elif a == "-smp":
            v = f"{vcpus},cores=1,threads=1"
        elif a == "-object" and v.startswith("memory-backend-ram,id=dimm1,"):
            v = f"memory-backend-ram,id=dimm1,size={mem}M"
        elif a == "-chardev":
            v = ",".join(f"path={work}/console.sock" if p.startswith("path=") else p for p in v.split(","))
        elif a == "-netdev":
            v = "hubport,id=network-0,hubid=0"
        elif a == "-device" and v.startswith("vhost-vsock-pci,"):
            v = ",".join("guest-cid=4000000123" if p.startswith("guest-cid=") else p
                         for p in v.split(",") if not p.startswith("vhostfd="))
        elif a == "-device" and v.startswith("driver=virtio-net-pci,"):
            v = ",".join(f"vectors={2 * vcpus + 2}" if p.startswith("vectors=") else p for p in v.split(","))
        elif a == "-drive":
            v = ",".join(f"file={work}/disk.img" if p.startswith("file=") else p for p in v.split(","))
        out.append(a)
        if v is not None and not a.startswith("--") and a not in ("-nodefaults", "-nographic", "-no-user-config"):
            out.append(v)
            i += 2
        else:
            i += 1
    return out


def pci_replay(dump):
    """The config writes that put a fresh QEMU into TDVF's PCI state at the ACPI fetch: PCIEXBAR,
    PMBASE, bridge bus numbers, BARs and windows, then decoding on, as OVMF's AcpiPlatformDxe
    enables it on every device. `dump` holds `PCI 0000:BB:DD.F <hex of 256 config bytes>` lines."""
    devs = {}
    for line in dump.splitlines():
        if line.startswith("PCI "):
            _, bdf, hexs = line.split()
            b, df = bdf.split(":")[1:]
            d, f = df.split(".")
            devs[(int(b, 16), int(d, 16), int(f, 16))] = bytes.fromhex(hexs)

    def addr(b, d, f, off):
        return 0x80000000 | b << 16 | d << 11 | f << 8 | off

    def dword(cfg, off):
        return struct.unpack_from("<I", cfg, off)[0]

    mch, lpc = devs[(0, 0, 0)], devs[(0, 0x1F, 0)]
    w = [(addr(0, 0, 0, 0x64), dword(mch, 0x64)), (addr(0, 0, 0, 0x60), dword(mch, 0x60))]
    # ICH9 PMBASE and ACPI_CNTL: the FADT and DSDT name the PM ports.
    w += [(addr(0, 0x1F, 0, 0x40), dword(lpc, 0x40)), (addr(0, 0x1F, 0, 0x44), dword(lpc, 0x44))]
    w += [(addr(*bdf, 0x18), dword(devs[bdf], 0x18)) for bdf in sorted(devs) if devs[bdf][0x0E] & 0x7F == 1]
    for bdf in sorted(devs):
        hdr = devs[bdf][0x0E] & 0x7F
        w += [(addr(*bdf, off), dword(devs[bdf], off)) for off in range(0x10, 0x40, 4) if not (hdr == 1 and off == 0x18)]
    w += [(addr(*bdf, 0x04), dword(devs[bdf], 0x04) & 0xFFFF | 0x3) for bdf in sorted(devs)]
    return w


def stub(entries, pci):
    """entries: [(fw_cfg key, segment, units of 256 bytes)]; pci: [(0xcf8 address, dword)] written first.
    HMP port writes do not reach fw_cfg's selector, hence real-mode code."""
    code, labels, fix = bytearray(), {}, []

    def emit(*b):
        code.extend(b)

    def jcc(op, label):
        emit(op, 0)
        fix.append((len(code) - 1, label))

    emit(0xFA, 0x31, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x70, 0xFC)  # cli; xor ax,ax; mov ss,ax; mov sp,7000; cld
    for addr, val in pci:
        emit(0xBA, 0xF8, 0x0C, 0x66, 0xB8, *struct.pack("<I", addr), 0x66, 0xEF)  # out cf8, addr
        emit(0xBA, 0xFC, 0x0C, 0x66, 0xB8, *struct.pack("<I", val), 0x66, 0xEF)   # out cfc, val
    emit(0xBE, 0x00, 0xF0)                                      # mov si,0xf000
    labels["loop"] = len(code)
    emit(0x2E, 0xAD, 0x3D, 0xFF, 0xFF)                          # cs lodsw; cmp ax,ffff
    jcc(0x74, "done")
    emit(0xBA, 0x10, 0x05, 0xEF)                                # mov dx,510; out dx,ax
    emit(0x2E, 0xAD, 0x8E, 0xC0, 0x2E, 0xAD, 0x89, 0xC3)        # es = seg; bx = units
    emit(0xBA, 0x11, 0x05)                                      # mov dx,511
    labels["inner"] = len(code)
    emit(0x31, 0xFF, 0xB9, 0x00, 0x01, 0xF3, 0x6C)              # xor di,di; mov cx,100; rep insb
    emit(0x8C, 0xC0, 0x05, 0x10, 0x00, 0x8E, 0xC0, 0x4B)        # es += 0x10; dec bx
    jcc(0x75, "inner")
    jcc(0xEB, "loop")
    labels["done"] = len(code)
    emit(0x31, 0xC0, 0x8E, 0xD8, 0xC7, 0x06, *struct.pack("<HH", DONE_AT, DONE))  # xor ax,ax; mov ds,ax; mov [DONE_AT],DONE
    emit(0xF4)
    jcc(0xEB, "done")
    for at, label in fix:
        code[at] = (labels[label] - (at + 1)) & 0xFF
    if len(code) > 0xF000:
        raise ValueError("stub code too long")
    rom = bytearray(0x10000)
    rom[:len(code)] = code
    table = b"".join(struct.pack("<HHH", *e) for e in entries) + b"\xff\xff"
    rom[0xF000:0xF000 + len(table)] = table
    rom[0xFFF0:0xFFF5] = bytes([0xEA, 0x00, 0x00, 0x00, 0xF0])  # jmp f000:0000
    return bytes(rom)


def qmp(sock):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(30)
    s.connect(sock)
    f = s.makefile("rb")

    def read():
        while True:
            m = json.loads(f.readline())
            if "event" not in m:
                return m

    def cmd(name, **args):
        s.sendall(json.dumps({"execute": name, "arguments": args}).encode() + b"\n")
        r = read()
        if "error" in r:
            raise RuntimeError(r)
        return r["return"]

    read()
    cmd("qmp_capabilities")
    return cmd


def boot(argv, entries, pci, work):
    """Low RAM after the stub ran, from 0x10000 to the end of the last entry."""
    rom, sock, mem = (os.path.join(work, n) for n in ("stub.rom", "qmp.sock", "mem.bin"))
    if os.path.exists(sock):
        os.unlink(sock)
    open(rom, "wb").write(stub(entries, pci))
    i = argv.index("-bios")
    argv = argv[:i + 1] + [rom] + argv[i + 2:] + ["-qmp", f"unix:{sock},server=on,wait=off"]
    with open(os.path.join(work, "qemu.stderr"), "a") as err:
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=err)
    try:
        for _ in range(600):
            if os.path.exists(sock) or p.poll() is not None:
                break
            time.sleep(0.05)
        if p.poll() is not None:
            sys.exit(f"qemu exited {p.returncode}: {open(os.path.join(work, 'qemu.stderr')).read()}")
        cmd = qmp(sock)
        done = os.path.join(work, "done.bin")
        for _ in range(600):
            cmd("pmemsave", val=DONE_AT, size=2, filename=done)
            if open(done, "rb").read() == struct.pack("<H", DONE):
                break
            time.sleep(0.05)
        else:
            sys.exit("the stub BIOS did not finish within 30 s")
        cmd("stop")
        end = max(seg * 16 + units * 256 for _, seg, units in entries)
        cmd("pmemsave", val=BASE_SEG * 16, size=end - BASE_SEG * 16, filename=mem)
        cmd("quit")
        p.wait(30)
    finally:
        if p.poll() is None:
            p.kill()
    return open(mem, "rb").read()


def fw_cfg_files(argv, pci, work):
    """The fw_cfg files TDVF measures. QEMU builds etc/acpi/* on the first select, from the PCI state."""
    d = boot(argv, [(0x19, BASE_SEG, 16)], pci, work)
    dirs = {}
    for i in range(int.from_bytes(d[:4], "big")):
        e = d[4 + i * 64:4 + (i + 1) * 64]
        dirs[e[8:].split(b"\0")[0].decode()] = (int.from_bytes(e[0:4], "big"), int.from_bytes(e[4:6], "big"))
    want, seg = [], BASE_SEG
    for name in FILES:
        size, key = dirs[name]
        units = (size + 255) // 256
        want.append((name, size, (key, seg, units)))
        seg += units * 16
    if seg > 0xA000:
        sys.exit("fw_cfg files do not fit below 640 KiB")
    m = boot(argv, [w[2] for w in want], pci, work)
    return {name: m[(s - BASE_SEG) * 16:(s - BASE_SEG) * 16 + size] for name, size, (_, s, _) in want}


def rtmr0_events(buf):
    """(type, data, sha384 digest) of every RTMR0 (CC MR 1) event of a TCG2 crypto-agile log."""
    esize = struct.unpack_from("<I", buf, 28)[0]
    spec = buf[32:32 + esize]
    sizes = dict(struct.unpack_from("<HH", spec, 28 + 4 * k) for k in range(struct.unpack_from("<I", spec, 24)[0]))
    out, off = [], 32 + esize
    while off + 12 <= len(buf):
        mr, et, cnt = struct.unpack_from("<III", buf, off)
        if mr == 0xFFFFFFFF or cnt == 0 or cnt > 8:
            break
        off += 12
        digests = {}
        for _ in range(cnt):
            alg = struct.unpack_from("<H", buf, off)[0]
            digests[alg] = buf[off + 2:off + 2 + sizes[alg]]
            off += 2 + sizes[alg]
        n = struct.unpack_from("<I", buf, off)[0]
        data = buf[off + 4:off + 4 + n]
        off += 4 + n
        if mr == 1:
            out.append((et, data, digests[SHA384]))
    return out


def tdvf_sections(fw):
    off = len(fw) - 32
    if fw[off - 16:off] != FOOTER:
        raise ValueError("no GUID table footer")
    tlen = struct.unpack_from("<H", fw, off - 18)[0]
    tables = fw[off - 18 - tlen:off - 18]
    o, meta = len(tables), None
    while o >= 18:
        ln = struct.unpack_from("<H", tables, o - 18)[0]
        if ln < 18 or ln > o:
            break
        if tables[o - 16:o] == META:
            meta = len(fw) - struct.unpack_from("<I", tables, o - 22)[0]
        o -= ln
    sig, _, ver, n = struct.unpack_from("<4sIII", fw, meta)
    if sig != b"TDVF" or ver != 1:
        raise ValueError("bad TDVF descriptor")
    return [dict(zip(("data_off", "raw_size", "mem_addr", "mem_size", "type", "attr"),
                     struct.unpack_from("<IIQQII", fw, meta + 16 + 32 * i))) for i in range(n)]


def td_hob(sections, memory_size):
    """The TD HOB as QEMU's tdvf-hob.c builds it."""
    ranges, base = [(False, 0, memory_size)], 0x809000
    for s in sections:
        if s["type"] in (2, 3):
            st, en = s["mem_addr"], s["mem_addr"] + s["mem_size"]
            nr = []
            for acc, a, b in ranges:
                if acc or b <= st or a >= en:
                    nr.append((acc, a, b))
                else:
                    if a < st:
                        nr.append((False, a, st))
                    if b > en:
                        nr.append((False, en, b))
            nr.append((True, st, en))
            ranges = sorted(nr, key=lambda r: r[1])
        if s["type"] == 2:
            base = s["mem_addr"]
    hob = bytearray(b"\x01\x00" + struct.pack("<H", 56) + bytes(4) + struct.pack("<I", 9) + bytes(4) + bytes(40))

    def res(rt, start, length):
        hob.extend(b"\x03\x00" + struct.pack("<H", 48) + bytes(4) + bytes(16) + bytes([rt]) + bytes(3)
                   + struct.pack("<I", 7) + struct.pack("<QQ", start, length))

    _, ls, le = ranges.pop()
    for acc, a, b in ranges:
        res(0x00 if acc else 0x07, a, b - a)
    if memory_size >= 0xB0000000:
        if ls < 0x80000000:
            res(0x07, ls, 0x80000000 - ls)
        if le > 0x80000000:
            res(0x07, 0x100000000, le - 0x80000000)
    else:
        res(0x07, ls, le - ls)
    hob[48:56] = struct.pack("<Q", base + len(hob) + 8)
    return bytes(hob)


# SMBIOS fields SmbiosMeasurementDxe blanks before it hashes (MdeModulePkg, edk2-stable202511).
# type: [(offset, size, is_string)]; None zeroes the whole formatted area.
SMBIOS_FILTER = {
    1: [(0x07, 1, True), (0x08, 16, False), (0x18, 1, False)],
    2: [(0x07, 1, True), (0x0A, 1, True)],
    3: [(0x07, 1, True), (0x08, 1, True)],
    4: [(0x20, 1, True), (0x21, 1, True), (0x22, 1, True), (0x23, 1, False), (0x24, 1, False),
        (0x25, 1, False), (0x2A, 2, False), (0x2C, 2, False), (0x2E, 2, False), (0x11, 1, False), (0x16, 2, False)],
    0x0B: None, 0x0F: None,
    0x11: [(0x18, 1, True), (0x19, 1, True), (0x1A, 1, True)],
    0x12: None,
    0x16: [(0x07, 1, True), (0x10, 2, False), (0x12, 2, False)],
    0x17: [(0x05, 2, False)],
    0x1B: [(0x0C, 2, False)],
    0x1F: None, 0x21: None,
    0x27: [(0x06, 1, True), (0x07, 1, True), (0x08, 1, True)],
}


def smbios_structures(table):
    o = 0
    while o + 4 <= len(table):
        ln = table[o + 1]
        end = table.index(b"\0\0", o + ln) + 2
        yield table[o:end]
        if table[o] == 127:
            return
        o = end


def smbios_filtered(s):
    s = bytearray(s)
    t, ln = s[0], s[1]
    if t >= 128 or (t in SMBIOS_FILTER and SMBIOS_FILTER[t] is None):
        s[4:] = bytes(len(s) - 4)
        return bytes(s)
    for off, size, is_string in SMBIOS_FILTER.get(t, []):
        if ln < off + size:
            continue
        if is_string and s[off]:
            strings = s[ln:].split(b"\0")
            i = s[off] - 1
            start = ln + sum(len(x) + 1 for x in strings[:i])
            s[start:start + len(strings[i])] = b" " * len(strings[i])
        s[off:off + size] = bytes(size)
    return bytes(s)


def smbios_measured(qemu_tables, reference_dmi):
    """QEMU's structures with the TD's CPUID in each Type 4, then the Type 0 TDVF adds and the
    end structure SmbiosDxe writes, both from the captured table."""
    ref = list(smbios_structures(reference_dmi))
    cpuid = next(s for s in ref if s[0] == 4)[8:16]
    type0 = next(s for s in ref if s[0] == 0)
    end = next(s for s in ref if s[0] == 127)
    own = [s for s in smbios_structures(qemu_tables) if s[0] != 127]
    if any(s[0] == 0 for s in own):
        raise ValueError("QEMU emitted a Type 0; TDVF would not add its own")
    own = [s[:8] + cpuid + s[16:] if s[0] == 4 else s for s in own]
    return b"".join(smbios_filtered(s) for s in own + [type0, end])


def rtmr0(fw, ccel, dmi, mem_mib, files):
    acpi = [hashlib.sha384(files[n]).digest() for n in ("etc/table-loader", "etc/acpi/rsdp", "etc/acpi/tables")]
    smb = hashlib.sha384(smbios_measured(files["etc/smbios/smbios-tables"], dmi)).digest()
    hob = hashlib.sha384(td_hob(tdvf_sections(fw), mem_mib << 20)).digest()
    events = rtmr0_events(ccel)
    if sum(et == EV_ACPI and data.startswith(b"ACPI DATA") for et, data, _ in events) != 3:
        raise ValueError("captured log does not have exactly three ACPI DATA events")
    reg, acpi_i = bytes(48), 0
    for et, data, d in events:
        if et == EV_TD_HOB:
            d = hob
        elif et == EV_ACPI and data.startswith(b"ACPI DATA"):
            d, acpi_i = acpi[acpi_i], acpi_i + 1
        elif et == EV_SMBIOS:
            d = smb
        reg = hashlib.sha384(reg + d).digest()
    return reg


def main():
    kata = os.path.abspath(sys.argv[1])
    check = sys.argv[3] if sys.argv[2:3] == ["--check"] else None
    read = lambda n: open(os.path.join(HERE, n), "rb").read()
    template = read("qemu.args").decode().splitlines()
    ccel, dmi = read("capture/acpi_tables_data_CCEL"), read("capture/dmi_tables_DMI")
    pci = pci_replay(read("capture/pci.txt").decode())
    fw = open(os.path.join(kata, "share/ovmf/OVMF.inteltdx.fd"), "rb").read()
    shapes = [l.split("\t") for l in read("shapes.tsv").decode().splitlines() if l and not l.startswith("#")]
    got = []
    with tempfile.TemporaryDirectory() as work:
        open(os.path.join(work, "disk.img"), "wb").write(bytes(4096))
        for vcpus, mem, _ in shapes:
            files = fw_cfg_files(shape_argv(template, kata, int(vcpus), int(mem), work), pci, work)
            got.append("sha384:" + rtmr0(fw, ccel, dmi, int(mem), files).hex())
            print(vcpus, mem, got[-1], flush=True)
    if check is None:
        return
    want = [e for e in json.load(open(check)) if e["runtime_class"] == CLASS and not e["gpu"]]
    if len(want) != 1:
        sys.exit(f"{check}: not exactly one {CLASS} entry")
    want = want[0]["rtmr0"]
    if len(want) != len(shapes):
        sys.exit(f"{check}: {len(want)} {CLASS} rtmr0 values for {len(shapes)} shapes")
    bad = [(s, w, g) for s, w, g in zip(shapes, want, got) if w != g]
    for (vcpus, mem, source), w, g in bad:
        print(f"{vcpus} vCPU {mem} MiB ({source}): {check} has {w}, computed {g}", file=sys.stderr)
    if bad:
        sys.exit(1)


if __name__ == "__main__":
    main()
