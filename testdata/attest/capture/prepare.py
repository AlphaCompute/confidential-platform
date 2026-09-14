#!/usr/bin/env python3
"""Writes a per-capture docker-compose.yml with the nonce and X-Wing key baked in.

usage: prepare.py <capture-dir>
The nonce is ts(8, BE unix seconds) ‖ HMAC-SHA256(nonce_key, ts)[0..24] over the test nonce key
in nonce_key.hex, the shape alpha-kms issues; the X-Wing key is derived from xwing_seed.hex by
`cargo run -p alpha-crypto --example xwing_pubkey -- <seed hex>`.
"""
import base64, hmac, hashlib, os, struct, subprocess, sys, time

here = os.path.dirname(os.path.abspath(__file__))
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
nonce_key = bytes.fromhex(open(os.path.join(here, "nonce_key.hex")).read().strip())
ts = int(time.time())
nonce = struct.pack(">Q", ts) + hmac.new(nonce_key, struct.pack(">Q", ts), hashlib.sha256).digest()[:24]
seed = open(os.path.join(here, "xwing_seed.hex")).read().strip()
xwing = subprocess.check_output(
    ["cargo", "run", "-q", "-p", "alpha-crypto", "--example", "xwing_pubkey", "--", seed],
    cwd=os.path.join(here, "../../.."),
).decode().strip()
script = base64.b64encode(open(os.path.join(here, "in-cvm.sh"), "rb").read()).decode()
compose = f"""services:
  capture:
    image: alpine:3.20
    command: sh -c "echo {script} | base64 -d > /in-cvm.sh && sh /in-cvm.sh"
    environment:
      NONCE_HEX: {nonce.hex()}
      XWING_HEX: {xwing}
    ports: ["8080:8080"]
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - /run/log/dstack:/run/log/dstack:ro
      - /sys/firmware/acpi/tables/data/CCEL:/ccel:ro
"""
open(os.path.join(out, "docker-compose.yml"), "w").write(compose)
open(os.path.join(out, "nonce.bin"), "wb").write(nonce)
print(f"nonce ts={ts} written to {out}/docker-compose.yml and nonce.bin")
