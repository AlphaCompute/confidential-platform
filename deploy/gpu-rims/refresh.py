#!/usr/bin/env python3
"""Builds the local GPU verifier's RIM cache (`alphacompute-gpu-rim-cache/1`), offline, for
`ALPHACOMPUTE_GPU_RIM_CACHE` (docs/local-gpu-verifier.md, "RIM cache").

    refresh.py --rim-service <url> --ocsp <url> --rim <id> [--rim <id> ...] \
               [--device-chain <pem> ...] --out <cache.json>

For every RIM ID (the ones the release pins in gpu_policy.local.rims): fetch it from the RIM
service, turn it into a canonical entry (testdata/gpu/tools/canonicalize.py, which checks the
signature and digest), and fetch an OCSP response for every certificate of its signing chain but
the root. For every device chain given (a GPU's evidence `certificate`, PEM), fetch OCSP for each
certificate between the leaf and the root. Write the file atomically.

Nothing here is trusted by the KMS: it verifies every RIM signature, chain, pin and OCSP response
itself, with the roots and maximum age the release-signed gpu_policy sets. A cache older than that
maximum age refuses every GPU, so run this at least daily. No URL is built in; NVIDIA's services
observed on 2026-10-12 were https://rim.attestation.nvidia.com and https://ocsp.ndis.nvidia.com.

Requires lxml and cryptography.
"""

import argparse
import base64
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

FORMAT = "alphacompute-gpu-rim-cache/1"
MAX_REPLY = 4 * 1024 * 1024
TOOLS = pathlib.Path(__file__).resolve().parents[2] / "testdata" / "gpu" / "tools"


def canonicalizer():
    # No __pycache__ under testdata/, whose files are in CI's SHA-256 manifest.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("canonicalize", TOOLS / "canonicalize.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fetch(request):
    with urllib.request.urlopen(request, timeout=30) as reply:
        body = reply.read(MAX_REPLY + 1)
    if len(body) > MAX_REPLY:
        sys.exit(f"{request.full_url}: reply too large")
    return body


def ocsp_status(url, cert, issuer):
    request = (ocsp.OCSPRequestBuilder()
               .add_certificate(cert, issuer, hashes.SHA384())
               .build()
               .public_bytes(serialization.Encoding.DER))
    body = fetch(urllib.request.Request(url, data=request, method="POST",
                                        headers={"Content-Type": "application/ocsp-request"}))
    response = ocsp.load_der_ocsp_response(body)
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        sys.exit(f"OCSP for {cert.subject.rfc4514_string()}: {response.response_status}")
    print(f"  {cert.subject.rfc4514_string()}: {response.certificate_status.name}",
          file=sys.stderr)
    return base64.b64encode(body).decode()


def chain_statuses(url, certs):
    """OCSP for each certificate but the last (the root), each against the next."""
    return [ocsp_status(url, certs[i], certs[i + 1]) for i in range(len(certs) - 1)]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rim-service", required=True)
    parser.add_argument("--ocsp", required=True)
    parser.add_argument("--rim", action="append", default=[], required=True)
    parser.add_argument("--device-chain", action="append", default=[])
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    canonicalize = canonicalizer()
    rims, statuses = [], []
    for rim_id in args.rim:
        print(f"{rim_id}", file=sys.stderr)
        reply = fetch(f"{args.rim_service.rstrip('/')}/v1/rim/{rim_id}")
        entry = canonicalize.entry(reply, rim_id)
        rims.append(entry)
        certs = [x509.load_der_x509_certificate(base64.b64decode(c))
                 for c in entry["certificates"]]
        statuses += chain_statuses(args.ocsp, certs)
    for path in args.device_chain:
        print(f"device chain {path}", file=sys.stderr)
        certs = x509.load_pem_x509_certificates(pathlib.Path(path).read_bytes())
        # The leaf is issued by the device itself; NVIDIA's responder does not know it.
        statuses += chain_statuses(args.ocsp, certs[1:])

    cache = {"format": FORMAT, "rims": rims, "ocsp": sorted(set(statuses))}
    out = pathlib.Path(args.out)
    with tempfile.NamedTemporaryFile("w", dir=out.parent, delete=False) as tmp:
        json.dump(cache, tmp, indent=1)
        tmp.write("\n")
    os.replace(tmp.name, out)
    print(f"wrote {out}: {len(rims)} RIMs, {len(cache['ocsp'])} OCSP responses", file=sys.stderr)


if __name__ == "__main__":
    main()
