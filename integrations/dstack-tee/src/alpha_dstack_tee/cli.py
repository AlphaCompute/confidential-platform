"""Ciphertext-only stdout. Values arrive on stdin, never in command arguments."""

import argparse
import json
from pathlib import Path
import sys

from alpha_dstack_tee import AlphaDstackTEEPlugin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signer-file", required=True, help="independently trusted KMS signer")
    parser.add_argument("--app-id", required=True, help="expected Phala App ID (20 bytes hex)")
    args = parser.parse_args()
    try:
        plugin = AlphaDstackTEEPlugin(Path(args.signer_file).read_text().strip())
        raw = sys.stdin.buffer.read(1048577)
        if len(raw) > 1048576:
            raise ValueError("input exceeds 1 MiB")
        request = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {
            "values", "offered_public_key", "signed_key"
        }:
            raise ValueError("invalid request")
        result = plugin.encrypt_environment(
            request["values"], expected_app_id=args.app_id,
            offered_public_key=request["offered_public_key"], signed_key=request["signed_key"]
        )
        print(result)
    except Exception:
        # JSON decoder/provider/library exceptions may contain confidential input.
        print("environment sealing refused; check the trusted pin and signed key", file=sys.stderr)
        raise SystemExit(1)
