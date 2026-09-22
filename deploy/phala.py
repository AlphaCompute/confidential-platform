#!/usr/bin/env python3
"""Creates or updates a Phala Cloud CVM from an app-compose.json, and waits for it to run.

  deploy/phala.py create <app-compose.json> <cvm name>
  deploy/phala.py update <cvm id> <app-compose.json>
  deploy/phala.py wait <cvm id>

PHALA_API_KEY authenticates. On create, PHALA_INSTANCE_TYPE (default tdx.small), PHALA_IMAGE
and PHALA_NODE_ID choose the machine. Every name in the compose's allowed_envs travels in the
encrypted env, empty when unset in this process's environment. create and update print
{cvm_id, app_id, gateway_base_domain} and refuse when the compose Phala stored is not the file.
wait returns once every container has been running for three checks in a row.
"""

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote

from alpha_dstack_tee import AlphaDstackTEEPlugin


API = "https://cloud-api.phala.network/api/v1"
# The edge in front of the API refuses urllib's default user agent with a bare 403.
USER_AGENT = "alphacompute-deploy/1"


def call(method, path, body=None):
    request = urllib.request.Request(
        API + path,
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={
            "X-API-Key": os.environ["PHALA_API_KEY"],
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=180) as reply:
            raw = reply.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError("provider response exceeds size limit")
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as refused:
        sys.exit(f"provider request refused: HTTP {refused.code}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("provider redirect refused")


def verified_seal(adapter, values, prepared, *, app_id, offered):
    kms = prepared.get("kms_contract_id") or prepared.get("kms_id") or prepared.get("kms_type")
    if not kms:
        raise ValueError("provider KMS identifier required")
    signed = call("GET", f"/kms/{quote(str(kms), safe='')}/pubkey/{quote(app_id, safe='')}")
    return adapter.encrypt_environment(values, expected_app_id=app_id,
                                      offered_public_key=offered, signed_key=signed)


def sha256_hex(compose_bytes):
    return hashlib.sha256(compose_bytes).hexdigest()


def check(phala_hash, compose_bytes):
    want = sha256_hex(compose_bytes)
    got = phala_hash.removeprefix("sha256:").removeprefix("0x")
    if got != want:
        sys.exit(
            f"compose_hash mismatch: Phala would measure {got}, the file hashes to {want}; "
            "nothing was committed"
        )


def check_stored(cvm_id, compose_bytes, timeout_s=5 * 60, interval_s=10):
    """The compose Phala keeps for the CVM, in the form it measures, must become the file. A
    commit that carries env can rewrite allowed_envs (drop names, reorder them), which changes
    the measured compose after the provision-time check passed. Phala applies a commit
    asynchronously, so this waits for the stored compose rather than reading it once."""
    want = sha256_hex(compose_bytes)
    deadline = time.monotonic() + timeout_s
    while True:
        stored = call("GET", f"/cvms/{cvm_id}/compose_file")
        form = json.dumps(stored, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        got = hashlib.sha256(form.encode()).hexdigest()
        if got == want:
            return
        if time.monotonic() >= deadline:
            sys.exit(
                f"stored compose of {cvm_id} hashes to {got}, the file to {want}: the CVM would "
                f"not attest; its allowed_envs are {stored.get('allowed_envs')}. Recreate the CVM."
            )
        time.sleep(interval_s)


def report(cvm_id):
    info = call("GET", f"/cvms/{cvm_id}")
    print(json.dumps({
        "cvm_id": cvm_id,
        "app_id": info["app_id"],
        "gateway_base_domain": info["gateway"]["base_domain"],
    }))


def wait(cvm_id, timeout_s=20 * 60, interval_s=10):
    deadline = time.monotonic() + timeout_s
    streak = 0
    containers = []
    while time.monotonic() < deadline:
        containers = (call("GET", f"/cvms/{cvm_id}/composition") or {}).get("containers") or []
        running = bool(containers) and all(c.get("state") == "running" for c in containers)
        streak = streak + 1 if running else 0
        if streak >= 3:
            for c in containers:
                print(f"{c.get('names')} {c.get('status')}", file=sys.stderr)
            return
        time.sleep(interval_s)
    states = ", ".join(f"{c.get('names')} {c.get('status')}" for c in containers) or "none"
    sys.exit(f"containers of {cvm_id} not running after {timeout_s // 60} minutes: {states}")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "wait":
        wait(sys.argv[2])
        return
    if len(sys.argv) != 4 or sys.argv[1] not in ("create", "update"):
        sys.exit(__doc__)
    action = sys.argv[1]
    adapter = AlphaDstackTEEPlugin(os.environ.get("PHALA_KMS_SIGNER", ""))
    path = sys.argv[2] if action == "create" else sys.argv[3]
    with open(path, "rb") as f:
        compose_bytes = f.read()
    compose = json.loads(compose_bytes)
    # Phala rewrites the stored allowed_envs from env_keys on commit, so every name goes out.
    values = {n: os.environ.get(n, "") for n in compose.get("allowed_envs", [])}

    if action == "create":
        body = {
            "name": sys.argv[3],
            "instance_type": os.environ.get("PHALA_INSTANCE_TYPE", "tdx.small"),
            "compose_file": compose,
        }
        if os.environ.get("PHALA_IMAGE"):
            body["image"] = os.environ["PHALA_IMAGE"]
        if os.environ.get("PHALA_NODE_ID"):
            body["node_id"] = int(os.environ["PHALA_NODE_ID"])
        prepared = call("POST", "/cvms/provision", body)
        check(prepared["compose_hash"], compose_bytes)
        made = call("POST", "/cvms", {
            "app_id": prepared["app_id"],
            "compose_hash": prepared["compose_hash"],
            "encrypted_env": verified_seal(adapter, values, prepared,
                                          app_id=prepared["app_id"],
                                          offered=prepared["app_env_encrypt_pubkey"]),
            "env_keys": list(values),
        })
        check_stored(made["id"], compose_bytes)
        report(made["id"])
        return

    cvm_id = sys.argv[2]
    prepared = call("POST", f"/cvms/{cvm_id}/compose_file/provision", compose)
    check(prepared["compose_hash"], compose_bytes)
    info = call("GET", f"/cvms/{cvm_id}")
    sealed = verified_seal(adapter, values, {**info, **prepared},
                          app_id=info["app_id"], offered=info["kms_info"]["encrypted_env_pubkey"])
    if prepared.get("compose_unchanged"):
        call("PATCH", f"/cvms/{cvm_id}/envs", {"encrypted_env": sealed, "env_keys": list(values)})
    else:
        call("PATCH", f"/cvms/{cvm_id}/compose_file", {
            "compose_hash": prepared["compose_hash"],
            "encrypted_env": sealed,
            "env_keys": list(values),
            "update_env_vars": True,
        })
    check_stored(cvm_id, compose_bytes)
    report(cvm_id)


if __name__ == "__main__":
    main()
