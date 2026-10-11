#!/usr/bin/env python3
"""INTERIM: renders a deploy/coco spec into the form PRD-01 admission and the KMS accept, until
`alpha coco render` (PRD-02 PR 6) replaces this script. Delete it then.

  deploy/coco/render-interim.py <spec.yaml> <policy.rego> <values.env>...
  deploy/coco/render-interim.py <spec.yaml> --for-genpolicy <values.env>...

The values files are KEY=VALUE lines (# comments); a name may be set in one file only, every
${NAME} in the spec must be set, and no value may still hold a <placeholder> or a character that
would break the YAML or the shell (" ' ` \\ $ or a newline). APP_ID and INFERENCE_APP_ID are
lower-case hyphenated UUIDs, as alpha_core::AppId prints them, and GPU_MODEL an upper-case model.

It builds the pod's init-data, a CoCo init-data document (version 0.1.0, algorithm sha384) with two
entries, exactly as PRD-02's alpha_core::coco reads it:
  policy.rego  the reviewed agent policy, byte for byte (genpolicy 4.1.0 run on this spec's
               --for-genpolicy rendering, then reviewed: no exec, no log readback);
  alpha.json   {"app_id": APP_ID, "format": "alphacompute-initdata/1", "gpu": {"count": the sum of
               the spec's nvidia.com/pgpu limits, "model": GPU_MODEL}, "runtime_class": the spec's
               runtimeClassName}, gpu left out when the spec asks for none;
and sets CC_INIT_DATA to base64(gzip(init-data)), the value of the pod's only Kata annotation,
io.katacontainers.config.hypervisor.cc_init_data. The rendered spec goes to stdout. On stderr: the
init-data and policy digests, the Revision v2 document in its canonical (JCS) form, and its hash,
which is what gets registered and what alpha-inference's MODEL_SERVERS pins.

--for-genpolicy renders the same spec with an empty init-data annotation and prints nothing else:
the input genpolicy generates the policy from. Admission refuses that rendering as it is.
"""

import base64
import gzip
import hashlib
import json
import re
import sys

INITDATA_VERSION = "0.1.0"
ALPHA_ENTRY_FORMAT = "alphacompute-initdata/1"
REVISION_FORMAT = "alphacompute-coco-revision/1"
GPU_COUNTS = (1, 8)
FORBIDDEN = set("\"'`\\$\n\r")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# How alpha_core::AppId prints, so the Revision printed here is the one the KMS rebuilds.
APP_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# What alpha_core::coco accepts as gpu.model.
GPU_MODEL = re.compile(r"[A-Z0-9-]{1,32}")


def fail(message):
    sys.exit(f"render-interim: {message}")


def read_values(paths):
    values = {}
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for number, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                name, sep, value = line.partition("=")
                if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                    fail(f"{path}:{number}: not NAME=value")
                if name in values:
                    fail(f"{path}:{number}: {name} is already set")
                values[name] = value
    return values


def substitute(text, values):
    missing = sorted({m for m in re.findall(r"\$\{([A-Z][A-Z0-9_]*)\}", text) if m not in values})
    if missing:
        fail(f"not set: {', '.join(missing)}")

    def value(match):
        name = match.group(1)
        v = values[name]
        if "<" in v or ">" in v:
            fail(f"{name} still holds a placeholder: {v}")
        if FORBIDDEN & set(v):
            fail(f"{name} holds a character that would break the YAML or the shell")
        return v

    return re.sub(r"\$\{([A-Z][A-Z0-9_]*)\}", value, text)


def canonical(value):
    # JCS for what these documents hold (ASCII keys, strings, small integers).
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def shape(spec):
    classes = re.findall(r"^\s*runtimeClassName:\s*(\S+)\s*$", spec, re.M)
    if len(classes) != 1:
        fail("the spec must name exactly one runtimeClassName")
    gpus = sum(int(n) for n in re.findall(r"^\s*nvidia\.com/pgpu:\s*(\d+)\b", spec, re.M))
    if re.search(r"nvidia\.com/gpu\b", spec):
        fail("GPUs are nvidia.com/pgpu, not nvidia.com/gpu")
    if gpus and gpus not in GPU_COUNTS:
        fail(f"{gpus} GPUs: a pod has 1 or 8")
    return classes[0], gpus


def initdata(policy, alpha):
    # A TOML multi-line literal string holds anything but three quotes in a row and control
    # characters other than tab and newline; a quote right before the closing three would merge
    # with them.
    if not policy.strip():
        fail("the policy is empty")
    if "'''" in policy or policy.endswith("'") or CONTROL.search(policy):
        fail("the policy cannot be a TOML literal string as it is (''', a final quote, or a "
             "control character such as a carriage return)")
    # Literal strings: no escaping, and TOML drops the newline right after the opening quotes,
    # so the entry is the policy byte for byte.
    return (
        f'algorithm = "sha384"\nversion = "{INITDATA_VERSION}"\n\n[data]\n'
        f"\"alpha.json\" = '''{alpha}'''\n"
        f"\"policy.rego\" = '''\n{policy}'''\n"
    ).encode()


def main(argv):
    if len(argv) < 4:
        fail("usage: render-interim.py <spec.yaml> <policy.rego>|--for-genpolicy <values.env>...")
    spec_path, policy_path, env_paths = argv[1], argv[2], argv[3:]
    with open(spec_path, encoding="utf-8") as f:
        template = f.read()
    values = read_values(env_paths)
    if "CC_INIT_DATA" in values:
        fail("CC_INIT_DATA is computed, not set")

    if policy_path == "--for-genpolicy":
        sys.stdout.write(substitute(template, {**values, "CC_INIT_DATA": ""}))
        return

    runtime_class, gpus = shape(substitute(template, {**values, "CC_INIT_DATA": ""}))
    for name in ("APP_ID", "GPU_MODEL") if gpus else ("APP_ID",):
        if name not in values:
            fail(f"not set: {name}")
    for name in ("APP_ID", "INFERENCE_APP_ID"):
        if name in values and not APP_ID.fullmatch(values[name]):
            fail(f"{name} is not an App id (a lower-case hyphenated UUID)")
    if gpus and not GPU_MODEL.fullmatch(values["GPU_MODEL"]):
        fail("GPU_MODEL is not an upper-case model name such as B300")
    alpha = {"app_id": values["APP_ID"], "format": ALPHA_ENTRY_FORMAT, "runtime_class": runtime_class}
    if gpus:
        alpha["gpu"] = {"count": gpus, "model": values["GPU_MODEL"]}
    # newline="": the policy's bytes as they are, so a carriage return is seen (and refused).
    with open(policy_path, encoding="utf-8", newline="") as f:
        policy = f.read()
    document = initdata(policy, canonical(alpha))
    encoded = base64.b64encode(gzip.compress(document, compresslevel=9, mtime=0)).decode()
    sys.stdout.write(substitute(template, {**values, "CC_INIT_DATA": encoded}))

    revision = {
        "app_id": values["APP_ID"],
        "format": REVISION_FORMAT,
        "initdata_sha256": sha256(document),
        "policy_sha256": sha256(policy.encode()),
        "runtime_class": runtime_class,
    }
    if gpus:
        revision["gpu"] = alpha["gpu"]
    text = canonical(revision)
    print(f"init-data {sha256(document)}, policy {revision['policy_sha256']}", file=sys.stderr)
    print(f"revision {text}", file=sys.stderr)
    print(f"revision hash {sha256(text.encode())}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv)
