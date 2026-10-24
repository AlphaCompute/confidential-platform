"""The next unsigned platform document, with the Kata reference values of this release and of the
release that the published document came from.

usage: python3 -I draft.py PUBLISHED CURRENT [PREVIOUS] > document.json   (the summary goes to stderr)
  PUBLISHED: the published {document, signatures}, or a missing file before day 0.
  CURRENT: deploy/kata/reference-values.json of this tag; PREVIOUS: the same file of the previous tag.
"""
import copy, json, os, sys
from datetime import datetime, timezone


def registers(entry):
    return {k: v for k, v in entry.items() if k != "rtmr0"}


def missing(entries, others):
    """(class, value) of each RTMR0 value in `entries` that no entry of `others` with the same
    other registers lists."""
    out = []
    for e in entries:
        have = {r for o in others if registers(o) == registers(e) for r in o["rtmr0"]}
        out += [(e["runtime_class"], r) for r in e["rtmr0"] if r not in have]
    return out


def main():
    published_path, current_path = sys.argv[1:3]
    previous_path = sys.argv[3] if len(sys.argv) > 3 else None
    doc = json.load(open(published_path))["document"] if os.path.exists(published_path) else {"version": 0}
    published = doc.get("kata_reference_values", [])
    current = json.load(open(current_path))
    previous = json.load(open(previous_path)) if previous_path else None
    # The previous tag's draft may never have been signed. Then its values are not what the running
    # Instances booted on, and the published values stay whole.
    if previous is None or missing(previous, published):
        print("previous values: the published document", file=sys.stderr)
        previous = published
    else:
        print("previous values: the previous tag", file=sys.stderr)
    merged = copy.deepcopy(current)
    # A previous entry joins the entry with the same registers apart from RTMR0, or stays whole,
    # so that no TD matches two entries.
    for p in previous:
        same = next((m for m in merged if registers(m) == registers(p)), None)
        if same is None:
            merged.append(p)
        else:
            same["rtmr0"] += [r for _, r in missing([p], merged)]
    doc["version"] += 1
    doc["issued_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc["kata_reference_values"] = merged
    json.dump(doc, sys.stdout, indent=2)
    for title, values in (("kept for one release, in no shape of this tag", missing(merged, current)),
                          ("removed from the published document", missing(published, merged))):
        print(f"{title}:", file=sys.stderr)
        for c, r in values:
            print(f"  {c} {r}", file=sys.stderr)


if __name__ == "__main__":
    main()
