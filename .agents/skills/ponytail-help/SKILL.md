---
name: ponytail-help
description: >
  Quick-reference card for Ponytail commands. One-shot
  display, not a persistent mode. Use when the user says "ponytail help", "how do I
  use ponytail", "what ponytail commands", or invokes /ponytail-help.
---

# Ponytail quick reference

**What it is:** maximum-efficiency dev mode. Zero-fluff prose + YAGNI-first code, always on together.

## Commands

| Command | Effect |
|---------|--------|
| `/ponytail` | Activate |
| `/ponytail-audit [path]` | Audit a diff/file/repo for both code bloat AND prose verbosity |
| `/ponytail-review` | Review the current diff for over-engineering |
| `stop ponytail` / `normal mode` | Deactivate |

Natural language works: "activate ponytail", "ponytail mode", "chislify this".

## The code ladder

YAGNI → reuse → stdlib → native → installed dep → one line → minimum code.

## Never minimal about

Input validation, error handling that prevents data loss, security,
accessibility, anything you explicitly asked for.
