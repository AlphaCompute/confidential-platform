# Working in this repository

Rules for everyone who changes this repository. CI enforces the ones marked (CI); reviewers reject
the rest.

## Branches and pull requests

- `main` is the only integration branch. Branch off `main`, open the pull request against `main`.
  No `dev`, no release branches, no long-lived feature branches, no stacks: if a change needs
  another unmerged one, wait for it to merge and rebase. (CI)
- One pull request is one change a reviewer can hold in their head: at most 1000 added lines,
  not counting `Cargo.lock` or any `.sqlx/` or `testdata/` directory. Split anything bigger into
  pull requests that each build, pass the tests and make sense on their own. (CI)
- Merge only when CI and the CodeRabbit check are green and every review thread is resolved.

## Before opening a pull request

Run this loop on the branch, in order, and repeat it until a whole pass changes nothing:

1. `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
2. Lean review over `git diff origin/main...HEAD`, by a reviewer who did not write the code. It
   looks only for what to remove or simplify under the Code rules below, plus dead code. Apply
   every finding, rerun step 1, commit, and review again with a new reviewer.
   The loop ends when the review has no findings. It never removes the no-panic error paths, input
   validation at trust boundaries, security checks or tests; if a round proposes only those cuts,
   or undoes the previous round, stop and say so in the pull request.
3. `coderabbit review --agent --base main`. Fix each finding or answer it in the pull request.
   If code changed, go back to step 1.

Only then open the pull request against `main`.

## Commits and pull request text

- Every commit subject and every pull request title follows
  [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):
  `type(scope)!: description`. Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
  `build`, `ci`, `chore`, `revert`. The scope is optional and names the crate or service without
  its `alpha-` prefix (`kms`, `attest`, `cli`); `!` and a `BREAKING CHANGE:` footer mark a
  breaking change to a wire format, route or CLI. The pull request title becomes the merge commit
  on `main`. (CI)
- The description is domain language in the imperative mood:
  `fix(attest): require the TDX TEE type in a quote's header`. The body says what changed and why,
  not how it was produced.
- No internal tracking identifiers anywhere public: commit messages, pull request titles and
  bodies, branch names, code, comments, logs, docs. That means no `PRD-05`, `D4`, `M2(a)`, `I1`,
  `P0`, ADR numbers, phase, plan or deliverable numbers. State the constraint itself. (CI checks
  titles, bodies and commit messages)
- No tool attribution: no `Co-Authored-By` for tools, no "generated with" lines. (CI)
- Keep local-only files out of commits; CI rejects the known paths.

## Code

- Services never panic. In `services/*` and every crate they link (all of `crates/*`, `alpha-cli`
  included): no `unwrap`, `expect`, `panic!`, `unreachable!`, `todo!`, `unimplemented!`, `assert!`
  outside tests; no indexing or slicing that can panic (use `get`, `split_first_chunk`,
  `try_into`); no `.lock().unwrap()` on std locks (use `parking_lot`); no arithmetic that can
  overflow or divide by zero on input a peer controls (use `checked_*`/`saturating_*`). Every such
  path returns an error. "This cannot fail" is not an argument, and a `// safe:` comment does not
  lift the rule. The `[workspace.lints.clippy]` table enforces all of it except `assert!`;
  only tests may allow it.
- No trait with one implementation. No config for a value that never changes. No scaffolding for
  later steps. Smallest diff that does the job; reuse what the workspace already has.
- Comments only for a non-obvious why. Mark a deliberate simplification with a `ponytail:` comment
  that names its ceiling and the upgrade path.
- Every service: `migrate` subcommand, `/ready` checks dependencies, `/healthz` only the process,
  drain on SIGTERM, no in-memory state shared across instances, config from env only.
- Tests: unit tests next to the code; database tests against a real Postgres (`DATABASE_URL`, run
  when it is set), never a mocked database; attestation golden tests on real quotes.
