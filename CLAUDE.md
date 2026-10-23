# nu-multiproof

The crypto layer under `nu-cybergraph`:
CIDs, merkle trees, ssh signatures, seals, OpenTimestamps.
Pre-alpha, one consumer, no backwards compatibility to keep.

The design decisions here were made by agents,
so they may drift from the user's intent.
The user regrets building this so fast without proper checks,
and needs your help to stabilize the functionality.
So do not trust the comments and the README on their own.
Check the git history and the Claude Code project sessions to recover the user's intent.
Or plainly ask him.

## An academic prototype, not a product

This is a canonical implementation:
it exists to show the format is right and the reasoning holds,
on inputs small enough to read by hand.
So prefer the plain reading over the clever one
— a walk over a cache, a recomputation over a stored copy —
and never add a mechanism whose only argument is speed.
When the load outgrows this,
the answer is optimization or a rewrite in a real language,
decided then with the numbers in hand.

Two things this does not license.
It is not permission to undo a cost already measured here
— a number written into a comment bought the shape that code has.
And "correct under correct circumstances" is about scale and load, never about input:
refusing malformed, tampered or unprovable bytes loudly is the product,
so a check is never what gets dropped for simplicity.

## `git-proof` was cut — act as if it never existed

A `git-proof` module once proved "this blob was in a signed commit".
It was a trial run, and it is gone (`3ccd1b2`, 2026-07-25).
This line exists because agents kept picking it back up as if it were core functionality.
Nothing about it counts:
not as precedent,
not as an argument for or against a design,
not as a reference implementation,
not as a thing to restore.
If you meet it in the history, in a README, or in a parked note,
leave it there.

## Module layout

- `nu-multiproof/mod.nu` defines the public API:
  it names each public command,
  and nothing else in a submodule is public.
- Every submodule file exports every command, helpers included,
  so a test reaches any of them with `use ../nu-multiproof/ots.nu [ helper ]`.
- A named list flattens the namespace
  (`export use ots.nu [ stamp ]` gives `nu-multiproof stamp`, not `nu-multiproof ots stamp`).
  So mod.nu wraps the subcommands of a file in an inline module of the same name:
  `module ots { export use ots.nu [ info stamp upgrade verify ] }` and `export use ots`.
- `main` of a file is imported outside the wrapper, with `export use seal.nu [ main ]`:
  inside the wrapper it would surface as `seal seal`, not `seal`.
- `nu-multiproof/_*.nu` files are internal helpers that no public file holds; mod.nu does not import them.
- Don't use `use foo *` or `export use foo *`.
  Always list the names you need explicitly
  — it keeps callsite intent visible
  and prevents quiet name-collisions when an impl file grows a new export.
- The check after a change to mod.nu:
  `use` the module in a fresh `nu`, list `scope commands` under its name,
  and compare the names and signatures with the state before the change.

## Rules for proof code

This module's output is evidence.
A bug here does not crash
— it returns `valid: true` for something false.
Every rule below exists because an audit found the opposite in this repo.

- **A guard on a verify path needs a test that feeds a hostile artifact** — a proof file, manifest or bundle built by hand, not one this repo's builder produced.
  Round-tripping the builder proves self-consistency, never conformance.
  Mutation testing found that `merkle verify` could stop calling `validate-leaf` entirely
  and the suite stayed green.
- **Crypto conformance needs at least one vector from outside this codebase.**
  The `side` convention in `audit-path`/`fold-path` can be flipped in both at once and no test notices,
  because every path test folds a path the same code built.
- **Never write an artifact you have not parsed back.**
  `ots stamp` appended an unvalidated calendar body and reported success;
  the resulting `.ots` was unreadable and unrecoverable.
  `ots upgrade` gets this right
  — validate, then atomic-rename.
- **A comment or README line may claim a security property only when a test pins it.**
  Name the test.
  `--signer` was documented as pinning a principal while it compared a filename;
  `check-block-header` was documented as rejecting low-work headers while it read the difficulty out of the header being checked.
- **Reject, never normalize** — already the rule for leaf charsets;
  it holds everywhere.
- **Trust lists**: a principal is a key's fingerprint (`pubkey fingerprint`),
  derived from key material every time a list is rendered
  — never from a filename, a key comment or a flag.
  Key material is the only thing an `allowed_signers` line may carry;
  anything else interpolated into one needs a charset gate.

## Nushell traps this repo has already hit

- **Never pass a path that came from data to `glob`.**
  It reads `[ ] * ? {` as pattern syntax and silently returns nothing
  — a discovery loop then reports "0 objects verified" or "no stamp found" instead of failing.
  This includes a pattern *built* from a path:
  `glob ($dir | path join "*.pub")` returns `[]` for a repo checked out to `/src/re[po]/`.
  Use `_fs.nu list-files` / `list-dirs`.
- **`ls` without `--all` hides dotfiles.**
  Any discovery over user-named files needs it
  — `.env.alice.sig` was invisible to signature discovery.
  `_fs.nu` already passes it;
  prefer that over a fresh `ls`.
- **A temp path's lifetime belongs to a closure, not to a remembered `rm`.**
  Use `_temp-helpers.nu with-temp-dir` / `with-temp-file`.
  Hand-written create-work-remove skips the remove on every throw;
  that shape was fixed one instance at a time in six separate commits.
- **Don't rewrap errors as `error make {msg: $e.msg}`** — it drops the span, label, help and inner error, leaving messages like a bare `Not found`.
  Use `try { ... } finally { cleanup }` for the cleanup case (0.111+).
- **`open --raw` yields a *string* when the bytes happen to be valid UTF-8.**
  Add `| into binary` before any binary pipeline.
- **External commands throw on non-zero exit, but their stderr never reaches `$e.msg`.**
  Use `do { ^cmd } | complete` wherever the failure is caught and reported to the user.
- **Pass `--` before data-derived arguments** to `git` and `ssh-keygen`.
  `git verify-commit --help` exits 0.
- **Every `http` call needs a timeout** (`--max-time`),
  and a URL taken from a file is attacker-controlled input.

Four of these are enforced by `tests/test_lint.nu`, not by memory:
the glob rule, `ls --all`, the error rewrap and the http timeout.
Adding a rule there is cheaper than re-finding the same defect.
Each rule carries a sample of what it forbids, checked on every run,
so a rule that quietly stops matching fails instead of passing.

## Command conventions

- Every command that touches a repo takes `--repo` and resolves it through `_repo.nu repo-root`.
  A callee that resolves the CWD instead forces its caller into workarounds
  — see the two apology comments in `seal.nu`.
  Three commands predate the rule and still call `repo-root` with no argument:
  `ssh-sign sign`, `ssh-sign verify` and `ots stamp`.
  They are the exception the apology comments are about, not a precedent
  — a new command gets `--repo`.
- Paths come from `_layout.nu`, signature names from `_sig.nu`, directory listings from `_fs.nu`, temp paths from `_temp-helpers.nu`.
  Don't re-derive any of them inline;
  that is how `ssh-sign verify` ended up resolving the wrong original file.
- `@example` must run offline in a throwaway directory.
  nutest does not execute them,
  so a broken one is invisible until a human tries it.

## Commit messages

The prefix is the command the change is about, spelled as the user types it
— `ots:`, `ots stamp:`, `merkle:`, `merkle verify:`, `ssh-sign:`, `beacon:`, `seal:`, `pubkey:`, `init:`, `tree-hashes:`, `cid-v0:`.
That is `mod.nu`'s export list,
so the prefix survives a file rename
and a reader can go straight from the log to the command.
Use a conventional type — `docs:`, `fix:`, `refactor:`, `test:` — only when no single command owns the change.

The subject is a sentence stating what is true *after* the commit,
not a label for the diff:
`ssh-sign: a named sig path that is not on disk throws, never a verdict`,
`merkle write-root: an empty repo's one-row manifest is as constant as no rows`.
This is denser than a conventional-commit summary
and it is why the log of this repo reads as a list of invariants
— keep it.

## Running tests

```sh
nu toolkit.nu test            # runs all tests under tests/; exits non-zero on any failure
nu toolkit.nu test --no-fail  # exit 0 even on failures (fail-on-error is the default)
nu toolkit.nu test --network  # runs tests-network/ instead — reaches the internet; one test writes a permanent public timestamp
nu toolkit.nu test --threads 0 # nutest's own parallelism back (0 means one per core) — see the warning below
```

The suite runs on one thread by default and takes about 17 seconds.
That is not a preference:
nutest's own default runs every suite in parallel and every test inside it in parallel too,
firing roughly 1500 short-lived processes in 3.5 seconds,
and under Apple `container` that wedges the terminal of the whole VM on the fourth or fifth consecutive run
— the guest keeps running, but nothing it prints reaches the screen again until the machine is restarted.
Thirty consecutive single-threaded runs never wedged it.
So 17 seconds instead of 4 is the price of a terminal that survives,
and `--threads 0` is the escape hatch, not the faster setting to reach for.
`--network` goes through the same strategy, so those tests are single-threaded too.
The fault is in the runtime rather than here,
so this default should go once it is fixed upstream
— the reasoning and the measurements are in the commit that set it.

Requires `nutest` as a sibling directory:
```sh
git clone https://github.com/vyadh/nutest ../nutest
```

Test files live in `tests/` and follow nutest conventions.
