# nu-multiproof

## Module layout

- `nu-multiproof/mod.nu` defines the public API. It re-exports the non-`_`
  submodules wholesale (`export use ots.nu`, etc.), so anything `export def`
  in those files is reachable as `nu-multiproof <module> <cmd>`.
- `nu-multiproof/_*.nu` files are internal. mod.nu does not re-export them.
  Tests and other impl files may import them directly via explicit named
  imports (`use ../nu-multiproof/_ots-helpers.nu copy-path-for`).
- Don't use `use foo *` or `export use foo *`. Always list the names you
  need explicitly — it keeps callsite intent visible and prevents quiet
  name-collisions when an impl file grows a new export.

### Where to put a helper

- **Used only inside its own non-`_` file** → private `def` (not `export def`).
- **Used by tests or another impl file, but should not be public** → extract
  to a sibling `_<topic>-helpers.nu` and import it explicitly. The `_`
  prefix is the only signal of "not public" — mod.nu does the actual hiding
  by not re-exporting `_*.nu` files.
- **Inside `_*.nu` files, everything stays `export def`** — even helpers nothing imports yet. Tests reach internals with `use` + explicit named imports (never `source`), and a private `def` is invisible to `use`. Non-public status comes from the `_` prefix + mod.nu, not from withholding `export`.
- **User-facing** → `export def` in the relevant non-`_` submodule file.

### Why not selective re-export in mod.nu

`export use foo.nu [cmd1 cmd2]` flattens the namespace (you'd get
`nu-multiproof cmd1`, not `nu-multiproof foo cmd1`). Wrapping in
`export module foo { export use foo.nu [...] }` preserves the namespace
but breaks `main` resolution — Nushell only fires the `main` shortcut when
`main` is defined directly in the invoked module, not re-exported into it.
The workaround would be: rename every impl file (so the module name no
longer collides with a top-level public command name), rewrite every
public command in subcommand form (`export def "ots info" [...]`), and
list everything explicitly in mod.nu. For the small number of helpers
actually needing to be hidden, the `_*.nu` extract pattern achieves the
same end with a much smaller diff.

## Rules for proof code

This module's output is evidence. A bug here does not crash — it returns `valid: true` for something false. Every rule below exists because an audit found the opposite in this repo.

- **A guard on a verify path needs a test that feeds a hostile artifact** — a proof file, manifest or bundle built by hand, not one this repo's builder produced. Round-tripping the builder proves self-consistency, never conformance. Mutation testing found that `merkle verify` could stop calling `validate-leaf` entirely and the suite stayed green.
- **Crypto conformance needs at least one vector from outside this codebase.** The `side` convention in `audit-path`/`fold-path` can be flipped in both at once and no test notices, because every path test folds a path the same code built.
- **Never write an artifact you have not parsed back.** `ots stamp` appended an unvalidated calendar body and reported success; the resulting `.ots` was unreadable and unrecoverable. `ots upgrade` gets this right — validate, then atomic-rename.
- **A comment or README line may claim a security property only when a test pins it.** Name the test. `--signer` was documented as pinning a principal while it compared a filename; `check-block-header` was documented as rejecting low-work headers while it read the difficulty out of the header being checked.
- **Reject, never normalize** — already the rule for leaf charsets; it holds everywhere.
- **Trust lists**: a principal comes from key material, never from a filename; a name interpolated into `allowed_signers` must be rejected if it holds whitespace, quotes or newlines.

## Nushell traps this repo has already hit

- **Never pass a path that came from data to `glob`.** It reads `[ ] * ? {` as pattern syntax and silently returns nothing — a discovery loop then reports "0 objects verified" or "no stamp found" instead of failing. This includes a pattern *built* from a path: `glob ($dir | path join "*.pub")` returns `[]` for a repo checked out to `/src/re[po]/`. Use `_fs.nu list-files` / `list-dirs`.
- **`ls` without `--all` hides dotfiles.** Any discovery over user-named files needs it — `.env.alice.sig` was invisible to signature discovery. `_fs.nu` already passes it; prefer that over a fresh `ls`.
- **A temp path's lifetime belongs to a closure, not to a remembered `rm`.** Use `_temp-helpers.nu with-temp-dir` / `with-temp-file`. Hand-written create-work-remove skips the remove on every throw; that shape was fixed one instance at a time in six separate commits.
- **Don't rewrap errors as `error make {msg: $e.msg}`** — it drops the span, label, help and inner error, leaving messages like a bare `Not found`. Use `try { ... } finally { cleanup }` for the cleanup case (0.111+).
- **`open --raw` yields a *string* when the bytes happen to be valid UTF-8.** Add `| into binary` before any binary pipeline.
- **External commands throw on non-zero exit, but their stderr never reaches `$e.msg`.** Use `do { ^cmd } | complete` wherever the failure is caught and reported to the user.
- **Pass `--` before data-derived arguments** to `git` and `ssh-keygen`. `git verify-commit --help` exits 0.
- **Every `http` call needs a timeout** (`--max-time`), and a URL taken from a file is attacker-controlled input.

Four of these are enforced by `tests/test_lint.nu`, not by memory: the glob rule, `ls --all`, the error rewrap and the http timeout. Adding a rule there is cheaper than re-finding the same defect. Each rule carries a sample of what it forbids, checked on every run, so a rule that quietly stops matching fails instead of passing.

## Command conventions

- Every command that touches a repo takes `--repo` and resolves it through `_repo.nu repo-root`. A callee that resolves the CWD instead forces its caller into workarounds — see the two apology comments in `seal.nu`.
- Paths come from `_layout.nu`, signature names from `_sig.nu`, directory listings from `_fs.nu`, temp paths from `_temp-helpers.nu`. Don't re-derive any of them inline; that is how `ssh-sign verify` ended up resolving the wrong original file.
- `@example` must run offline in a throwaway directory. nutest does not execute them, so a broken one is invisible until a human tries it.

## Running tests

```sh
nu toolkit.nu test          # runs all tests under tests/
nu toolkit.nu test --fail   # exits non-zero on any failure (for CI)
```

Requires `nutest` as a sibling directory:
```sh
git clone https://github.com/vyadh/nutest ../nutest
```

Test files live in `tests/` and follow nutest conventions.
