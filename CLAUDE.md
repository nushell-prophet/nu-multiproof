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
