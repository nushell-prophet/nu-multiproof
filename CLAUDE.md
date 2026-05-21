# nu-multiproof

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
