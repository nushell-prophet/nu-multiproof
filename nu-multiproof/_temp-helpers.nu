# Temp paths whose lifetime is bounded by the work that needs them.
#
# Why closures, not "make a path, remember to remove it": the hand-written form
# — create, work, `rm` — skips the `rm` on every throw, and this repo wrote it
# six separate times. `finally` runs on the error path too, and unlike a
# `catch` + rethrow it does not flatten the original error.

# Why `| collect` on both: Nushell 0.114.1 deadlocks — forever, no error and no
# timeout — when an external command's stdout crosses a `try` boundary and
# exceeds 256 KiB (`try { ^cmd } finally { }` hangs at 262145 bytes; `do { ^cmd }`
# and a bare call are both fine). `tree-hashes` hit exactly this on any repo whose
# `git ls-tree` output ran past it — about 1000 tracked paths — and `seal` simply
# never returned. Collecting inside the helper keeps the deadlock out of every
# caller. Pinned by tests/test_temp-helpers.nu "with-temp-file returns more than
# 256 KiB of external output", which runs in a subprocess under `timeout`
# because a regression hangs instead of failing.

# Run `action` with a fresh empty directory, removed afterwards either way.
# Returns whatever `action` returns. `label` names the work, so a leaked dir
# from a killed process says which command made it.
export def with-temp-dir [label: string action: closure]: nothing -> any {
    let dir = $nu.temp-dir | path join $"nu-multiproof-($label)-(random uuid)"
    mkdir $dir
    try { do $action $dir | collect } finally { rm --recursive --force $dir }
}

# Run `action` with a temp file *path*, removed afterwards either way. The path
# is not created — callers pass it to something that writes it (a save, an
# external command, GIT_INDEX_FILE), so removal is `--force`.
export def with-temp-file [label: string action: closure]: nothing -> any {
    let file = $nu.temp-dir | path join $"nu-multiproof-($label)-(random uuid)"
    try { do $action $file | collect } finally { rm --force $file }
}
