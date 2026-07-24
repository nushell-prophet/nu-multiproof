# Temp paths whose lifetime is bounded by the work that needs them.
#
# Why closures, not "make a path, remember to remove it": the hand-written form
# — create, work, `rm` — skips the `rm` on every throw, and this repo wrote it
# five separate times (56b07e5, 98d0abb, 13fe73f, 52feb4a, 0165d07, e88a559
# each fixed one instance). `finally` runs on the error path too, and unlike a
# `catch` + rethrow it does not flatten the original error.

# Run `action` with a fresh empty directory, removed afterwards either way.
# Returns whatever `action` returns. `label` names the work, so a leaked dir
# from a killed process says which command made it.
export def with-temp-dir [label: string action: closure]: nothing -> any {
    let dir = $nu.temp-dir | path join $"nu-multiproof-($label)-(random uuid)"
    mkdir $dir
    try { do $action $dir } finally { rm --recursive --force $dir }
}

# Run `action` with a temp file *path*, removed afterwards either way. The path
# is not created — callers pass it to something that writes it (a save, an
# external command, GIT_INDEX_FILE), so removal is `--force`.
export def with-temp-file [label: string action: closure]: nothing -> any {
    let file = $nu.temp-dir | path join $"nu-multiproof-($label)-(random uuid)"
    try { do $action $file } finally { rm --force $file }
}
