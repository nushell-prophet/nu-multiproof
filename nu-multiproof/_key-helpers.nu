# Resolve the SSH signing key to sign with, from a repo's git config.
# Shared by seal and `ssh-sign sign` (its --key default).
#
# Not shared with init: init resolves a *public* key to store and must refuse
# private keys, whereas this returns the private key (or its inline material)
# to sign with — the opposite intent and safety rule.

# Read user.signingKey and return {path, temp} — a key path usable with
# `ssh-keygen -Y sign -f <key>`, plus who owns it. Handles both forms:
#  - inline `key::ssh-ed25519 AAAA…` — materialized to a temp .pub file
#    (ssh-keygen wants a file; the agent must hold the matching private key),
#    `temp: true`: the caller must delete it when done
#  - a file path — used as-is, falling back to its `.pub` sibling, `temp: false`
#
# Prefer `with-signing-key`, which owns that lifetime for you.
#
# --root: repo whose git config to read (default: current directory's repo).
export def resolve-signing-key [--root: path]: nothing -> record<path: path, temp: bool> {
    let git = if $root != null {
        do { ^git -C $root config user.signingKey } | complete
    } else {
        do { ^git config user.signingKey } | complete
    }
    if $git.exit_code != 0 {
        error make {msg: "no git signing key configured — set user.signingKey or pass --key"}
    }
    let raw = $git.stdout | str trim
    if ($raw | str starts-with "key::") {
        let key_data = $raw | str replace "key::" ""
        # Why uuid: a fixed temp name lets two concurrent signs clobber each
        # other's key file mid-operation.
        let tmp = $nu.temp-dir | path join $"nu-multiproof-signing-key-(random uuid).pub"
        $key_data | save --raw --force $tmp
        {path: $tmp temp: true}
    } else {
        let expanded = $raw | path expand
        if ($expanded | path exists) {
            {path: $expanded temp: false}
        } else if ($"($expanded).pub" | path exists) {
            {path: $"($expanded).pub" temp: false}
        } else {
            error make {msg: $"signing key not found: ($raw)"}
        }
    }
}

# Run `action` with a signing-key path, then delete anything resolution had to
# materialize. Returns whatever `action` returns.
#
# Why a closure: the inline `key::` form has no file on disk, so resolution
# writes one — and a command that only *returns* the path has no moment at
# which it can delete it. That leaked one temp key per call, forever.
#
# --key: caller-supplied key, used as-is (nothing to resolve or clean up).
# --root: repo whose git config to read (default: current directory's repo).
export def with-signing-key [
    action: closure # Receives the key path
    --key: path
    --root: path
]: nothing -> any {
    let resolved = if $key != null {
        {path: ($key | into string) temp: false}
    } else {
        resolve-signing-key --root $root
    }
    # Why finally, not catch-and-rethrow: a failed signing ceremony must not
    # skip the cleanup, and `error make {msg: $e.msg}` would drop the original
    # error's span, labels, help and inner error on the way out.
    try {
        do $action $resolved.path
    } finally {
        if $resolved.temp { rm --force $resolved.path }
    }
}
