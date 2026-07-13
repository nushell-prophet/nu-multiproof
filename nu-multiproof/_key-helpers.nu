# Resolve the SSH signing key to sign with, from a repo's git config.
# Shared by seal and `ssh-sign sign` (its --key default).
#
# Not shared with init: init resolves a *public* key to store and must refuse
# private keys, whereas this returns the private key (or its inline material)
# to sign with — the opposite intent and safety rule.

# Return a key path usable with `ssh-keygen -Y sign -f <key>`, read from
# user.signingKey. Handles both forms:
#  - inline `key::ssh-ed25519 AAAA…` — materialized to a temp .pub file
#    (ssh-keygen wants a file; the agent must hold the matching private key)
#  - a file path — used as-is, falling back to its `.pub` sibling
#
# --root: repo whose git config to read (default: current directory's repo).
export def resolve-signing-key [--root: path]: nothing -> path {
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
        $tmp
    } else {
        let expanded = $raw | path expand
        if ($expanded | path exists) {
            $expanded
        } else if ($"($expanded).pub" | path exists) {
            $"($expanded).pub"
        } else {
            error make {msg: $"signing key not found: ($raw)"}
        }
    }
}
