# Resolve the SSH signing key to sign with, from a repo's git config.
# Shared by seal and `ssh-sign sign` (its --key default).
#
# Not shared with init: init resolves a *public* key to store and must refuse
# private keys, whereas this returns the private key (or its inline material)
# to sign with — the opposite intent and safety rule.

use _allowed-signers.nu registered-principals
use _pubkey-helpers.nu fingerprint-file
use _temp-helpers.nu with-temp-dir

# Run `action` with a key path usable with `ssh-keygen -Y sign -f <key>`,
# read from user.signingKey unless --key names one. Returns whatever `action`
# returns. Handles both config forms:
#  - inline `key::ssh-ed25519 AAAA…` — materialized to a temp .pub file
#    (ssh-keygen wants a file; the agent must hold the matching private key)
#  - a file path — used as-is, falling back to its `.pub` sibling
#
# Why a closure: the inline form has no file on disk, so resolution writes one
# — and a command that only *returns* the path has no moment at which it can
# delete it. That leaked one temp key per call, forever.
#
# --key: caller-supplied key, used as-is (nothing to resolve or clean up).
# --root: repo whose git config to read (default: current directory's repo).
export def with-signing-key [
    action: closure # Receives the key path
    --key: path
    --root: path
]: nothing -> any {
    if $key != null { return (do $action ($key | into string)) }
    let git = do { ^git -C ($root | default ".") config user.signingKey } | complete
    if $git.exit_code != 0 {
        # Why not "or pass --key": seal has no such flag, and this is
        # the only message its caller ever sees. `ssh-sign sign --key` short-
        # circuits before reaching here, so naming the config serves both.
        error make {msg: "no git signing key configured — set it with: git config user.signingKey <path-to-key>"}
    }
    let raw = $git.stdout | str trim
    if ($raw | str starts-with "key::") {
        # Why a directory and not with-temp-file: the file must end in `.pub`,
        # which signing-principal reads as "this is the public half".
        return (with-temp-dir "signing-key" {|dir|
            let pub = $dir | path join "key.pub"
            $raw | str replace "key::" "" | save --raw $pub
            do $action $pub
        })
    }
    let expanded = $raw | path expand
    if ($expanded | path exists) {
        do $action $expanded
    } else if ($"($expanded).pub" | path exists) {
        do $action $"($expanded).pub"
    } else {
        error make {msg: $"signing key not found: ($raw)"}
    }
}

# The principal this key signs under: its own fingerprint, from its public half.
#
# Registration is still required, and that is the only reason pubkeys/ is read
# here: a signature by a key the trust list does not hold is one nothing reading
# the artifact can check. There is no `--name` escape hatch, deliberately — a
# principal is not the signer's to choose.
export def signing-principal [key: path pubkeys_dir: path]: nothing -> string {
    let pub_path = if ($key | str ends-with ".pub") { $key } else {
        let candidate = $"($key).pub"
        if not ($candidate | path exists) {
            error make {msg: $"public key file not found: ($candidate)"}
        }
        $candidate
    }
    let principal = fingerprint-file $pub_path
    if $principal not-in (registered-principals $pubkeys_dir) {
        error make {msg: $"the signing key \(($principal)\) is not registered in ($pubkeys_dir)/ — register it with `init --pubkey ($pub_path)`, or nothing reading this artifact can check the signature"}
    }
    $principal
}
