# SSH public key canonical form.
#
# Downstream (nu-cybergraph) an identity is the CID of the pubkey *file
# bytes* — hash the file, compare, no SSH parsing in the trust path. For that
# hash to be stable the bytes must have exactly one encoding, so the parsing
# happens once, at the write/import boundary: `init` stores keys in canonical
# form.
#
# Only that boundary enforces it. No verifier re-checks the form of a pubkey it
# reads, so a key that reached pubkeys/ by any other route (hand-edited,
# unpacked from a bundle) keeps whatever bytes it has, and its CID identity
# differs from the same key stored through `init`.
#
# Canonical form: `<type> <base64>` plus a trailing newline — no comment, no
# extra whitespace. Why the comment goes: it is mutable metadata (`user@host`
# drifts across machines and re-saves) and would silently fork one key into
# several identities. The human label lives in the pubkey's file *name*.

# Reduce an SSH public key line to canonical form: `<type> <base64>\n`.
# Errors on anything that does not look like `<type> <base64> [comment]`.
export def canonical []: string -> string {
    let line = $in | str trim
    if ($line | lines | length) > 1 {
        error make {msg: "not a single-line SSH public key"}
    }
    let parts = $line | split row --regex '\s+'
    let is_pubkey_type = ["ssh-" "sk-" "ecdsa-"] | any {|p| $parts.0 | str starts-with $p }
    if ($parts | length) < 2 or not $is_pubkey_type {
        error make {msg: "does not look like an SSH public key (`<type> <base64> [comment]`)"}
    }
    if not ($parts.1 =~ '^[A-Za-z0-9+/]+={0,2}$') {
        error make {msg: "SSH pubkey key material is not base64"}
    }
    $"($parts.0) ($parts.1)\n"
}
