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

# The key types accepted here. An allowlist and not a `ssh-`/`sk-`/`ecdsa-`
# prefix test because the type string travels: it is written into
# `allowed_signers` lines, and `init` derives a *filename* from it for a key
# with no comment. `ssh-../../../../tmp/pwn Zm9v` passes any prefix test and
# named a path outside pubkeys/. A key type OpenSSH grows later is a one-line
# addition here; until then, unknown type is a refusal.
const KEY_TYPES = [
    "ssh-rsa"
    "ssh-dss"
    "ssh-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    "sk-ssh-ed25519@openssh.com"
    "sk-ecdsa-sha2-nistp256@openssh.com"
]

# Reduce an SSH public key line to canonical form: `<type> <base64>\n`.
# Errors on anything that is not one well-formed public key of a known type.
export def canonical []: string -> string {
    let line = $in | str trim
    if ($line | lines | length) > 1 {
        error make {msg: "not a single-line SSH public key"}
    }
    let parts = $line | split row --regex '\s+'
    if ($parts | length) < 2 {
        error make {msg: "does not look like an SSH public key (`<type> <base64> [comment]`)"}
    }
    let key_type = $parts.0
    if $key_type not-in $KEY_TYPES {
        error make {msg: $"not a known SSH public key type: ($key_type)"}
    }
    let blob = try { $parts.1 | decode base64 } catch {
        error make {msg: "SSH pubkey key material is not base64"}
    }
    # Why the blob is parsed and not just shape-matched: these bytes are the
    # identity every verifier downstream reads, and the old shape check
    # accepted `ssh-rsa A`. A blob that is not an exact sequence of
    # length-prefixed fields is truncated or padded — not a key.
    let fields = ssh-blob-fields $blob
    if $fields == null or ($fields | length) < 2 {
        error make {msg: $"SSH pubkey blob is not a sequence of length-prefixed fields: ($key_type)"}
    }
    # The type appears twice — outside the blob and as its first field. OpenSSH
    # reads the inner one, so a mismatch means the line lies about what the key
    # is.
    let blob_type = try { $fields.0 | decode } catch { "" }
    if $blob_type != $key_type {
        error make {msg: $"SSH pubkey says ($key_type) but its blob holds ($blob_type)"}
    }
    $"($key_type) ($parts.1)\n"
}

# Split an SSH key blob into its length-prefixed fields (RFC 4253 `string`:
# 4-byte big-endian length, then that many bytes). Returns null when the bytes
# do not divide exactly into such fields — a short length prefix, a length
# running past the end, or trailing bytes after the last field.
def ssh-blob-fields [blob: binary]: nothing -> any {
    let total = $blob | bytes length
    mut fields = []
    mut offset = 0
    while $offset < $total {
        if ($total - $offset) < 4 { return null }
        let len = $blob | bytes at $offset..<($offset + 4) | into int --endian big
        let start = $offset + 4
        if $len < 0 or ($total - $start) < $len { return null }
        $fields = ($fields | append [($blob | bytes at $start..<($start + $len))])
        $offset = $start + $len
    }
    $fields
}
