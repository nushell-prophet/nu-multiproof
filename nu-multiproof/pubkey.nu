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

# The key types accepted here, and the blob each one must hold. An allowlist
# and not a `ssh-`/`sk-`/`ecdsa-` prefix test because the type string travels:
# it is written into `allowed_signers` lines, and `init` derives a *filename*
# from it for a key with no comment. `ssh-../../../../tmp/pwn Zm9v` passes any
# prefix test and named a path outside pubkeys/. A key type OpenSSH grows later
# is a one-line addition here; until then, unknown type is a refusal.
#
# Why the shape and not just the field walk: counting length-prefixed fields
# only proves the bytes divide evenly. `ssh-keygen -lf` refused five lines this
# accepted — an ed25519 point of 16 bytes and of 0 bytes, a valid key with one
# extra field appended, an `ssh-rsa` missing its modulus, and an
# `ecdsa-sha2-nistp256` whose curve field says nistp384. pubkeys/ is the trust
# list, so what this accepts and what OpenSSH accepts must be the same set
# (tests/test_pubkey.nu "canonical and ssh-keygen accept the same keys").
#
# No `ssh-dss`: OpenSSH 10 removed DSA, so `ssh-keygen` here neither generates
# such a key nor reads one back. Keeping the type would have meant accepting
# into pubkeys/ a key that no `ssh-keygen -Y verify` on this machine can use —
# a trust-list entry that verifies nothing — and no vector could be generated
# to hold it to the same standard as every other type.
#
#   fields  — exact number of length-prefixed fields, the type field included
#   curve   — required text of the curve field, for the types that name one
#   key_at  — index of the field whose length is fixed, with key_len its size
const KEY_SHAPES = [
    [type fields curve key_at key_len];
    ["ssh-rsa" 3 null null null]
    ["ssh-ed25519" 2 null 1 32]
    ["ecdsa-sha2-nistp256" 3 "nistp256" 2 65]
    ["ecdsa-sha2-nistp384" 3 "nistp384" 2 97]
    ["ecdsa-sha2-nistp521" 3 "nistp521" 2 133]
    ["sk-ssh-ed25519@openssh.com" 3 null 1 32]
    ["sk-ecdsa-sha2-nistp256@openssh.com" 4 "nistp256" 2 65]
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
    let shape = $KEY_SHAPES | where type == $key_type
    if ($shape | is-empty) {
        error make {msg: $"not a known SSH public key type: ($key_type)"}
    }
    let shape = $shape | first
    let blob = try { $parts.1 | decode base64 } catch {
        error make {msg: "SSH pubkey key material is not base64"}
    }
    # Why the blob is parsed and not just shape-matched: these bytes are the
    # identity every verifier downstream reads, and the old shape check
    # accepted `ssh-rsa A`. A blob that is not an exact sequence of
    # length-prefixed fields is truncated or padded — not a key.
    let fields = ssh-blob-fields $blob
    if $fields == null {
        error make {msg: $"SSH pubkey blob is not a sequence of length-prefixed fields: ($key_type)"}
    }
    if ($fields | length) != $shape.fields {
        error make {msg: $"($key_type) holds ($shape.fields) blob fields, this one has ($fields | length)"}
    }
    # The type appears twice — outside the blob and as its first field. OpenSSH
    # reads the inner one, so a mismatch means the line lies about what the key
    # is.
    let blob_type = try { $fields.0 | decode } catch { "" }
    if $blob_type != $key_type {
        error make {msg: $"SSH pubkey says ($key_type) but its blob holds ($blob_type)"}
    }
    # The curve is named twice for the same reason, and OpenSSH again reads the
    # inner one: `ecdsa-sha2-nistp256` over a nistp384 field is not a key it
    # will load.
    if $shape.curve != null {
        let curve = try { $fields.1 | decode } catch { "" }
        if $curve != $shape.curve {
            error make {msg: $"($key_type) must name curve ($shape.curve), its blob names ($curve)"}
        }
    }
    # The types whose key field is a fixed size: an ed25519 point is 32 bytes
    # and an EC point is `04 || x || y` at the curve's width. RSA carries
    # mpints whose length is the key's, so only its field count is fixed.
    # Nothing here proves the point is *on* the curve — that check lives in
    # OpenSSH, and this module never claims a key is usable.
    if $shape.key_at != null {
        let actual = $fields | get $shape.key_at | bytes length
        if $actual != $shape.key_len {
            error make {msg: $"($key_type) key material is ($shape.key_len) bytes, this one has ($actual)"}
        }
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
        # 4 bytes read big-endian are unsigned (0xffffffff -> 4294967295), so an
        # oversized length can only overshoot the buffer, never wrap negative.
        let len = $blob | bytes at $offset..<($offset + 4) | into int --endian big
        let start = $offset + 4
        if ($total - $start) < $len { return null }
        $fields = ($fields | append [($blob | bytes at $start..<($start + $len))])
        $offset = $start + $len
    }
    $fields
}
