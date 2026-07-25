# Reading a stored public key file as key material.
#
# Why one helper and not `open --raw` at each site: `ssh-sign` had its own
# `split row " " | first 2`, which yields empty key material for
# `ssh-ed25519  AAAA…` (two spaces) — and two such keys then compare *equal*,
# so the signer lookup matched the wrong key. Key material has one definition,
# `pubkey canonical`, and every reader goes through it.

use pubkey.nu

# Canonical bytes of a stored pubkey file, naming the file when it is not one.
# Fail loudly: a file in a trust list that is not a public key is a broken
# trust list, not something to skip over, and the operator needs the name to
# fix it.
export def canonical-file [file: path]: nothing -> string {
    try {
        open --raw $file | pubkey canonical
    } catch {|e|
        error make {msg: $"($file) is not an SSH public key: ($e.msg)"}
    }
}
