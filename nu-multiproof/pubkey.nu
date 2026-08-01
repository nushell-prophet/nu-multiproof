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
# several identities. Nothing human survives: a key's name in this project is
# its fingerprint (see `fingerprint` below), which is why the comment has
# nowhere to go rather than moving to the file name.

use _temp-helpers.nu with-temp-dir

# The key types accepted here. An allowlist and not a `ssh-`/`sk-`/`ecdsa-`
# prefix test because the type string travels: it is written into
# `allowed_signers` lines, and `init` derives a *filename* from it for a key
# with no comment. `ssh-../../../../tmp/pwn Zm9v` passes any prefix test and
# named a path outside pubkeys/. A key type OpenSSH grows later is a one-line
# addition here; until then, unknown type is a refusal.
#
# No `ssh-dss`: OpenSSH 10 removed DSA, so `ssh-keygen` here neither generates
# such a key nor reads one back. Keeping the type would have meant accepting
# into pubkeys/ a key that no `ssh-keygen -Y verify` on this machine can use —
# a trust-list entry that verifies nothing.
#
# Certificates (`ssh-ed25519-cert-v01@openssh.com`) are absent on purpose:
# ssh-keygen reads them, this module refuses them.
const KEY_TYPES = [
    "ssh-rsa"
    "ssh-ed25519"
    "ecdsa-sha2-nistp256"
    "ecdsa-sha2-nistp384"
    "ecdsa-sha2-nistp521"
    "sk-ssh-ed25519@openssh.com"
    "sk-ecdsa-sha2-nistp256@openssh.com"
]

# Reduce an SSH public key line to canonical form: `<type> <base64>\n`.
# Errors on anything that is not one well-formed public key of a known type,
# and on a key whose bytes are not the ones OpenSSH writes for it.
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

    # The type appears twice — outside the blob and as its first field — and
    # OpenSSH reads the inner one, so the allowlist above only says what the
    # line *claims*. Everything about the key material is decided by the parser
    # that will actually have to load it.
    let candidate = $"($key_type) ($parts.1)"
    let reserialized = openssh-reserialize $candidate
    if $reserialized != $candidate {
        error make {
            msg: (
                [
                    "SSH pubkey is not the encoding OpenSSH writes for this key"
                    $"  given:    ($candidate)"
                    $"  OpenSSH:  ($reserialized)"
                ] | str join "\n"
            )
        }
    }
    $"($candidate)\n"
}

# The key's principal: the SHA-256 of its key blob, lowercase hex.
#
# This is the one identity this project hands out — the principal in every
# rendered `allowed_signers`, the signer label in `<file>.<signer>.sig`, and the
# value `merkle verify --signer` takes. It is derived from key material and from
# nothing else, so no file name and no flag can claim it: mallory's key filed as
# `alice.pub` renders mallory's fingerprint, and there is no name left for a
# verifier to be fooled by. Everything the old filename-as-principal grammar
# needed — a charset gate on stems and `--name`, twin detection, name derivation
# from a key comment — is gone with it.
#
# Why lowercase hex and not OpenSSH's `SHA256:<base64>` spelling of the very
# same digest: base64 holds `/`, and a principal becomes a path component
# (`<principal>.pub`, `<file>.<principal>.sig`). One form that is legal in a
# filename, in an allowed_signers line and on a command line beats two forms to
# keep in sync — and hex is what every other digest in this project is written
# as. `ssh-keygen -lf` prints the same bytes; the two are pinned against each
# other by tests/test_pubkey.nu "fingerprint is the digest ssh-keygen prints".
#
# Why `canonical` first, rather than hashing whatever arrives: the digest is
# over the blob bytes as given, and a padded copy of a key has different blob
# bytes while OpenSSH reports the same fingerprint for it. Hashing an
# unvalidated line would hand one key a second principal — the identity fork
# `canonical` exists to close, re-opened one function along.
@example "the principal a stored public key signs under" {
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOi7LinplEQewM3/l8Ol9rE85+YwhvLPKf+ZUUf36Xuf" | nu-multiproof pubkey fingerprint
} --result "b610a91de8fa99e224f6b2e7fb6bb8c9e8f0303f8d72d14e5a494ab8d1c68011"
export def fingerprint []: string -> string {
    $in | canonical | str trim | split row " " | get 1 | decode base64 | hash sha256
}

# The key line as OpenSSH itself would write it, or an error naming why it
# could not read the key.
#
# Why an export/import round trip and not `ssh-keygen -lf`: -lf answers "can
# this be loaded", which is only half the question. RFC 4251 lets an RSA mpint
# carry a redundant leading zero byte, and OpenSSH *trims* leading zeros while
# parsing rather than refusing them — so `-lf` accepts a padded copy of alice's
# key, exits 0 and prints alice's own fingerprint. That padded copy is a second
# canonical line for one key, hence a second file-byte CID, hence a second
# identity: mallory registered one as `mallory.pub`, alice signed, and
# `ssh-sign verify` reported mallory as the signer of alice's signature.
# `init`'s duplicate check compares canonical bytes, so it did not fire.
#
# -e writes the key out in RFC 4716 form and -i reads it back, which forces
# OpenSSH to parse the blob into its own structures and re-serialize it with
# its own encoder. The result is a fixed point for every type in KEY_TYPES —
# all seven, the two sk-* ones through hand-assembled vectors, since
# `ssh-keygen -t ed25519-sk` needs hardware present (pinned by "canonical is a
# fixed point for real keys of every accepted type"). A difference therefore
# means the input was not what OpenSSH writes. RFC 4716
# and not PEM/PKCS8 because it is the one -m format that covers ed25519 and
# sk-* too. The envelope carries a `Comment:` header naming the local user and
# host; -i drops it, and only `<type> <base64>` is ever compared or returned.
#
# Reject rather than return OpenSSH's version: the caller is registering key
# material into a trust list, and silently storing bytes other than the ones it
# was handed is how one key becomes two identities in the first place.
def openssh-reserialize [line: string]: nothing -> string {
    # Why this is asked before any work: a missing binary makes an external call
    # *throw*, and `complete` does not catch that — only a non-zero exit. The
    # throw travelled up to `canonical-file`, which wrapped it as "<file> is not
    # an SSH public key: External command failed", so a broken toolchain read as
    # a verdict about the operator's key — and through `merkle verify`, as
    # `valid: false` on the artifact. Fail-closed either way; the difference is
    # what the operator goes looking for.
    for tool in ["ssh-keygen" "chmod"] {
        if (which $tool | is-empty) {
            error make {msg: $"($tool) is not on PATH — deciding what an SSH key is needs OpenSSH. This is a toolchain problem, not a problem with the key."}
        }
    }
    with-temp-dir "pubkey" {|dir|
        let source = $dir | path join "key.pub"
        let envelope = $dir | path join "key.rfc4716"
        $"($line)\n" | save --force $source
        # Why 0600 on a *public* key: when -e cannot read the line as a public
        # key it retries it as a private one, and a private key at the default
        # umask trips the UNPROTECTED PRIVATE KEY FILE banner. The operator then
        # got a permissions complaint about a temp path that no longer exists
        # instead of `invalid format` — a message that changed with their umask.

        ^chmod 600 $source

        let exported = do { ^ssh-keygen -e -m RFC4716 -f $source } | complete
        if $exported.exit_code != 0 {
            # Why `complete`: ssh-keygen writes the reason ("invalid format",
            # "unknown key type") to stderr, and a bare external call would
            # throw with none of it reaching the operator. The temp path is
            # swapped out of the text — it is gone by the time anyone reads
            # this, and sending the operator to look for it is worse than
            # saying nothing.
            error make {msg: $"ssh-keygen cannot read this SSH pubkey: (reason $exported $source)"}
        }
        $exported.stdout | save --force $envelope

        let imported = do { ^ssh-keygen -i -m RFC4716 -f $envelope } | complete
        if $imported.exit_code != 0 {
            error make {msg: $"ssh-keygen cannot read back this SSH pubkey: (reason $imported $envelope)"}
        }
        $imported.stdout | str trim
    }
}

# What ssh-keygen said, with the temp path it names replaced by what that path
# held. The caller is looking at a key line, not at a file this module made.
def reason [result: record path: path]: nothing -> string {
    $result.stderr | str trim | str replace --all $path "the given key"
}
