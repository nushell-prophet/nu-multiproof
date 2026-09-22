# Render an OpenSSH allowed_signers body from every *.pub in a directory.
# Used by ssh-sign verify (named principals, so find-principals returns the
# signer) and by merkle verify to resolve --signer.

use _fs.nu list-files
use _pubkey-helpers.nu [ canonical-file fingerprint-file ]
use pubkey.nu

# The one namespace this repo signs and verifies under. A const and not a flag:
# `--namespace` was interpolated into the line raw, right beside the principal,
# so a value holding `"` and a newline wrote an extra trust-list entry and
# `ssh-sign verify --namespace <payload>` returned `valid: true` for a key that
# is not in pubkeys/ at all. Without a newline one quote still injected an
# option: `file",cert-authority,namespaces="file` rendered every registered key
# as a certificate authority. No caller ever passed a non-default value, so the
# flag bought a hole and nothing else. Validating it would have been guarding an
# input that does not exist.
export const NAMESPACE = "file"

# One line per pubkey: `<fingerprint> namespaces="file" <key>`.
#
# Why the principal is derived from the key rather than read off the file name:
# a line here is a trust statement, and a file name is chosen by whoever put the
# file there. Nothing a file name holds reaches this line, so `pubkeys/*.pub`
# may be called anything at all and mallory's key filed as `alice.pub` renders
# mallory's fingerprint.
#
# Why every key goes through `pubkey canonical` rather than being copied
# through: a key file holding two lines emitted a principal-less second line.
# ssh-keygen does not reject the file over it — it writes "<file>:1: invalid
# key" to stderr, skips that line and carries on (measured on OpenSSH 10.2p1;
# pinned by tests/test_allowed-signers.nu "ssh-keygen skips a malformed entry
# rather than failing"). Skipping is the worse outcome: the rendered trust
# list no longer says what pubkeys/ says, the warning is swallowed by the
# `complete` wrapped around every ssh-keygen call here, and the signer whose
# key is broken comes back as an unrecognized signer with nothing pointing at
# the cause. A broken trust list is an error, raised at the file that broke it.
export def allowed-signers-body [pubkeys_dir: path]: nothing -> string {
    # Why a `for` and not an `each`: an `error make` raised inside a closure
    # reaches the caller as "Eval block failed with pipeline input", with the
    # message naming the broken file buried in `$e.inner`. The operator has to
    # be told which file to fix.
    mut lines = []
    for file in (list-files $pubkeys_dir --suffix ".pub") {
        let key = canonical-file $file | str trim
        $lines = ($lines | append $"($key | pubkey fingerprint) namespaces=\"($NAMESPACE)\" ($key)")
    }
    $lines | str join "\n"
}

# Every principal a trust list holds. Read from key material, so this is the
# same set the rendered body carries — two lookups of one fact would be two
# places to drift.
export def registered-principals [pubkeys_dir: path]: nothing -> list<string> {
    list-files $pubkeys_dir --suffix ".pub" | each { fingerprint-file $in }
}

# Refuse a --signer whose key the trust list does not hold.
#
# Why an error rather than a negative verdict: "alice did not sign this" is a
# claim, and a verifier without alice's key cannot make it — the honest answer
# is "I cannot tell". Asked before any other work. Shared here because the rule
# being applied is this module's: a principal is a key's fingerprint.
export def check-signer-known [signer: string pubkeys_dir: path]: nothing -> string {
    let known = registered-principals $pubkeys_dir
    if $signer not-in $known {
        error make {
            msg: $"no key with fingerprint ($signer) in ($pubkeys_dir)/ — this verifier cannot say whether that key signed anything without holding it. Registered: ($known | str join ', ')"
            help: "a principal is the sha256 of a key blob, 64 lowercase hex — `pubkey fingerprint` over a key line prints it. It is the same digest `ssh-keygen -lf` prints, written as hex rather than base64."
        }
    }
    $signer
}
