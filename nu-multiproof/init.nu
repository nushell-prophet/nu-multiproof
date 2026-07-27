# Bootstrap multiproofs/ directory in a git repository.

use _repo.nu repo-root
use _layout.nu [multiproofs-dir pubkeys-dir]
use _pubkey-helpers.nu canonical-file
use pubkey.nu

# Initialize multiproofs/ structure in a git repo.
# Creates the directory and registers the public key from a given path or git
# config. A key is stored as `<fingerprint>.pub` in `pubkey canonical` form —
# `<type> <base64>\n`, comment stripped — so its file bytes hash identically
# everywhere and its name says which key it is (see pubkey.nu).
@example "bootstrap multiproofs/ in the current repo" { init }
export def main [
    --repo: path # Target git repo root (default: git root of current directory)
    --pubkey: path # SSH public key file to register (default: signing key from git config)
] {
    let root = repo-root $repo
    let multiproofs = multiproofs-dir $root
    let pubkeys_dir = pubkeys-dir $root

    if ($multiproofs | path exists) {
        print $"multiproofs/ already exists in ($root)"
    } else {
        mkdir $multiproofs
        print $"Created ($multiproofs)/"
    }

    mkdir $pubkeys_dir

    # Canonical bytes of the key to register, or null when there is nothing to
    # register and the operator has been told why.
    let canon = resolve-key $root $pubkey
    if $canon != null {
        register $canon $pubkeys_dir $root
    }
}

# Which key this run registers: --pubkey when given, otherwise git's
# user.signingKey in either of its two forms.
#
# Every branch ends in `pubkey canonical`, so a private key (multi-line, no
# pubkey type prefix) can never land — that much is pinned by the private-key
# refusal tests. It also hands the line to ssh-keygen and refuses anything that
# parser will not load, so an off-curve point does not land either
# (tests/test_pubkey.nu "canonical never accepts a key ssh-keygen cannot load").
# Loadable is not the same as usable: nothing here says anyone holds the matching
# private key, only that a verifier can read the entry.
def resolve-key [root: path, pubkey: any]: nothing -> any {
    if $pubkey != null {
        return (canonical-file (resolve-pubkey-file $pubkey))
    }
    let git_key = (do { ^git -C $root config user.signingKey } | complete)
    if $git_key.exit_code != 0 {
        print "No git signing key configured and no --pubkey given"
        print "Use --pubkey to specify a public key file"
        return null
    }
    let raw = $git_key.stdout | str trim
    if ($raw | str starts-with "key::") {
        let key_data = $raw | str replace "key::" ""
        # Why the inner message survives (same shape as canonical-file, which
        # names the source file; the source here is git config): replacing it
        # wholesale answered "is not an SSH public key" for every refusal alike
        # — a padded second encoding of a REAL key lost the canonical error
        # naming both encodings, and a missing ssh-keygen (310c29b) read as a
        # verdict about the key. Either way the operator went looking for the
        # wrong problem — see resolve-pubkey-file below.
        return (try { $key_data | pubkey canonical } catch {|e|
            error make {msg: $"user.signingKey inline `key::` value: ($e.msg)"}
        })
    }
    let expanded = $raw | path expand
    # Why: keep soft-warning behavior for the git-config branch — a key
    # configured on another machine shouldn't hard-error init; --pubkey
    # can still recover. --pubkey itself has no such fallback (user
    # explicitly named the path), so resolve-pubkey-file errors there.
    if not (($expanded | path exists) or ($"($expanded).pub" | path exists)) {
        print $"Warning: git signing key path not found: ($raw)"
        print "Use --pubkey to specify a public key file"
        return null
    }
    canonical-file (resolve-pubkey-file $expanded)
}

# Store the key under its fingerprint, or say why nothing was stored.
#
# Why the name is the fingerprint and not anything the operator supplies: the
# name used to be the source file's stem (or, for an inline key, a sanitized key
# comment), which made it this key's principal in every rendered trust list —
# hence a charset gate on it, a refusal for a stem another registered key already
# used, a scan for the same key material filed under a second name, and a rule
# about what a key comment may become. None of that is here: two files cannot
# hold one key under two names, because one key has one fingerprint, and no name
# reaches a trust list at all (see _allowed-signers.nu).
#
# Not an `--as <label>` flag for a human-readable name, because: nothing reads the
# name, so `mv` already gives a key any name the operator wants, and a key placed
# in pubkeys/ by hand keeps whatever it is called — both pinned by
# tests/test_ssh-sign.nu "a pubkey file name the trust list could never express
# still signs and verifies". A flag would buy that one step and bring back the two
# rules the fingerprint removed: a collision when a label is already taken by
# another key, and a gate on the label (a `/` writes outside pubkeys/, and a
# control byte makes a name `ls` cannot round-trip, which throws on every later
# render — see todo/20260727-023419). Same call as `merkle prove --out`, deleted
# in ad1f7ab: `mv` is the escape hatch.
def register [canon: string, pubkeys_dir: path, root: path] {
    let principal = $canon | pubkey fingerprint
    let dest = $pubkeys_dir | path join $"($principal).pub"

    if ($dest | path exists) {
        if (canonical-file $dest) == $canon {
            print $"pubkey already registered: ($dest | path relative-to $root)"
            return
        }
        # Not reachable through this command — the name IS the fingerprint of the
        # bytes being written — so this only fires on a hand-edited pubkeys/,
        # where the file's name says one key and its body holds another. Refuse
        # rather than overwrite: pubkeys/ is the trust list, and a file whose
        # name contradicts its contents is a question for the operator. The
        # rendered principal comes from the body either way, so the lie costs no
        # verifier anything — it just makes this the wrong place to write.
        error make {msg: ([
            $"($dest | path relative-to $root) is named for this key's fingerprint but holds a different key — refusing to overwrite the trust list"
            $"  stored there: (ssh-fingerprint (canonical-file $dest))"
            $"  offered:      (ssh-fingerprint $canon)"
            "the file was not written by `init`; remove or rename it, then register again"
        ] | str join "\n")}
    }

    $canon | save --force $dest
    # Both spellings of one digest: the name this repo uses, and the form
    # `ssh-keygen -lf` prints, so the operator can check the registration
    # against a key they hold without converting anything.
    print $"Registered ($dest | path relative-to $root)"
    print $"  ssh-keygen -lf: (ssh-fingerprint $canon)"
}

# The `SHA256:<base64>` spelling OpenSSH prints for a canonical key line — for
# operator-facing messages only, never as an identity this code compares.
# Falls back to the key line itself so a fingerprint failure never replaces the
# real message.
def ssh-fingerprint [key: string]: nothing -> string {
    let out = $key | ^ssh-keygen -lf - | complete
    if $out.exit_code == 0 {
        $out.stdout | str trim | split row " " | get 1
    } else {
        $key | str trim
    }
}

# Resolve an SSH key path to its public-key file.
# Why: --pubkey and the user.signingKey file-path branch must never copy a
# private key into pubkeys/. Prefer the `.pub` sibling when present (forgiving
# misconfig); otherwise run the whole file through `pubkey canonical`, which a
# private key fails on its second line.
def resolve-pubkey-file [key_path: path]: nothing -> path {
    let expanded = $key_path | path expand
    let pub_sibling = $"($expanded).pub"
    if ($pub_sibling | path exists) {
        return ($pub_sibling | into string | path expand)
    }
    if not ($expanded | path exists) {
        error make {msg: $"pubkey file not found: ($key_path)"}
    }
    # Why canonical-file and not a `try … | is-not-empty`: the swallowed form
    # answered "does not look like an SSH public key" for every refusal alike,
    # including a key ssh-keygen loads happily and this module rejects for its
    # *encoding* — an operator reading that would go looking for the wrong
    # problem. canonical-file raises the real reason with the file's name on it.
    # A private key fails here too: it is multi-line, which canonical refuses.
    canonical-file $expanded
    $expanded
}
