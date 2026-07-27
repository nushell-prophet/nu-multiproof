# Bootstrap multiproofs/ directory in a git repository.

use _repo.nu repo-root
use _layout.nu [multiproofs-dir pubkeys-dir]
use _fs.nu list-files
use _pubkey-helpers.nu canonical-file
use _allowed-signers.nu check-signer-name
use pubkey.nu

# Initialize multiproofs/ structure in a git repo.
# Creates the directory and registers the public key from a given path or git
# config. Keys land in `pubkey canonical` form — `<type> <base64>\n`, comment
# stripped — so their file bytes hash identically everywhere; the human label
# survives in the file name (see pubkey.nu for the full rationale).
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

    # Resolve pubkey to register
    let key_file = if $pubkey != null {
        resolve-pubkey-file $pubkey
    } else {
        # Try git config signing key
        let git_key = (do { ^git -C $root config user.signingKey } | complete)
        if $git_key.exit_code == 0 {
            let raw = $git_key.stdout | str trim
            if ($raw | str starts-with "key::") {
                # Inline key — canonicalize and save
                let key_data = $raw | str replace "key::" ""
                let canon = try { $key_data | pubkey canonical } catch {
                    error make {msg: "user.signingKey inline `key::` value is not an SSH public key — pubkeys/ must hold public keys only"}
                }
                let name = resolve-key-name $key_data
                let dest = $pubkeys_dir | path join $"($name).pub"
                if (check-registration $canon $dest $pubkeys_dir $root) {
                    $canon | save --force $dest
                    print $"Saved signing key as ($dest | path relative-to $root)"
                }
                return
            } else {
                # It's a file path
                let expanded = $raw | path expand
                # Why: keep soft-warning behavior for the git-config branch — a key
                # configured on another machine shouldn't hard-error init; --pubkey
                # can still recover. --pubkey itself has no such fallback (user
                # explicitly named the path), so resolve-pubkey-file errors there.
                if not (($expanded | path exists) or ($"($expanded).pub" | path exists)) {
                    print $"Warning: git signing key path not found: ($raw)"
                    print "Use --pubkey to specify a public key file"
                    return
                }
                resolve-pubkey-file $expanded
            }
        } else {
            print "No git signing key configured and no --pubkey given"
            print "Use --pubkey to specify a public key file"
            return
        }
    }

    # Checked before it becomes a file name: the stem is this key's principal in
    # every allowed_signers this repo renders, and `init --pubkey 'src/al
    # ice.pub'` used to print success while making every later `ssh-sign
    # verify`, `merkle verify` and `seal` in that repo throw before reaching a
    # verdict — denial of service, from one registration. `--pubkey 'src/*.pub'`
    # created a file literally named `*.pub`, a key trusted for every signer.
    # Reject, never normalize: renaming the source file is the operator's call,
    # not this command's. The inline `key::` branch above needs no such gate —
    # `resolve-key-name` builds its name from a sanitized comment or from a key
    # type `pubkey canonical` has already accepted.
    let name = check-signer-name ($key_file | path parse | get stem) $"pubkey file name ($key_file | path basename)"
    let dest = $pubkeys_dir | path join $"($name).pub"
    # Not cp because: the stored bytes are the identity downstream — they
    # must be canonical regardless of how the source file was written.
    let canon = open --raw $key_file | pubkey canonical
    if (check-registration $canon $dest $pubkeys_dir $root) {
        $canon | save --force $dest
        print $"Registered ($key_file | path basename) → ($dest | path relative-to $root)"
    }
}

# Decide what registering $canon at $dest means, by key material — never by
# path. Why: two different keys whose files share a stem land on the same
# $dest, and a path-only check reported "already exists" while keeping the
# first key — telling the operator a key was registered when it was refused.
# Returns true when the caller should write; prints and returns false when the
# key is already there; errors when the outcome is a refusal.
def check-registration [
    canon: string # canonical bytes of the key being registered
    dest: path # where this key would be written
    pubkeys_dir: path
    root: path
]: nothing -> bool {
    if ($dest | path exists) {
        let registered = canonical-file $dest
        if $registered == $canon {
            print $"pubkey already registered: ($dest | path relative-to $root)"
            return false
        }
        # Not overwriting because: pubkeys/ is the trust list, and silently
        # swapping an entry is worse than refusing. But the operator must hear
        # that the key was rejected, not registered.
        error make {msg: ([
            $"($dest | path relative-to $root) already holds a different key — refusing to overwrite the trust list"
            $"  registered: (fingerprint $registered)"
            $"  offered:    (fingerprint $canon)"
            "register the new key under another name"
        ] | str join "\n")}
    }

    let twins = list-files $pubkeys_dir --suffix ".pub" | where {|f| (canonical-file $f) == $canon }
    if ($twins | is-not-empty) {
        # Why an error and not a second copy: `ssh-sign` finds the signer name
        # by matching key material, so a duplicate under another stem makes
        # every later signature fail with `multiple pubkeys match`.
        error make {msg: $"this key \((fingerprint $canon)\) is already registered as ($twins | first | path relative-to $root) — a second copy under another name makes the signer ambiguous when signing"}
    }
    true
}

# SSH fingerprint of a canonical key line, for operator-facing messages only.
# Falls back to the key line itself so a fingerprint failure never replaces the
# real message.
def fingerprint [key: string]: nothing -> string {
    let out = $key | ^ssh-keygen -lf - | complete
    if $out.exit_code == 0 {
        $out.stdout | str trim | split row " " | get 1
    } else {
        $key | str trim
    }
}

# Every branch that writes to pubkeys/ runs `pubkey canonical` first, so a
# private key (multi-line, no pubkey type prefix) can never land — that much is
# pinned by the private-key refusal tests.
#
# `pubkey canonical` also hands the line to ssh-keygen and refuses anything
# that parser will not load, so an off-curve point no longer lands
# (tests/test_pubkey.nu "canonical never accepts a key ssh-keygen cannot
# load"). Loadable is not the same as usable: nothing here says anyone holds
# the matching private key, only that a verifier can read the entry.

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

# Derive a short name from an SSH public key string. The result becomes a file
# name under pubkeys/ and, through that stem, a principal in the trust list.
# Split on `\s+`, not on a single space: `ssh-ed25519  AAAA…` (two spaces, no
# comment) otherwise parses as three fields and names the file after the whole
# base64 blob.
def resolve-key-name [key: string]: nothing -> string {
    let parts = $key | str trim | split row --regex '\s+'
    # 3+ fields = type, base64, comment — use comment. It is free text from
    # another machine, so strip it to alphanumeric/hyphen/underscore.
    if ($parts | length) >= 3 {
        $parts | last | str replace --all --regex '[^a-zA-Z0-9_-]' '' | str replace --regex '^$' 'signer'
    } else {
        # No comment — derive from the key type. Not sanitized because it can
        # only be one of the types `pubkey canonical` accepts; the caller has
        # already run it. That is what stops `key::ssh-../../../../pwned Zm9v`,
        # which used to name a path outside pubkeys/.
        $parts | first | str replace "@openssh.com" "" | str replace "sk-ecdsa-sha2-nistp256" "ecdsa-sk" | str replace "ssh-" ""
    }
}
