# Bootstrap multiproofs/ directory in a git repository.

use _repo.nu repo-root
use _layout.nu [multiproofs-dir pubkeys-dir]
use _fs.nu list-files
use _pubkey-helpers.nu canonical-file
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

    let name = $key_file | path parse | get stem
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
# `pubkey canonical` also decodes the key material and checks that the blob's
# own type field matches the declared one (tests/test_pubkey.nu "canonical
# rejects key material that is not a key"), so `ssh-rsa A` no longer passes.
# What it does not check is whether the key is *usable* — a well-formed blob
# with a garbage public point still lands.

# Resolve an SSH key path to its public-key file.
# Why: --pubkey and the user.signingKey file-path branch must never copy a
# private key into pubkeys/. Prefer the `.pub` sibling when present (forgiving
# misconfig); otherwise validate the file's first line looks like an SSH pubkey.
def resolve-pubkey-file [key_path: path]: nothing -> path {
    let expanded = $key_path | path expand
    let pub_sibling = $"($expanded).pub"
    if ($pub_sibling | path exists) {
        return ($pub_sibling | into string | path expand)
    }
    if not ($expanded | path exists) {
        error make {msg: $"pubkey file not found: ($key_path)"}
    }
    let first_line = (open --raw $expanded | lines | first | default "")
    if (try { $first_line | pubkey canonical } | is-not-empty) {
        $expanded
    } else {
        error make {msg: $"($key_path) does not look like an SSH public key — point at the .pub file"}
    }
}

# Derive a short name from an SSH public key string
def resolve-key-name [key: string]: nothing -> string {
    let parts = $key | str trim | split row " "
    # 3+ fields = type, base64, comment — use comment
    if ($parts | length) >= 3 {
        # Sanitize: take alphanumeric/hyphen/underscore only
        $parts | last | str replace --all --regex '[^a-zA-Z0-9_-]' '' | str replace --regex '^$' 'signer'
    } else {
        # No comment — derive from key type
        $parts | first | str replace "@openssh.com" "" | str replace "sk-ecdsa-sha2-nistp256" "ecdsa-sk" | str replace "ssh-" ""
    }
}
