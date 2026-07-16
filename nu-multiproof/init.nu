# Bootstrap multiproofs/ directory in a git repository.

use _repo.nu repo-root
use _layout.nu [multiproofs-dir pubkeys-dir]
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
                if ($dest | path exists) {
                    print $"pubkey already exists: ($dest | path relative-to $root)"
                } else {
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
    if ($dest | path exists) {
        print $"pubkey already exists: ($dest | path relative-to $root)"
    } else {
        # Not cp because: the stored bytes are the identity downstream — they
        # must be canonical regardless of how the source file was written.
        open --raw $key_file | pubkey canonical | save --force $dest
        print $"Registered ($key_file | path basename) → ($dest | path relative-to $root)"
    }
}

# The one shape check behind init's rule that nothing but a public key lands
# in pubkeys/ is `pubkey canonical` — every branch that writes there runs it,
# so a private key (multi-line, no pubkey type prefix) can never land.

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
