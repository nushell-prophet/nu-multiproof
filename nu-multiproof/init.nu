# Bootstrap multiproofs/ directory in a git repository.

# Initialize multiproofs/ structure in a git repo.
# Creates the directory, copies public keys from ssh-agent or a given path.
export def main [
    --repo: path # Target git repo root (default: git root of current directory)
    --pubkey: path # SSH public key file to copy (default: signing key from git config)
] {
    let root = if $repo != null { $repo | path expand } else {
        ^git rev-parse --show-toplevel | str trim
    }
    let multiproofs = $root | path join "multiproofs"
    let pubkeys_dir = $multiproofs | path join "pubkeys"

    if ($multiproofs | path exists) {
        print $"multiproofs/ already exists in ($root)"
    } else {
        mkdir $multiproofs
        print $"Created ($multiproofs)/"
    }

    mkdir $pubkeys_dir

    # Resolve pubkey to copy
    let key_file = if $pubkey != null {
        resolve-pubkey-file $pubkey
    } else {
        # Try git config signing key
        let git_key = (do { ^git -C $root config user.signingKey } | complete)
        if $git_key.exit_code == 0 {
            let raw = $git_key.stdout | str trim
            if ($raw | str starts-with "key::") {
                # Inline key — save it directly
                let key_data = $raw | str replace "key::" ""
                let name = resolve-key-name $key_data
                let dest = $pubkeys_dir | path join $"($name).pub"
                if ($dest | path exists) {
                    print $"pubkey already exists: ($dest | path relative-to $root)"
                } else {
                    $key_data | save --force $dest
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
        cp $key_file $dest
        print $"Copied ($key_file | path basename) → ($dest | path relative-to $root)"
    }
}

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
    if ($first_line | str starts-with "ssh-") or ($first_line | str starts-with "sk-") or ($first_line | str starts-with "ecdsa-") {
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
