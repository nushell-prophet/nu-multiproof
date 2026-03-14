# Bootstrap multiproofs/ directory in a git repository.

# Initialize multiproofs/ structure in a git repo.
# Creates the directory, copies public keys from ssh-agent or a given path.
export def main [
    --path: path       # Target git repo root (default: git root of current directory)
    --pubkey: path     # SSH public key file to copy (default: signing key from git config)
] {
    let root = if $path != null { $path | path expand } else {
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
        $pubkey
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
                if ($expanded | path exists) {
                    $expanded
                } else if ($"($expanded).pub" | path exists) {
                    $"($expanded).pub"
                } else {
                    print $"Warning: git signing key path not found: ($raw)"
                    print "Use --pubkey to specify a public key file"
                    return
                }
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

# Derive a short name from an SSH public key string
def resolve-key-name [key: string]: nothing -> string {
    let parts = $key | str trim | split row " "
    # 3+ fields = type, base64, comment — use comment
    if ($parts | length) >= 3 {
        # Sanitize: take alphanumeric/hyphen/underscore only
        $parts | last | str replace --regex '[^a-zA-Z0-9_-]' '' | str replace --regex '^$' 'signer'
    } else {
        # No comment — derive from key type
        $parts | first | str replace "@openssh.com" "" | str replace "sk-ecdsa-sha2-nistp256" "ecdsa-sk" | str replace "ssh-" ""
    }
}
