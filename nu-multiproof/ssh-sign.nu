# SSH file signing and verification via ssh-keygen.

# Sign a file with an SSH key.
# Creates {path}.{name}.sig alongside the input file.
export def sign [
    path: path           # File to sign
    --key: path          # SSH private key path (or public key if agent has the private key)
    --name: string       # Signer name for the .sig file (default: key filename stem)
    --namespace: string = "file"
] {
    ^ssh-keygen -Y sign -f $key -n $namespace $path
    let default_sig = $"($path).sig"
    if not ($default_sig | path exists) {
        error make {msg: $"signature file not created: ($default_sig)"}
    }

    let signer_name = $name | default ($key | path parse | get stem)
    let sig_path = $"($path).($signer_name).sig"
    mv $default_sig $sig_path

    print $"Signed: ($sig_path)"
    $sig_path
}

# Verify a file's SSH signatures against public keys in a directory.
# If --sig is given, verifies that single file. Otherwise finds all {path}.*.sig files.
# By default, renames each valid .sig file to match the signer's pubkey name.
export def verify [
    path: path                         # File to verify (or a .sig file — original is inferred)
    --sig: string                      # Specific signature file (default: all .sig files)
    --pubkeys-dir: string              # Directory containing *.pub files (default: multiproofs/pubkeys from git root)
    --namespace: string = "file"
    --no-rename                        # Skip renaming sig files to match signer pubkey name
] {
    # If a .sig file was passed, infer the original file
    let path = if ($path | str ends-with ".sig") {
        # Strip .{name}.sig or .sig suffix to find original
        let p = $path | into string
        let original = if ($p =~ '\.\w+\.sig$') {
            $p | str replace --regex '\.\w+\.sig$' ''
        } else {
            $p | str replace --regex '\.sig$' ''
        }
        if not ($original | path exists) {
            error make {msg: $"cannot find original file for ($path) — tried ($original)"}
        }
        $original
    } else {
        $path
    }

    let pubkeys_dir = if $pubkeys_dir != null { $pubkeys_dir } else {
        let git_root = ^git rev-parse --show-toplevel | str trim
        $git_root | path join "multiproofs/pubkeys"
    }
    let pubkeys = (glob ($pubkeys_dir | path join "*.pub")
        | each {|file|
            let key = (open --raw $file | str trim)
            let name = ($file | path parse | get stem)
            {name: $name, key: $key}
        }
    )

    if ($pubkeys | is-empty) {
        error make {msg: $"no public keys found in ($pubkeys_dir)/"}
    }

    let sig_files = if $sig != null {
        [$sig]
    } else {
        let named = glob $"($path).*.sig"
        let bare = $"($path).sig"
        if ($bare | path exists) { $named ++ [$bare] } else { $named }
    }

    if ($sig_files | is-empty) {
        error make {msg: $"no signature files found for ($path)"}
    }

    let base = $path | path basename
    let results = $sig_files | each {|sig_path|
        let sig_basename = $sig_path | path basename
        let current_name = if $sig_basename == $"($base).sig" {
            null
        } else {
            $sig_basename | str replace $"($base)." "" | str replace ".sig" ""
        }

        # Try each pubkey individually to identify the signer
        let matched = $pubkeys | each {|pk|
            let tmp = mktemp
            $"($pk.name) namespaces=\"($namespace)\" ($pk.key)" | save --force $tmp
            let result = (do {
                open --raw $path | ^ssh-keygen -Y verify -f $tmp -I $pk.name -n $namespace -s $sig_path
            } | complete)
            rm $tmp
            if $result.exit_code == 0 { $pk.name } else { null }
        } | where $it != null

        if ($matched | is-empty) {
            let label = $current_name | default "unknown"
            print $"($label): invalid \(no matching pubkey\)"
            {signer: $label, valid: false, error: "no matching pubkey"}
        } else {
            let signer = $matched | first
            let needs_rename = (not $no_rename) and ($current_name != $signer)

            if $needs_rename {
                let new_sig_path = $"($path).($signer).sig"
                mv $sig_path $new_sig_path
                print $"($signer): valid \(renamed from ($sig_basename)\)"
            } else {
                print $"($signer): valid"
            }

            {signer: $signer, valid: true}
        }
    }

    $results
}
