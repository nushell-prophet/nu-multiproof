# SSH file signing and verification via ssh-keygen.

# Extract algorithm + base64 blob from a public key line, dropping the trailing comment.
def pubkey-material []: string -> string {
    str trim | split row " " | first 2 | str join " "
}

# Match the signing key against registered pubkeys; return the registered stem.
# Why: signer identity = filename in multiproofs/pubkeys/, not the private-key filename.
def lookup-signer-name [key: path pubkeys_dir: path]: nothing -> string {
    let pub_path = if ($key | str ends-with ".pub") { $key } else {
        let candidate = $"($key).pub"
        if not ($candidate | path exists) {
            error make {msg: $"public key file not found: ($candidate)"}
        }
        $candidate
    }
    let signing = open --raw $pub_path | pubkey-material

    let matches = glob ($pubkeys_dir | path join "*.pub")
        | each {|file|
            let registered = open --raw $file | pubkey-material
            if $registered == $signing { $file | path parse | get stem } else { null }
        }
        | where $it != null

    if ($matches | is-empty) {
        error make {msg: $"signing key not registered in ($pubkeys_dir)/ — add its pubkey or pass --name explicitly"}
    }
    if ($matches | length) > 1 {
        error make {msg: $"multiple pubkeys match in ($pubkeys_dir)/: ($matches | str join ', ')"}
    }
    $matches | first
}

# Sign a file with an SSH key.
# Creates {path}.{name}.sig alongside the input file.
export def sign [
    path: path # File to sign
    --key: path # SSH private key path (or public key if agent has the private key)
    --name: string # Signer name for the .sig file (default: stem of matching pubkey in --pubkeys-dir)
    --pubkeys-dir: path # Directory of registered *.pub files (default: multiproofs/pubkeys from git root)
    --namespace: string = "file"
] {
    let signer_name = if $name != null { $name } else {
        let dir = if $pubkeys_dir != null { $pubkeys_dir } else {
            ^git rev-parse --show-toplevel | str trim | path join "multiproofs/pubkeys"
        }
        lookup-signer-name $key $dir
    }

    ^ssh-keygen -Y sign -f $key -n $namespace $path
    let default_sig = $"($path).sig"
    if not ($default_sig | path exists) {
        error make {msg: $"signature file not created: ($default_sig)"}
    }

    let sig_path = $"($path).($signer_name).sig"
    mv $default_sig $sig_path

    print $"Signed: ($sig_path)"
    $sig_path
}

# Verify a file's SSH signatures against public keys in a directory.
# If --sig is given, verifies that single file. Otherwise finds all {path}.*.sig files.
export def verify [
    path: path # File to verify (or a .sig file — original is inferred)
    --sig: path # Specific signature file (default: all .sig files)
    --pubkeys-dir: path # Directory containing *.pub files (default: multiproofs/pubkeys from git root)
    --namespace: string = "file"
] {
    # If a .sig file was passed, infer the original file
    let path = if ($path | str ends-with ".sig") {
        # Strip .{name}.sig or .sig suffix to find original
        let p = $path | into string
        # Why: signer names can contain `-` (e.g. `maxim-uvarov2`), which `\w` excludes.
        # Match anything between the last two dots that isn't a dot or slash.
        let original = if ($p =~ '\.[^./]+\.sig$') {
            $p | str replace --regex '\.[^./]+\.sig$' ''
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
    let pubkeys = (
        glob ($pubkeys_dir | path join "*.pub")
        | each {|file|
            let key = (open --raw $file | str trim)
            let name = ($file | path parse | get stem)
            {name: $name key: $key}
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
                    let result = (
                        do {
                            open --raw $path | ^ssh-keygen -Y verify -f $tmp -I $pk.name -n $namespace -s $sig_path
                        } | complete
                    )
                    rm $tmp
                    if $result.exit_code == 0 { $pk.name } else { null }
                } | where $it != null

            if ($matched | is-empty) {
                # Why: distinguish "sig is good but signer not in our bundle"
                # from "sig itself is broken". `-Y check-novalidate` verifies
                # the signature against its embedded public key without
                # consulting allowed_signers.
                let cn = (
                    do {
                        open --raw $path | ^ssh-keygen -Y check-novalidate -n $namespace -s $sig_path
                    } | complete
                )
                let label = $current_name | default "unknown"
                if $cn.exit_code == 0 {
                    print $"($label): unrecognized signer \(sig cryptographically valid but key not in pubkeys_dir\)"
                    {signer: $label valid: false error: "unrecognized_signer"}
                } else {
                    print $"($label): invalid signature"
                    {signer: $label valid: false error: "invalid_signature"}
                }
            } else {
                let signer = $matched | first
                print $"($signer): valid"
                {signer: $signer valid: true}
            }
        }

    $results
}
