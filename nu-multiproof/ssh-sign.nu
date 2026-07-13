# SSH file signing and verification via ssh-keygen.

use _repo.nu repo-root
use _layout.nu pubkeys-dir
use _sig.nu [sig-files-for signer-from-sig]
use _key-helpers.nu resolve-signing-key
use _allowed-signers.nu allowed-signers-body

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
    --key: path # SSH private key (default: from git config user.signingKey)
    --name: string # Signer name for the .sig file (default: stem of matching pubkey in --pubkeys-dir)
    --pubkeys-dir: path # Directory of registered *.pub files (default: multiproofs/pubkeys from git root)
    --namespace: string = "file"
] {
    # Why default from git config: makes `ssh-sign sign <file>` usable with no
    # flags; without it, a missing --key blew up with a null-conversion error.
    let key = if $key != null { $key } else { resolve-signing-key }

    let signer_name = if $name != null { $name } else {
        let dir = if $pubkeys_dir != null { $pubkeys_dir } else {
            pubkeys-dir (repo-root)
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
        pubkeys-dir (repo-root)
    }
    let signers = (allowed-signers-body $pubkeys_dir --namespace $namespace)
    if ($signers | str trim | is-empty) {
        error make {msg: $"no public keys found in ($pubkeys_dir)/"}
    }
    # One allowed_signers file with every registered key (principal = stem), so
    # find-principals identifies the signer in a single call per sig.
    let signers_file = mktemp
    $signers | save --force $signers_file

    let sig_files = if $sig != null {
        [$sig]
    } else {
        sig-files-for $path
    }

    if ($sig_files | is-empty) {
        rm $signers_file
        error make {msg: $"no signature files found for ($path)"}
    }

    let results = $sig_files | each {|sig_path|
            # find-principals matches by public key alone (not the signature),
            # so exit 0 means "this sig's key is registered" — its stem is the
            # signer. It does not prove the content matches; verify does that.
            let fp = (do { ^ssh-keygen -Y find-principals -s $sig_path -f $signers_file } | complete)

            if $fp.exit_code == 0 {
                let signer = ($fp.stdout | lines | first)
                let v = (do {
                    open --raw $path | ^ssh-keygen -Y verify -f $signers_file -I $signer -n $namespace -s $sig_path
                } | complete)
                if $v.exit_code == 0 {
                    print $"($signer): valid"
                    {signer: $signer valid: true}
                } else {
                    # Registered key, but the content no longer matches the sig.
                    print $"($signer): invalid signature"
                    {signer: $signer valid: false error: "invalid_signature"}
                }
            } else {
                # Signer's key isn't registered. Why check-novalidate: distinguish
                # "sig is good but signer not in our bundle" from "sig is broken".
                let cn = (do {
                    open --raw $path | ^ssh-keygen -Y check-novalidate -n $namespace -s $sig_path
                } | complete)
                let label = (signer-from-sig $path $sig_path | default "unknown")
                if $cn.exit_code == 0 {
                    print $"($label): unrecognized signer \(sig cryptographically valid but key not in pubkeys_dir\)"
                    {signer: $label valid: false error: "unrecognized_signer"}
                } else {
                    print $"($label): invalid signature"
                    {signer: $label valid: false error: "invalid_signature"}
                }
            }
        }

    rm $signers_file
    $results
}
