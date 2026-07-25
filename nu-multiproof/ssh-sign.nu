# SSH file signing and verification via ssh-keygen.

use _repo.nu repo-root
use _layout.nu pubkeys-dir
use _sig.nu [sig-files-for signer-from-sig sig-path-for original-for-sig]
use _key-helpers.nu with-signing-key
use _temp-helpers.nu with-temp-file
use _fs.nu list-files
use _allowed-signers.nu allowed-signers-body
use _pubkey-helpers.nu canonical-file

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
    let signing = canonical-file $pub_path

    # A `for` so that a broken file in pubkeys/ reports its own name, instead of
    # the closure wrapper's "Eval block failed with pipeline input".
    mut matches = []
    for file in (list-files $pubkeys_dir --suffix ".pub") {
        if (canonical-file $file) == $signing {
            $matches = ($matches | append ($file | path parse | get stem))
        }
    }

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
@example "sign the root statement with the git signing key" { ssh-sign sign multiproofs/tree-root.txt }
export def sign [
    path: path # File to sign
    --key: path # SSH private key (default: from git config user.signingKey)
    --name: string # Signer name for the .sig file (default: stem of matching pubkey in --pubkeys-dir)
    --pubkeys-dir: path # Directory of registered *.pub files (default: multiproofs/pubkeys from git root)
    --namespace: string = "file"
] {
    # Why default from git config: makes `ssh-sign sign <file>` usable with no
    # flags; without it, a missing --key blew up with a null-conversion error.
    # The closure form bounds the key's lifetime: an inline `key::` config is
    # materialized to a temp file, which with-signing-key deletes on the way out.
    with-signing-key --key $key {|key|
        let signer_name = if $name != null { $name } else {
            let dir = if $pubkeys_dir != null { $pubkeys_dir } else {
                pubkeys-dir (repo-root)
            }
            lookup-signer-name $key $dir
        }

        ^ssh-keygen -Y sign -f $key -n $namespace $path
        let default_sig = (sig-path-for $path)
        if not ($default_sig | path exists) {
            error make {msg: $"signature file not created: ($default_sig)"}
        }

        # Why: Apple's ssh-keychain.dylib fail-opens — on a cancelled Touch ID
        # prompt (or a wedged Secure Enclave stack) it reports success and
        # ssh-keygen writes a sig whose ECDSA r/s are empty. A .sig file existing
        # proves nothing; only a verify does. Delete the bad artifact so it can't
        # be committed as if it were a signature.
        let check = (do {
            open --raw $path | ^ssh-keygen -Y check-novalidate -n $namespace -s $default_sig
        } | complete)
        if $check.exit_code != 0 {
            rm $default_sig
            error make {msg: $"ssh-keygen wrote an invalid \(empty?\) signature for ($path) — cancelled or failed signing ceremony. Re-run and complete the prompt."}
        }

        let sig_path = (sig-path-for $path $signer_name)
        mv $default_sig $sig_path

        print $"Signed: ($sig_path)"
        $sig_path
    }
}

# Verify a file's SSH signatures against public keys in a directory.
# Naming a .sig file (positionally or via --sig) verifies that one signature;
# naming the original verifies every {path}.*.sig found beside it.
# Returns a table of {signer, valid, error?}. --fail exits non-zero if any
# signature is invalid (for CI), instead of a silent pass the caller must inspect.
@example "verify all signatures on the root statement" { ssh-sign verify multiproofs/tree-root.txt }
export def verify [
    path: path # File to verify (or a .sig file — verifies just that sig, original inferred)
    --sig: path # Specific signature file (default: all .sig files)
    --pubkeys-dir: path # Directory containing *.pub files (default: multiproofs/pubkeys from git root)
    --namespace: string = "file"
    --fail # Exit non-zero if any signature is invalid (for CI)
] {
    # A positional .sig names both the signature to check and, by inference, the
    # original it covers. The grammar lives in _sig.nu — reading it here is what
    # made `doc.txt.sig` resolve to `doc`.
    let target = if ($path | str ends-with ".sig") {
        {file: (original-for-sig $path) sig: ($path | into string)}
    } else {
        {file: $path sig: null}
    }
    let path = $target.file

    let pubkeys_dir = if $pubkeys_dir != null { $pubkeys_dir } else {
        pubkeys-dir (repo-root)
    }
    let signers = (allowed-signers-body $pubkeys_dir --namespace $namespace)
    if ($signers | str trim | is-empty) {
        error make {msg: $"no public keys found in ($pubkeys_dir)/"}
    }
    # One allowed_signers file with every registered key (principal = stem), so
    # find-principals identifies the signer in a single call per sig.
    let results = with-temp-file "allowed-signers" {|signers_file|
        $signers | save --force $signers_file
        # Why the positional sig wins over discovery: `verify foo.csv.alice.sig`
        # reads as "check alice's signature", but discovery would also pull in
        # bob's — reporting on sigs the caller never named.
        let sig_files = if $sig != null {
            [$sig]
        } else if $target.sig != null {
            [$target.sig]
        } else {
            sig-files-for $path
        }

        if ($sig_files | is-empty) {
            error make {msg: $"no signature files found for ($path)"}
        }

        $sig_files | each {|sig_path|
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
    }

    if $fail {
        let bad = $results | where not valid
        if not ($bad | is-empty) {
            error make {msg: $"($bad | length) invalid signature\(s\) for ($path)"}
        }
    }
    $results
}
