# SSH file signing and verification via ssh-keygen.

use _repo.nu repo-root
use _layout.nu pubkeys-dir
use _sig.nu [sig-files-for signer-from-sig sig-path-for original-for-sig]
use _key-helpers.nu with-signing-key
use _temp-helpers.nu with-temp-file
use _allowed-signers.nu [allowed-signers-body registered-principals NAMESPACE]
use _pubkey-helpers.nu fingerprint-file

# The principal this key signs under: its own fingerprint, from its public half.
#
# Why it is not looked up in pubkeys/ any more: the signer used to be the *stem*
# of whichever registered file held matching key material, so the same key filed
# twice made every signature fail with "multiple pubkeys match", and a stem the
# trust-list renderer refused made every later verify in that repo throw. A
# fingerprint is a property of the key, so neither question arises.
#
# Registration is still required, and that is the only reason pubkeys/ is read
# here: a signature by a key the trust list does not hold is one nothing reading
# the artifact can check. There is no `--name` escape hatch, deliberately — a
# principal is not the signer's to choose.
def signing-principal [key: path pubkeys_dir: path]: nothing -> string {
    let pub_path = if ($key | str ends-with ".pub") { $key } else {
        let candidate = $"($key).pub"
        if not ($candidate | path exists) {
            error make {msg: $"public key file not found: ($candidate)"}
        }
        $candidate
    }
    let principal = fingerprint-file $pub_path
    if $principal not-in (registered-principals $pubkeys_dir) {
        error make {msg: $"the signing key \(($principal)\) is not registered in ($pubkeys_dir)/ — register it with `init --pubkey ($pub_path)`, or nothing reading this artifact can check the signature"}
    }
    $principal
}

# Sign a file with an SSH key.
# Creates {path}.{fingerprint}.sig alongside the input file, where the
# fingerprint is the signing key's own (see `pubkey fingerprint`).
@example "sign the root statement with the git signing key" { ssh-sign sign multiproofs/tree-root.txt }
export def sign [
    path: path # File to sign
    --key: path # SSH private key (default: from git config user.signingKey)
    --pubkeys-dir: path # Directory of registered *.pub files (default: multiproofs/pubkeys from git root)
] {
    # Why default from git config: makes `ssh-sign sign <file>` usable with no
    # flags; without it, a missing --key blew up with a null-conversion error.
    # The closure form bounds the key's lifetime: an inline `key::` config is
    # materialized to a temp file, which with-signing-key deletes on the way out.
    with-signing-key --key $key {|key|
        let signer_name = signing-principal $key (
            if $pubkeys_dir != null { $pubkeys_dir } else { pubkeys-dir (repo-root) }
        )

        # Why the content goes in over stdin instead of naming the file: given a
        # file, ssh-keygen writes the signature to the fixed name `<path>.sig`,
        # which every process signing that file shares. Two signs of one file
        # with different keys raced there and the surviving
        # `tree-root.txt.id_ed25519.sig` held id2's signature — the filename is
        # what `signer-from-sig` reads as truth. Signing standard input returns
        # the signature on stdout, so each call keeps its own, and a file name
        # starting with `-` stops being an option (ssh-keygen has no `--`).
        # -q silences the "Signing data on standard input" notice.
        let signed = (do {
            open --raw $path | into binary | ^ssh-keygen -Y sign -q -f $key -n $NAMESPACE
        } | complete)
        if $signed.exit_code != 0 {
            error make {msg: $"ssh-keygen could not sign ($path): ($signed.stderr | str trim)"}
        }

        let sig_path = (sig-path-for $path $signer_name)

        # Why: Apple's ssh-keychain.dylib fail-opens — on a cancelled Touch ID
        # prompt (or a wedged Secure Enclave stack) it reports success and
        # ssh-keygen emits a sig whose ECDSA r/s are empty. A .sig file existing
        # proves nothing; only a verify does.
        #
        # Why the check runs at a temp path and the move comes last: saving
        # straight to $sig_path first meant a cancelled ceremony overwrote and
        # then deleted a previously valid `<file>.<signer>.sig`. `seal` clears
        # sigs only when the signed bytes changed, so on an unchanged
        # tree-root.txt it deliberately keeps the good sig and then re-signs —
        # one cancelled prompt destroyed exactly the signature it kept. Same
        # validate-then-write shape as `ots upgrade`.
        with-temp-file "sig" {|tmp_sig|
            $signed.stdout | save --force $tmp_sig
            let check = (do {
                open --raw $path | into binary | ^ssh-keygen -Y check-novalidate -n $NAMESPACE -s $tmp_sig
            } | complete)
            if $check.exit_code != 0 {
                error make {msg: $"ssh-keygen wrote an invalid \(empty?\) signature for ($path) — cancelled or failed signing ceremony. Re-run and complete the prompt."}
            }
            mv --force $tmp_sig $sig_path
        }

        print $"Signed: ($sig_path)"
        $sig_path
    }
}

# Verify a file's SSH signatures against public keys in a directory.
# Naming a .sig file verifies that one signature; naming the original verifies
# every signature `_sig.nu sig-files-for` finds beside it — both the named
# `{path}.{signer}.sig` form and the bare `{path}.sig`.
# Returns a table of {signer, valid, error?}, where `signer` is the fingerprint
# of the key that made the signature — read out of the signature itself. Only an
# `unrecognized_signer` row falls back to the label the sig's file name carries,
# since there is no registered key to name. A sig that fails even keyless
# checking yields `{signer: null, error: unreadable_signature, sig: <path>}` —
# no signing key was established, so nothing read off a file name is reported
# as a principal. --fail exits non-zero if any
# signature is invalid (for CI), instead of a silent pass the caller must inspect.
@example "verify all signatures on the root statement" { ssh-sign verify multiproofs/tree-root.txt }
export def verify [
    path: path # File to verify (or a .sig file — verifies just that sig, original inferred)
    --pubkeys-dir: path # Directory containing *.pub files (default: multiproofs/pubkeys from git root)
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
    let signers = (allowed-signers-body $pubkeys_dir)
    if ($signers | str trim | is-empty) {
        error make {msg: $"no public keys found in ($pubkeys_dir)/"}
    }
    # One allowed_signers file with every registered key (principal = the key's
    # fingerprint), so find-principals identifies the signer in a single call per
    # sig — and identifies it from the key inside the signature, not from what
    # the sig's file name claims.
    let results = with-temp-file "allowed-signers" {|signers_file|
        $signers | save --force $signers_file
        # Why naming a sig wins over discovery: `verify foo.csv.alice.sig`
        # reads as "check alice's signature", but discovery would also pull in
        # bob's — reporting on sigs the caller never named. Not also a --sig
        # flag: it said the same thing without inferring the original, so
        # `verify doc.txt --sig doc.txt.alice.sig` had to repeat what the sig
        # name already carries.
        let sig_files = if $target.sig != null { [$target.sig] } else { sig-files-for $path }

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
                    open --raw $path | ^ssh-keygen -Y verify -f $signers_file -I $signer -n $NAMESPACE -s $sig_path
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
                    open --raw $path | ^ssh-keygen -Y check-novalidate -n $NAMESPACE -s $sig_path
                } | complete)
                if $cn.exit_code == 0 {
                    let label = (signer-from-sig $path $sig_path | default "unknown")
                    print $"($label): unrecognized signer \(sig cryptographically valid but key not in pubkeys_dir\)"
                    {signer: $label valid: false error: "unrecognized_signer"}
                } else {
                    # Even keyless checking failed: junk bytes planted at a sig
                    # name, or a foreign key's sig over content it never signed.
                    # Either way no signing key was established, so there is no
                    # principal to report. This row used to carry the label off
                    # the sig's file name as `signer`, which made a junk file
                    # planted at `doc.<alice-fp>.sig` byte-identical to alice's
                    # registered key really failing over changed content. The
                    # sig path says which file to inspect; it is a path, not an
                    # identity.
                    print $"($sig_path): unreadable signature \(does not check as an SSH signature over ($path)\)"
                    {signer: null valid: false error: "unreadable_signature" sig: ($sig_path | into string)}
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
