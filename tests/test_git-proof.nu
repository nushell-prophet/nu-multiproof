use std/assert
use std/testing *

use ../nu-multiproof/git-proof.nu

@test
def "extract single file" [] {
    let proof_dir = (^mktemp -d | str trim)

    let result = (git-proof extract nu-multiproof/mod.nu --out-dir $proof_dir)

    assert equal $result.version 1
    assert equal $result.object_format "sha256"
    assert equal ($result.files | length) 1
    assert equal ($result.files | first | get path) "nu-multiproof/mod.nu"
    assert (($proof_dir | path join "manifest.json") | path exists)
    assert (($proof_dir | path join "objects") | path exists)
    assert (($proof_dir | path join "pubkeys") | path exists)

    rm --recursive $proof_dir
}

@test
def "extract multiple files with deduplication" [] {
    let proof_dir = (^mktemp -d | str trim)

    let result = (git-proof extract nu-multiproof/mod.nu toolkit.nu --out-dir $proof_dir)

    assert equal ($result.files | length) 2
    # commit + root tree + nu-multiproof subtree + 2 blobs = 5 unique objects
    assert equal ($result.objects | length) 5

    rm --recursive $proof_dir
}

@test
def "verify valid proof" [] {
    let proof_dir = (^mktemp -d | str trim)

    # Why signed commit: top-level `valid` requires both structure AND signature.
    # HEAD may not be signed, so pick any commit with a signature attached.
    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract nu-multiproof/mod.nu --commit $signed --out-dir $proof_dir
    let result = (git-proof verify $proof_dir)

    assert equal $result.valid true
    assert equal $result.structure_valid true
    assert equal ($result.files | length) 1
    assert equal ($result.files | first | get path) "nu-multiproof/mod.nu"

    rm --recursive $proof_dir
}

@test
def "verify checks signature" [] {
    let proof_dir = (^mktemp -d | str trim)

    # Use any signed commit — HEAD may not be signed.
    # Not status == "G" because: %G? reflects *local* trust (allowedSignersFile),
    # not whether the commit carries a signature. The proof bundles its own pubkeys
    # and points git at them at verify time, so any non-"N" status is a valid fixture.
    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir
    let result = (git-proof verify $proof_dir)

    assert equal $result.valid true
    assert equal $result.signature.valid true

    rm --recursive $proof_dir
}

@test
def "verify fails when signer key not in bundle" [] {
    let proof_dir = (^mktemp -d | str trim)

    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    let signer_fp = (^git log -1 --format='%GK' $signed | str trim)

    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    # Remove the pubkey that matches the signer; remaining keys are non-matching.
    # This models a bundle whose pubkeys/ never contained the signer's key.
    glob ($proof_dir | path join "pubkeys/*.pub") | each {|f|
        let fp = (^ssh-keygen -lf $f | split row " " | get 1)
        if $fp == $signer_fp { rm $f }
    }

    let result = (git-proof verify $proof_dir)
    assert equal $result.signature.valid false
    # Why: callers checking only `.valid` must reject this bundle.
    assert equal $result.valid false
    assert equal $result.structure_valid true

    rm --recursive $proof_dir
}

@test
def "verify fails when bundled pubkey tampered" [] {
    let proof_dir = (^mktemp -d | str trim)

    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    let signer_fp = (^git log -1 --format='%GK' $signed | str trim)

    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    # Overwrite the matching pubkey with a malformed key. The allowedSignersFile
    # parser flags the line "invalid key" and git verify-commit can no longer
    # match the signer.
    glob ($proof_dir | path join "pubkeys/*.pub") | each {|f|
        let fp = (^ssh-keygen -lf $f | split row " " | get 1)
        if $fp == $signer_fp {
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITAMPERED tampered" | save --force $f
        }
    }

    let result = (git-proof verify $proof_dir)
    assert equal $result.signature.valid false
    assert equal $result.valid false
    assert equal $result.structure_valid true

    rm --recursive $proof_dir
}

@test
def "render-allowed-signers writes one wildcard line per pubkey" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let out = $"($tmp_dir)/allowed_signers"
    mkdir $pubkeys_dir

    ^ssh-keygen -t ed25519 -f $"($tmp_dir)/k1" -N "" -q -C "alice"
    ^ssh-keygen -t ed25519 -f $"($tmp_dir)/k2" -N "" -q -C "bob"
    cp $"($tmp_dir)/k1.pub" ($pubkeys_dir | path join "alice.pub")
    cp $"($tmp_dir)/k2.pub" ($pubkeys_dir | path join "bob.pub")

    git-proof render-allowed-signers --to $out --pubkeys-dir $pubkeys_dir

    let lines = open --raw $out | lines
    assert equal ($lines | length) 2
    # Why wildcard principal: collective trust statement — keys are in the
    # project's signer list without attaching personal identity.
    for line in $lines {
        assert ($line | str starts-with "* namespaces=\"git\" ") $"unexpected line: ($line)"
    }

    rm --recursive $tmp_dir
}

@test
def "render-allowed-signers errors on empty pubkeys dir" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let out = $"($tmp_dir)/allowed_signers"
    mkdir $pubkeys_dir

    let outcome = (try {
        git-proof render-allowed-signers --to $out --pubkeys-dir $pubkeys_dir
        "ok"
    } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"

    rm --recursive $tmp_dir
}

@test
def "blob hash matches git" [] {
    let proof_dir = (^mktemp -d | str trim)

    let git_hash = (
        ^git ls-tree HEAD toolkit.nu
        | lines
        | parse "{mode} {type} {hash}\t{name}"
        | first
        | get hash
    )

    let result = (git-proof extract toolkit.nu --out-dir $proof_dir)
    let proof_hash = ($result.files | first | get hash)

    assert equal $proof_hash $git_hash

    rm --recursive $proof_dir
}
