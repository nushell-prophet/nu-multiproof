use std/assert
use std/testing *

use ../nu-multiproof/git-proof.nu

@test
def "extract single file" [] {
    let proof_dir = (^mktemp -d | str trim)

    let result = (git-proof extract spec/cybergraph-model.md --out-dir $proof_dir)

    assert equal $result.version 1
    assert equal $result.object_format "sha256"
    assert equal ($result.files | length) 1
    assert equal ($result.files | first | get path) "spec/cybergraph-model.md"
    assert (($proof_dir | path join "manifest.json") | path exists)
    assert (($proof_dir | path join "objects") | path exists)
    assert (($proof_dir | path join "pubkeys") | path exists)

    rm --recursive $proof_dir
}

@test
def "extract multiple files with deduplication" [] {
    let proof_dir = (^mktemp -d | str trim)

    let result = (git-proof extract spec/cybergraph-model.md toolkit.nu --out-dir $proof_dir)

    assert equal ($result.files | length) 2
    # commit + root tree + spec subtree + 2 blobs = 5 unique objects
    assert equal ($result.objects | length) 5

    rm --recursive $proof_dir
}

@test
def "verify valid proof" [] {
    let proof_dir = (^mktemp -d | str trim)

    git-proof extract spec/cybergraph-model.md --out-dir $proof_dir
    let result = (git-proof verify $proof_dir)

    assert equal $result.valid true
    assert equal ($result.files | length) 1
    assert equal ($result.files | first | get path) "spec/cybergraph-model.md"

    rm --recursive $proof_dir
}

@test
def "verify checks signature" [] {
    let proof_dir = (^mktemp -d | str trim)

    git-proof extract toolkit.nu --out-dir $proof_dir
    let result = (git-proof verify $proof_dir)

    assert equal $result.valid true
    assert equal $result.signature.valid true

    rm --recursive $proof_dir
}

@test
def "blob hash matches git" [] {
    let proof_dir = (^mktemp -d | str trim)

    let git_hash = (^git ls-tree HEAD toolkit.nu
        | lines
        | parse "{mode} {type} {hash}\t{name}"
        | first
        | get hash)

    let result = (git-proof extract toolkit.nu --out-dir $proof_dir)
    let proof_hash = ($result.files | first | get hash)

    assert equal $proof_hash $git_hash

    rm --recursive $proof_dir
}
