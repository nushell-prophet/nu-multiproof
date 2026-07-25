use std/assert
use std/testing *

use ../nu-multiproof/seal.nu

# Why a fixture, not rm at the end of test bodies: after-each runs even when
# the test throws, so a failing test does not leak its /tmp/tmp.* dir.
@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

# seal happy path with --no-stamp --no-root-cid:
# avoids the OTS calendar network call and the ipfs CLI, but still
# exercises tree-hashes regen + signing-key resolution + sig clearing.
@test
def "seal produces manifest and signed root statement" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo

    # seal works on a SHA-1 repo: it hashes file contents itself
    ^git -C $repo init -q
    ^git -C $repo config user.email "seal-test@example.com"
    ^git -C $repo config user.name "Seal Test"

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    ^git -C $repo config user.signingKey $"($key_path).pub"

    # Bootstrap pubkeys/ via init so signer-name lookup works
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"

    "hello\n" | save --force $"($repo)/README.md"
    ^git -C $repo add README.md
    ^git -C $repo commit -q -m "init"

    let result = seal --repo $repo --no-stamp --no-root-cid

    let manifest = $"($repo)/multiproofs/tree-hashes.csv"
    assert ($manifest | path exists) "manifest not created"
    # The CSV itself is unsigned — the signed root statement covers every row
    assert equal (glob $"($manifest).*.sig" | length) 0

    # Merkle root statement derived from the fresh manifest and signed
    let root_file = $"($repo)/multiproofs/tree-root.txt"
    assert ($root_file | path exists) "root statement not created"
    assert equal (open --raw $root_file | into string) $"multiproof-merkle-v1 ($result.merkle_root)\n"
    assert ($result.root_sig | str ends-with ".sshkey.sig")
}

# Second seal must succeed even though the previous seal left a sig next to
# the root statement — seal clears stale sigs itself before re-signing.
@test
def "seal re-runs without sig conflict" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo

    ^git -C $repo init -q
    ^git -C $repo config user.email "seal-test@example.com"
    ^git -C $repo config user.name "Seal Test"

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    ^git -C $repo config user.signingKey $"($key_path).pub"
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"

    "v1\n" | save --force $"($repo)/file.txt"
    ^git -C $repo add file.txt
    ^git -C $repo commit -q -m "init"

    seal --repo $repo --no-stamp --no-root-cid
    # Second invocation must not error: stale sig from first run gets cleared
    seal --repo $repo --no-stamp --no-root-cid

    # Stale root-statement sig from the first run cleared, exactly one live sig
    let root_sigs = (glob $"($repo)/multiproofs/tree-root.txt.*.sig")
    assert equal ($root_sigs | length) 1
}

# The CSV signature is dropped legacy: a live manifest sig can only be a
# leftover from the transition era, and seal deletes it instead of leaving a
# stale artifact (tag pre-drop-manifest-sig holds the last producing version).
@test
def "seal deletes leftover transition-era manifest sigs" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo

    ^git -C $repo init -q
    ^git -C $repo config user.email "seal-test@example.com"
    ^git -C $repo config user.name "Seal Test"

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    ^git -C $repo config user.signingKey $"($key_path).pub"
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"

    "v1\n" | save --force $"($repo)/file.txt"
    ^git -C $repo add file.txt
    ^git -C $repo commit -q -m "init"

    let manifest = $"($repo)/multiproofs/tree-hashes.csv"
    seal --repo $repo --no-stamp --no-root-cid
    # Plant sigs as an older seal would have left them: named and bare forms
    "legacy\n" | save --force $"($manifest).sshkey.sig"
    "legacy\n" | save --force $"($manifest).sig"
    seal --repo $repo --no-stamp --no-root-cid
    assert equal (glob $"($manifest)*.sig" | length) 0
}

# --no-sign means "skip signing", not "remove signatures": an unchanged
# reseal regenerates identical bytes, so the previous seal's sigs are still
# valid and must survive; once content changes they're stale and go.
@test
def "seal --no-sign keeps still-valid sigs, clears stale ones" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo

    ^git -C $repo init -q
    ^git -C $repo config user.email "seal-test@example.com"
    ^git -C $repo config user.name "Seal Test"

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    ^git -C $repo config user.signingKey $"($key_path).pub"
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"

    "v1\n" | save --force $"($repo)/file.txt"
    ^git -C $repo add file.txt
    ^git -C $repo commit -q -m "init"

    seal --repo $repo --no-stamp --no-root-cid
    let root_file = $"($repo)/multiproofs/tree-root.txt"

    # Unchanged content: regenerated bytes are identical, the sig stays
    seal --repo $repo --no-stamp --no-root-cid --no-sign
    assert equal (glob $"($root_file).*.sig" | length) 1

    # Changed content: the root statement's bytes change, the stale sig goes
    "v2\n" | save --force $"($repo)/file.txt"
    seal --repo $repo --no-stamp --no-root-cid --no-sign
    assert equal (glob $"($root_file).*.sig" | length) 0
}
