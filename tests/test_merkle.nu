use std/assert
use std/testing *

use ../nu-multiproof/merkle.nu
use ../nu-multiproof/tree-hashes.nu
use ../nu-multiproof/ssh-sign.nu
use ../nu-multiproof/_merkle-helpers.nu [
    mth audit-path fold-path leaf-hash load-leaves
    root-statement parse-root-statement validate-leaf
]

# Leaf inputs from the RFC 6962 / Certificate Transparency test suite,
# hashed per spec: sha256(0x00 ++ input).
def vector-leaf-hashes []: nothing -> list<binary> {
    ["" "00" "10" "2021" "3031" "40414243" "5051525354555657" "606162636465666768696a6b6c6d6e6f"]
    | each {|h|
        let input = if $h == "" { 0x[] } else { $h | decode hex }
        0x[00] | bytes add --end $input | hash sha256 --binary
    }
}

def as-hex []: binary -> string {
    encode hex | str lowercase
}

# Fixed 4-row manifest for golden-root pinning. Deliberately unsorted (builder
# must sort itself) with a numeric-looking filepath (must stay a string) and a
# directory row (empty sha256/cid).
def write-mini-manifest [repo: path] {
    mkdir $"($repo)/multiproofs"
    [
        {filepath: "z.txt" content_sha256: ("one" | hash sha256) content_git: ("two" | hash sha256) content_cid: ""}
        {filepath: "docs" content_sha256: "" content_git: ("three" | hash sha256) content_cid: ""}
        {filepath: "docs/a.md" content_sha256: ("four" | hash sha256) content_git: ("five" | hash sha256) content_cid: "QmNwvubv2KpTeugGN29uBnaZhZkDCwG4kMrx2vAEBk9nPo"}
        {filepath: "42" content_sha256: ("six" | hash sha256) content_git: ("seven" | hash sha256) content_cid: ""}
    ] | to csv | save --force $"($repo)/multiproofs/tree-hashes.csv"
}

const GOLDEN_MINI_ROOT = "1bb128f5734e4063378753825da46f637ab6a8747973b8f1507d8e6f5404c9a0"

# Git repo whose manifest has rows README.md, sub, sub/inner.txt (n=3).
def make-test-repo [tmp_dir: path]: nothing -> path {
    let repo = $"($tmp_dir)/repo"
    mkdir $"($repo)/sub"
    ^git -C $repo init -q
    "hello\n" | save --force $"($repo)/README.md"
    "world\n" | save --force $"($repo)/sub/inner.txt"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo -c user.email=t@t -c user.name=t commit -q -m init
    tree-hashes --repo $repo
    $repo
}

# --- spec cross-checks ---

@test
def "mth reproduces the RFC 6962 known-answer vectors" [] {
    let leaves = vector-leaf-hashes
    # Published constants from the CT reference test data (MTH over the first
    # n leaf inputs). Matching them means an independent RFC 6962
    # implementation reproduces our roots.
    assert equal (mth [] | as-hex) "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert equal (mth ($leaves | first 1) | as-hex) "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert equal (mth ($leaves | first 2) | as-hex) "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"
    assert equal (mth ($leaves | first 3) | as-hex) "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"
    assert equal (mth ($leaves | first 7) | as-hex) "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c"
}

@test
def "audit path folds to the root for every leaf of a 7-leaf tree" [] {
    let leaves = vector-leaf-hashes | first 7
    let root = mth $leaves | as-hex
    for index in 0..6 {
        let steps = audit-path $leaves $index
            | each {|step| {side: $step.side hash: ($step.hash | as-hex)} }
        let folded = fold-path ($leaves | get $index) $steps | as-hex
        assert equal $folded $root $"leaf ($index) did not fold to the root"
    }
}

@test
def "single-leaf tree: empty path, root is the leaf hash" [] {
    let leaves = vector-leaf-hashes | first 1
    assert equal (audit-path $leaves 0) []
    assert equal (fold-path ($leaves | first) [] | as-hex) (mth $leaves | as-hex)
}

# --- builder over the manifest ---

@test
def "golden root for the fixed mini-manifest, statement byte-exact" [] {
    let tmp_dir = (^mktemp -d | str trim)
    write-mini-manifest $tmp_dir

    let result = merkle root --repo $tmp_dir
    assert equal $result.root $GOLDEN_MINI_ROOT
    assert equal $result.leaves 4
    # Signature and OTS cover exact bytes: one statement line, one "\n"
    let statement = open --raw $"($tmp_dir)/multiproofs/tree-root.txt" | into string
    assert equal $statement $"multiproof-merkle-v1 ($GOLDEN_MINI_ROOT)\n"
    assert equal (parse-root-statement $"($tmp_dir)/multiproofs/tree-root.txt") $GOLDEN_MINI_ROOT

    rm --recursive $tmp_dir
}

@test
def "duplicate filepaths are a hard error - equivocation guard" [] {
    let tmp_dir = (^mktemp -d | str trim)
    mkdir $"($tmp_dir)/multiproofs"
    let row = {filepath: "a.txt" content_sha256: ("one" | hash sha256) content_git: "" content_cid: ""}
    [$row $row] | to csv | save --force $"($tmp_dir)/multiproofs/tree-hashes.csv"

    assert error {|| merkle root --repo $tmp_dir }

    rm --recursive $tmp_dir
}

@test
def "newline in filepath is rejected - leaf forgery guard" [] {
    let tmp_dir = (^mktemp -d | str trim)
    mkdir $"($tmp_dir)/multiproofs"
    # A tracked file named like a serialized record would otherwise inject
    # attacker-chosen hash fields into the leaf bytes
    let evil = $"evil\n(('x' | hash sha256))\n(('y' | hash sha256))\n"
    [{filepath: $evil content_sha256: ("one" | hash sha256) content_git: "" content_cid: ""}]
        | to csv | save --force $"($tmp_dir)/multiproofs/tree-hashes.csv"

    assert error {|| merkle root --repo $tmp_dir }

    rm --recursive $tmp_dir
}

@test
def "uppercase hex in a leaf is rejected, not normalized" [] {
    assert error {||
        validate-leaf {
            filepath: "a.txt"
            content_sha256: ("one" | hash sha256 | str uppercase)
            content_git: ""
            content_cid: ""
        }
    }
}

@test
def "malformed root statements are rejected" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let file = $"($tmp_dir)/tree-root.txt"
    let root = "one" | hash sha256

    for bad in [
        $"multiproof-merkle-v1 ($root)\n\n" # extra trailing newline
        $"multiproof-merkle-v1 ($root)" # missing newline
        $"multiproof-merkle-v1 ($root | str uppercase)\n" # uppercase hex
        $"($root)\n" # bare hash, no statement prefix
    ] {
        $bad | save --raw --force $file
        assert error {|| parse-root-statement $file } $"accepted: ($bad | to json)"
    }

    rm --recursive $tmp_dir
}

# --- prove/verify end-to-end ---

@test
def "signed roundtrip: file and directory proofs verify as valid" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let repo = make-test-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"

    let root_result = merkle root --repo $repo
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"

    # File row: content on disk matches the proven sha256
    let proof = merkle prove README.md --repo $repo
    assert equal $proof $"($repo)/multiproofs/inclusion-proofs/README.md.multiproof.nuon"
    let result = merkle verify $proof --repo $repo
    assert $result.valid
    assert $result.structure_valid
    assert equal $result.content_verified true
    assert equal ($result.signatures | where valid | length) 1
    assert equal $result.ots.status "absent"

    # Directory row: attests only content_git, so content check is null —
    # but with structure + signature good, the proof is still valid
    let dir_result = merkle verify (merkle prove sub --repo $repo) --repo $repo
    assert $dir_result.valid
    assert equal $dir_result.content_verified null

    rm --recursive $tmp_dir
}

@test
def "tampered leaf, changed content, and unsigned root are each caught" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let repo = make-test-repo $tmp_dir
    merkle root --repo $repo
    let proof = merkle prove README.md --repo $repo

    # Unsigned root: structure holds, valid stays false, --fail throws
    let unsigned = merkle verify $proof --repo $repo
    assert $unsigned.structure_valid
    assert not $unsigned.valid
    assert error {|| merkle verify $proof --repo $repo --fail }

    # Content drift after sealing: the row was catalogued, the file changed
    "changed\n" | save --force $"($repo)/README.md"
    let drifted = merkle verify $proof --repo $repo
    assert $drifted.structure_valid
    assert equal $drifted.content_verified false
    assert not $drifted.valid

    # Tampered leaf (well-formed hex, wrong value): fold no longer reaches
    # the signed root
    let tampered_file = $"($tmp_dir)/tampered.nuon"
    open $proof
        | update leaf.content_sha256 ("tampered" | hash sha256)
        | to nuon | save --force $tampered_file
    let tampered = merkle verify $tampered_file --repo $repo
    assert not $tampered.structure_valid
    assert not $tampered.valid

    rm --recursive $tmp_dir
}

@test
def "proof against a different seal root throws loudly" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let repo = make-test-repo $tmp_dir
    merkle root --repo $repo
    let proof = merkle prove README.md --repo $repo

    # A later seal rewrote the root statement: verification must name the
    # seal mismatch, not report a quiet invalid
    root-statement ("other" | hash sha256) | save --raw --force $"($repo)/multiproofs/tree-root.txt"
    assert error {|| merkle verify $proof --repo $repo }

    rm --recursive $tmp_dir
}
