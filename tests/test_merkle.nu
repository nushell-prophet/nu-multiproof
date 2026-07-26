use std/assert
use std/testing *

use ../nu-multiproof/merkle.nu
use ../nu-multiproof/tree-hashes.nu
use ../nu-multiproof/ssh-sign.nu
use ../nu-multiproof/_merkle-helpers.nu [
    mth audit-path fold-path leaf-hash load-leaves
    root-statement parse-root-statement validate-leaf
]
use _ots-fixtures.nu [build-pending-ots build-bitcoin-ots]

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

# Externally pinned audit paths — PATH(0, D[8]) and PATH(5, D[8]) from the
# RFC 6962 / CT reference test data, hashes copied in as literals. Why this
# test and not another fold-round-trip: every other path test folds a path
# this same code produced, so the `side` convention can be flipped in
# audit-path AND fold-path together and all of them stay green (measured).
# The sides below are read off the tree, not off our output: for a balanced
# 8-leaf tree, leaf 0 sits leftmost so every sibling is to its right; leaf 5
# is the right child of the (4,5) pair (sibling left), that pair is the left
# child of the (4..7) subtree (sibling right), and that subtree is the right
# half of the root (sibling left).
const CT_ROOT_D8 = "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
const CT_PATH_0_D8 = [
    [side hash];
    [right "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"]
    [right "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"]
    [right "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]
]
const CT_PATH_5_D8 = [
    [side hash];
    [left "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]
    [right "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"]
    [left "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]
]

@test
def "CT reference audit paths for 8 leaves, sides included" [] {
    let leaves = vector-leaf-hashes
    assert equal (mth $leaves | as-hex) $CT_ROOT_D8

    # Builder side: our path must equal the published one, step for step
    let path_0 = audit-path $leaves 0 | each {|s| {side: $s.side hash: ($s.hash | as-hex)} }
    let path_5 = audit-path $leaves 5 | each {|s| {side: $s.side hash: ($s.hash | as-hex)} }
    assert equal $path_0 $CT_PATH_0_D8
    assert equal $path_5 $CT_PATH_5_D8

    # Verifier side: fold the PUBLISHED steps, not ours, up to the published
    # root — a flipped side rule reaches a different hash here
    assert equal (fold-path ($leaves | get 0) $CT_PATH_0_D8 | as-hex) $CT_ROOT_D8
    assert equal (fold-path ($leaves | get 5) $CT_PATH_5_D8 | as-hex) $CT_ROOT_D8
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
    let tmp_dir = $in.tmp_dir
    write-mini-manifest $tmp_dir

    let result = merkle write-root --repo $tmp_dir
    assert equal $result.root $GOLDEN_MINI_ROOT
    assert equal $result.leaves 4
    # Signature and OTS cover exact bytes: one statement line, one "\n"
    let statement = open --raw $"($tmp_dir)/multiproofs/tree-root.txt" | into string
    assert equal $statement $"multiproof-merkle-v1 ($GOLDEN_MINI_ROOT)\n"
    assert equal (parse-root-statement $"($tmp_dir)/multiproofs/tree-root.txt") $GOLDEN_MINI_ROOT
}

# The IPFS root CID rides in the manifest as the "." row (tree-hashes.nu), and
# nothing signs the CSV any more — so the only thing authenticating that CID is
# its being a leaf under the signed root. Pinned by a hand-written manifest, not
# by a tree-hashes build: the point is what the leaf set covers, so the rows are
# hostile input, not this repo's own output.
@test
def "the root-CID row is a covered leaf" [] {
    let tmp_dir = $in.tmp_dir
    let cid = "QmNwvubv2KpTeugGN29uBnaZhZkDCwG4kMrx2vAEBk9nPo"
    let other_cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
    let rows = [
        {filepath: "." content_sha256: "" content_git: "" content_cid: $cid}
        {filepath: "z.txt" content_sha256: ("one" | hash sha256) content_git: ("two" | hash sha256) content_cid: ""}
    ]
    mkdir $"($tmp_dir)/multiproofs"
    $rows | to csv | save --force $"($tmp_dir)/multiproofs/tree-hashes.csv"
    let with_cid = merkle write-root --repo $tmp_dir

    assert equal $with_cid.leaves 2
    # "." is a provable row like any other
    let proof = open (merkle prove "." --repo $tmp_dir)
    assert equal $proof.leaf.content_cid $cid

    # Swap only the root CID: a different root means the signature over the old
    # root no longer covers this manifest.
    $rows | update 0 {|r| $r | update content_cid $other_cid } | to csv | save --force $"($tmp_dir)/multiproofs/tree-hashes.csv"
    let swapped = merkle write-root --repo $tmp_dir
    assert not ($swapped.root == $with_cid.root) "changing the root-CID row left the merkle root unchanged"
}

@test
def "an empty manifest is refused - the empty root is constant and replayable" [] {
    let tmp_dir = $in.tmp_dir
    mkdir $"($tmp_dir)/multiproofs"
    "filepath,content_sha256,content_git,content_cid\n"
        | save --force $"($tmp_dir)/multiproofs/tree-hashes.csv"

    let err = try { merkle write-root --repo $tmp_dir; null } catch {|e| $e.msg }
    assert ($err != null) "an empty manifest minted a root"
    assert ($err | str contains "lists no files")
    # Nothing written: a signature over e3b0c442… would carry no repo in it
    assert not ($"($tmp_dir)/multiproofs/tree-root.txt" | path exists)
}

@test
def "duplicate filepaths are a hard error - equivocation guard" [] {
    let tmp_dir = $in.tmp_dir
    mkdir $"($tmp_dir)/multiproofs"
    let row = {filepath: "a.txt" content_sha256: ("one" | hash sha256) content_git: "" content_cid: ""}
    [$row $row] | to csv | save --force $"($tmp_dir)/multiproofs/tree-hashes.csv"

    # Not bare `assert error` because: it stays green on ANY error (e.g.
    # manifest-not-found) — pin the equivocation message
    let err = try { merkle write-root --repo $tmp_dir; null } catch {|e| $e.msg }
    assert ($err != null) "duplicate filepaths were accepted"
    assert ($err | str contains "duplicate filepaths")
}

@test
def "newline in filepath is rejected - leaf forgery guard" [] {
    let tmp_dir = $in.tmp_dir
    mkdir $"($tmp_dir)/multiproofs"
    # A tracked file named like a serialized record would otherwise inject
    # attacker-chosen hash fields into the leaf bytes
    let evil = $"evil\n(('x' | hash sha256))\n(('y' | hash sha256))\n"
    [{filepath: $evil content_sha256: ("one" | hash sha256) content_git: "" content_cid: ""}]
        | to csv | save --force $"($tmp_dir)/multiproofs/tree-hashes.csv"

    # Pin the validate-leaf message so an unrelated error can't keep this green
    let err = try { merkle write-root --repo $tmp_dir; null } catch {|e| $e.msg }
    assert ($err != null) "forged filepath was accepted"
    assert ($err | str contains "control bytes")
}

@test
def "a filepath escaping the repo is rejected - containment guard" [] {
    # Without this, a proof's leaf can name a file OUTSIDE the directory the
    # proof travels in: verify joins the two and reads whatever it lands on, so
    # a bundle proves a file it does not contain — or one of the verifier's.
    for bad in ["../outside.json" "links/../../outside.json" "/etc/passwd" ".."] {
        let err = try {
            validate-leaf {filepath: $bad content_sha256: "" content_git: "" content_cid: ""}
            null
        } catch {|e| $e.msg }
        assert ($err != null) $"escaping filepath was accepted: ($bad)"
        assert ($err | str contains "must stay inside the repo")
    }
    # "." is the root-CID row — legal, and a file named "..foo" is not a
    # traversal either
    validate-leaf {filepath: "." content_sha256: "" content_git: "" content_cid: ""}
    validate-leaf {filepath: "..foo" content_sha256: "" content_git: "" content_cid: ""}
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
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/tree-root.txt"
    let root = "one" | hash sha256

    for bad in [
        $"multiproof-merkle-v1 ($root)\n\n" # extra trailing newline
        $"multiproof-merkle-v1 ($root)" # missing newline
        $"multiproof-merkle-v1 ($root | str uppercase)\n" # uppercase hex
        $"($root)\n" # bare hash, no statement prefix
        $"multiproof-merkle-v2 ($root)\n" # another schema — parser must track MERKLE_SCHEMA
    ] {
        $bad | save --raw --force $file
        assert error {|| parse-root-statement $file } $"accepted: ($bad | to json)"
    }
}

# --- prove/verify end-to-end ---

@test
def "signed roundtrip: file and directory proofs verify as valid" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"

    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"

    # File row: content on disk matches the proven sha256
    let proof = merkle prove README.md --repo $repo
    assert equal $proof $"($repo)/multiproofs/inclusion-proofs/README.md.multiproof.json"
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
}

# Every discovery step here (pubkeys for the allowed_signers body, the signer
# lookup, sig files beside the root statement, archived OTS bundles) used to
# build a glob pattern by interpolating a directory path. A repo checked out
# under a name holding `[`, `]`, `*` or `?` made those patterns match nothing,
# and the failures were silent: no keys in the trust list, no signature found.
@test
def "signed roundtrip works when the repo path holds glob metacharacters" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/re[po] v*1?"
    mkdir $repo
    ^git -C $repo init -q
    "hello\n" | save --force $"($repo)/README.md"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo -c user.email=t@t -c user.name=t commit -q -m init
    tree-hashes --repo $repo

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"

    let root_result = merkle write-root --repo $repo
    # --name is not passed: the signer name comes from matching key material
    # against the registered pubkeys, which is one of the discovery steps.
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"

    let result = merkle verify (merkle prove README.md --repo $repo) --repo $repo
    assert $result.valid "a repo path with glob metacharacters broke the roundtrip"
    assert equal ($result.signatures | where valid | length) 1
    assert equal $result.signatures.0.signer "sshkey"
}

@test
def "tampered leaf, changed content, and unsigned root are each caught" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    merkle write-root --repo $repo
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

    # Deleted file after sealing: absence is a divergence from the sealed
    # catalogue, not "nothing to check" — must not collapse into the
    # directory-row null and read as valid
    rm $"($repo)/README.md"
    let missing = merkle verify $proof --repo $repo
    assert $missing.structure_valid
    assert equal $missing.content_verified "missing"
    assert not $missing.valid

    # Tampered leaf (well-formed hex, wrong value): fold no longer reaches
    # the signed root
    let tampered_file = $"($tmp_dir)/tampered.json"
    open $proof
        | update leaf.content_sha256 ("tampered" | hash sha256)
        | to json | save --force $tampered_file
    let tampered = merkle verify $tampered_file --repo $repo
    assert not $tampered.structure_valid
    assert not $tampered.valid
}

@test
def "signer flag pins the principal, not just any registered key" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir

    # Two registered keys, one signature: the fork-and-reseal shape — the
    # attacker's key is in the bundle's own trust list
    let alice = $"($tmp_dir)/alice"
    let mallory = $"($tmp_dir)/mallory"
    ^ssh-keygen -t ed25519 -f $alice -N "" -q
    ^ssh-keygen -t ed25519 -f $mallory -N "" -q
    let pubkeys = $"($repo)/multiproofs/pubkeys"
    mkdir $pubkeys
    cp $"($alice).pub" $"($pubkeys)/alice.pub"
    cp $"($mallory).pub" $"($pubkeys)/mallory.pub"

    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $mallory --pubkeys-dir $pubkeys
    let proof = merkle prove README.md --repo $repo

    # Default: any key in the bundle's list satisfies valid — internal
    # consistency only
    assert (merkle verify $proof --repo $repo).valid

    # The verifier's own copy of the list. --signer is reachable only this way,
    # so every assertion below is about stems the verifier chose.
    let trusted = $"($tmp_dir)/trusted"
    mkdir $trusted
    cp $"($alice).pub" $"($trusted)/alice.pub"
    cp $"($mallory).pub" $"($trusted)/mallory.pub"

    # Signature is cryptographically valid, but it is not alice's
    let wrong = merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer alice
    assert $wrong.structure_valid "structure must still verify"
    assert not $wrong.valid "a signature from another principal was accepted"
    assert ($wrong.error | str contains "alice")
    assert equal ($wrong.signatures | where valid | get signer) [mallory]
    assert error {|| merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer alice --fail }

    assert (merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer mallory).valid
}

# "alice did not sign this" is a claim; a verifier holding no key for alice
# cannot make it. Folded into the negative verdict, a typo in the verifier's own
# flag read as evidence against the artifact — structure_valid true, valid
# false, "no valid signature from signer alice".
@test
def "signer with no matching key in the trusted dir is an error, not invalid" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir

    let mallory = $"($tmp_dir)/mallory"
    ^ssh-keygen -t ed25519 -f $mallory -N "" -q
    let pubkeys = $"($repo)/multiproofs/pubkeys"
    mkdir $pubkeys
    cp $"($mallory).pub" $"($pubkeys)/mallory.pub"

    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $mallory --pubkeys-dir $pubkeys
    let proof = merkle prove README.md --repo $repo

    # The verifier's own list: it holds bob, and was never given alice's key.
    let bob = $"($tmp_dir)/bob"
    ^ssh-keygen -t ed25519 -f $bob -N "" -q
    let trusted = $"($tmp_dir)/trusted"
    mkdir $trusted
    cp $"($bob).pub" $"($trusted)/bob.pub"

    let err = try { merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer alice; null } catch {|e| $e.msg }
    assert ($err != null) "a signer the trust list cannot answer for got a verdict"
    assert ($err | str contains "no key for signer alice")

    # Same list, a principal it does hold: answered, not refused.
    let answered = merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer bob
    assert not $answered.valid "bob's key did not sign this root"
    assert $answered.structure_valid
}

# A whole artifact set written by hand — attacker's key, attacker's root
# statement, attacker's proof JSON — with no call to write-root or prove.
# Round-tripping our own builder can only show self-consistency; the leaf
# guard on the verify path is about what someone else may ship.
def forge-bundle [dir: path leaf: record key: path]: nothing -> path {
    mkdir $"($dir)/multiproofs/pubkeys"
    cp $"($key).pub" $"($dir)/multiproofs/pubkeys/attacker.pub"
    # Leaf and root serialized here from the README spec, not via leaf-hash/mth:
    # a single-leaf tree's root IS the leaf hash.
    let leaf_bytes = [$leaf.filepath $leaf.content_sha256 $leaf.content_git $leaf.content_cid]
        | str join "\n" | into binary
    let root = 0x[00] | bytes add --end $leaf_bytes | hash sha256
    $"multiproof-merkle-v1 ($root)\n" | save --force $"($dir)/multiproofs/tree-root.txt"
    ssh-sign sign $"($dir)/multiproofs/tree-root.txt" --key $key --pubkeys-dir $"($dir)/multiproofs/pubkeys"
    let proof_file = $"($dir)/proof.json"
    {schema: "multiproof-merkle-v1" leaf: $leaf path: [] root: $root} | to json | save --force $proof_file
    $proof_file
}

@test
def "verify refuses a forged proof whose leaf points outside the bundle" [] {
    let tmp_dir = $in.tmp_dir
    let key = $"($tmp_dir)/attacker"
    ^ssh-keygen -t ed25519 -f $key -N "" -q
    "secret\n" | save --force $"($tmp_dir)/outside.txt"

    # Control: the same hand-built shape with a contained leaf verifies. So
    # the refusal below is the leaf guard, not a malformed bundle.
    let honest_dir = $"($tmp_dir)/honest"
    mkdir $honest_dir
    "inside\n" | save --force $"($honest_dir)/inside.txt"
    let honest = forge-bundle $honest_dir {
        filepath: "inside.txt" content_sha256: ("inside\n" | hash sha256)
        content_git: "" content_cid: ""
    } $key
    let ok = merkle verify $honest --repo $honest_dir
    assert $ok.valid "the hand-built bundle must otherwise verify"
    assert equal $ok.content_verified true

    # The attack: a leaf naming a file outside the bundle. verify joins the
    # filepath onto the target dir and hashes what it lands on, so this reads
    # the verifier's own file and reports whether it has the attested hash.
    let evil_dir = $"($tmp_dir)/evil"
    mkdir $evil_dir
    let evil = forge-bundle $evil_dir {
        filepath: "../outside.txt" content_sha256: ("secret\n" | hash sha256)
        content_git: "" content_cid: ""
    } $key
    let err = try { merkle verify $evil --repo $evil_dir; null } catch {|e| $e.msg }
    assert ($err != null) "a proof for a file outside the bundle was verified"
    assert ($err | str contains "must stay inside the repo")
}

# validate-leaf constrains the path text, so `../outside.txt` is caught above.
# A symlink is the same attack with the traversal moved out of the text and
# onto the filesystem, where the path guard cannot see it: `open --raw` follows
# it. The bundle then "proves" it carries a file it does not carry, and any
# verifier can be asked whether their own file has a guessed hash.
@test
def "a leaf that is a symlink, or reaches out through one, is not content-verified" [] {
    let tmp_dir = $in.tmp_dir
    let key = $"($tmp_dir)/attacker"
    ^ssh-keygen -t ed25519 -f $key -N "" -q
    "secret\n" | save --force $"($tmp_dir)/outside.txt"

    # 1. the leaf itself is a link to the verifier's file
    let link_dir = $"($tmp_dir)/link"
    mkdir $link_dir
    ^ln -s $"($tmp_dir)/outside.txt" $"($link_dir)/leaked.txt"
    let link_proof = forge-bundle $link_dir {
        filepath: "leaked.txt" content_sha256: ("secret\n" | hash sha256)
        content_git: "" content_cid: ""
    } $key
    let linked = merkle verify $link_proof --repo $link_dir
    assert equal $linked.content_verified "symlink"
    assert not $linked.valid "a symlink was followed and reported as verified content"
    assert ($linked.error | str contains "symlink")

    # 2. a broken link — checked before existence, so it does not degrade into
    #    the vaguer "missing"
    let broken_dir = $"($tmp_dir)/broken"
    mkdir $broken_dir
    ^ln -s $"($tmp_dir)/no-such-file" $"($broken_dir)/leaked.txt"
    let broken_proof = forge-bundle $broken_dir {
        filepath: "leaked.txt" content_sha256: ("secret\n" | hash sha256)
        content_git: "" content_cid: ""
    } $key
    assert equal (merkle verify $broken_proof --repo $broken_dir).content_verified "symlink"

    # 3. the leaf is a regular file, but a parent component is a link out. The
    #    path text has no ".." and the final component is not a link, so only
    #    resolving the whole chain catches it.
    let parent_dir = $"($tmp_dir)/parent"
    mkdir $parent_dir
    ^ln -s $tmp_dir $"($parent_dir)/up"
    let parent_proof = forge-bundle $parent_dir {
        filepath: "up/outside.txt" content_sha256: ("secret\n" | hash sha256)
        content_git: "" content_cid: ""
    } $key
    let escaped = merkle verify $parent_proof --repo $parent_dir
    assert equal $escaped.content_verified "outside"
    assert not $escaped.valid "a leaf resolving out of the repo was content-verified"
}

# The manifest and the statement signed over it were never compared: verify read
# the root out of tree-root.txt and trusted it. Every artifact here is written by
# hand — CSV, statement, signature, proof JSON — because a seal round-trip can
# only produce the consistent case, which is exactly the one this checks against.
@test
def "a manifest that no longer yields the signed root is caught" [] {
    let tmp_dir = $in.tmp_dir
    let key = $"($tmp_dir)/signer"
    ^ssh-keygen -t ed25519 -f $key -N "" -q
    let dir = $"($tmp_dir)/bundle"
    mkdir $dir
    "inside\n" | save --force $"($dir)/inside.txt"
    let leaf = {
        filepath: "inside.txt" content_sha256: ("inside\n" | hash sha256)
        content_git: "" content_cid: ""
    }
    let proof = forge-bundle $dir $leaf $key
    let manifest = $"($dir)/multiproofs/tree-hashes.csv"

    # Control: a one-row catalogue whose tree IS the signed root
    [$leaf] | to csv | save --force $manifest
    let ok = merkle verify $proof --repo $dir
    assert $ok.valid "a manifest matching the signed root must verify"
    assert equal $ok.manifest_root $ok.root

    # The desync: one more catalogued row, same signed statement. The proof
    # still folds — it is a valid proof of the older seal — so nothing but the
    # rebuild can see that the CSV beside it is a different tree.
    [
        $leaf
        {filepath: "later.txt" content_sha256: ("later\n" | hash sha256) content_git: "" content_cid: ""}
    ] | to csv | save --force $manifest
    let desynced = merkle verify $proof --repo $dir
    assert $desynced.structure_valid "the proof itself still folds to the signed root"
    assert not $desynced.valid "a manifest/root desync was reported valid"
    assert not ($desynced.manifest_root == $desynced.root) "the rebuilt root must differ"
    assert ($desynced.error | str contains "different seals")
    assert error {|| merkle verify $proof --repo $dir --fail }

    # A manifest that cannot be read at all is not a verdict about the proof
    [$leaf $leaf] | to csv | save --force $manifest
    let err = try { merkle verify $proof --repo $dir; null } catch {|e| $e.msg }
    assert ($err != null) "an equivocating manifest got a verdict"
    assert ($err | str contains "duplicate filepaths")

    # No manifest is not a desync — the portable bundle layout carries none
    rm $manifest
    let portable = merkle verify $proof --repo $dir
    assert $portable.valid "a bundle without a manifest must still verify"
    assert equal $portable.manifest_root null
}

@test
def "signer flag against a bundle-supplied trust list is refused, not answered" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir

    # The fork-and-file-it-as-alice shape: one key, mallory's, registered in
    # the bundle's own pubkeys/ under alice's name and signing under it. The
    # principal is a filename, so before the guard `--signer alice` reported
    # `alice: valid` / `valid: true` for a key whose comment is mallory@evil.
    let mallory = $"($tmp_dir)/mallory"
    ^ssh-keygen -t ed25519 -f $mallory -N "" -q -C "mallory@evil"
    let pubkeys = $"($repo)/multiproofs/pubkeys"
    mkdir $pubkeys
    cp $"($mallory).pub" $"($pubkeys)/alice.pub"

    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $mallory --name alice --pubkeys-dir $pubkeys
    let proof = merkle prove README.md --repo $repo

    # Asking for a principal against a list the artifact supplies is not a
    # question this command can answer — it refuses instead of returning a
    # verdict that reads as an identity check.
    assert error {|| merkle verify $proof --repo $repo --signer alice }

    # The same artifact, checked against alice's real key: not endorsed.
    let alice = $"($tmp_dir)/alice"
    ^ssh-keygen -t ed25519 -f $alice -N "" -q
    let trusted = $"($tmp_dir)/trusted"
    mkdir $trusted
    cp $"($alice).pub" $"($trusted)/alice.pub"
    let result = merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer alice
    assert $result.structure_valid "structure must still verify"
    assert not $result.valid "mallory's key passed as alice"
    assert equal ($result.signatures | get error) [unrecognized_signer]
}

@test
def "pubkeys-dir flag supplies the verifier trust list from outside the bundle" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"
    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"
    let proof = merkle prove README.md --repo $repo

    # Trust list held outside the artifact: same key, verifier's own copy
    let trusted = $"($tmp_dir)/trusted"
    mkdir $trusted
    cp $"($key_path).pub" $"($trusted)/sshkey.pub"
    assert (merkle verify $proof --repo $repo --pubkeys-dir $trusted).valid

    # A trust list without the signer's key: the sig verifies cryptographically,
    # but nobody the verifier trusts endorsed this root
    let stranger_key = $"($tmp_dir)/stranger"
    ^ssh-keygen -t ed25519 -f $stranger_key -N "" -q
    let stranger_dir = $"($tmp_dir)/stranger-trust"
    mkdir $stranger_dir
    cp $"($stranger_key).pub" $"($stranger_dir)/stranger.pub"
    let result = merkle verify $proof --repo $repo --pubkeys-dir $stranger_dir
    assert $result.structure_valid
    assert not $result.valid
    assert equal ($result.signatures | get error) [unrecognized_signer]
}

@test
def "portable bundle: proof verifies offline in a non-git directory" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"
    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"
    let proof = merkle prove README.md --repo $repo

    # The consumer's full artifact set in the README bundle layout —
    # deliberately NOT a git repo. This pins the contract that an explicit
    # --repo needs no .git, only the relative layout (see repo-root).
    let bundle = $"($tmp_dir)/bundle"
    mkdir $"($bundle)/multiproofs/pubkeys"
    cp $"($repo)/README.md" $"($bundle)/README.md"
    cp $"($repo)/multiproofs/tree-root.txt" $"($bundle)/multiproofs/"
    cp $"($repo)/multiproofs/tree-root.txt.sshkey.sig" $"($bundle)/multiproofs/"
    cp $"($repo)/multiproofs/pubkeys/sshkey.pub" $"($bundle)/multiproofs/pubkeys/"
    let root_hash = open --raw $"($repo)/multiproofs/tree-root.txt" | hash sha256 | decode hex
    let ots_bundle = $"($bundle)/multiproofs/ots-timestamps/tree-root.cafe0000"
    mkdir $ots_bundle
    build-pending-ots --hash $root_hash | save --raw --force $"($ots_bundle)/tree-root.ots"

    let result = merkle verify $proof --repo $bundle
    assert $result.valid
    assert equal $result.content_verified true
    assert equal ($result.signatures | where valid | length) 1
    assert equal $result.ots.status "pending"
}

@test
def "ots status: discovery by content commitment, pending and anchored pinned" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    merkle write-root --repo $repo
    let proof = merkle prove README.md --repo $repo

    # Discovery keys on the stamp's content commitment: its hash must equal
    # sha256(tree-root.txt). Without these branches pinned, a silently broken
    # discovery (always "absent") would keep the suite green.
    let root_hash = open --raw $"($repo)/multiproofs/tree-root.txt" | hash sha256 | decode hex
    let bundle = $"($repo)/multiproofs/ots-timestamps/tree-root.cafe0000"
    mkdir $bundle

    # A stamp committing to a different hash is archival — stays absent
    build-pending-ots | save --raw --force $"($bundle)/tree-root.ots"
    assert equal (merkle verify $proof --repo $repo).ots.status "absent"

    build-pending-ots --hash $root_hash | save --raw --force $"($bundle)/tree-root.ots"
    let pending = merkle verify $proof --repo $repo
    assert equal $pending.ots.status "pending"
    assert equal $pending.ots.ots $"($bundle)/tree-root.ots"

    build-bitcoin-ots --hash $root_hash | save --raw --force $"($bundle)/tree-root.ots"
    assert equal (merkle verify $proof --repo $repo).ots.status "anchored"
}

@test
def "ots discovery: corrupt archival stamps skipped, anchored preferred" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    merkle write-root --repo $repo
    let proof = merkle prove README.md --repo $repo
    let root_hash = open --raw $"($repo)/multiproofs/tree-root.txt" | hash sha256 | decode hex
    let bundle = $"($repo)/multiproofs/ots-timestamps/tree-root.cafe0000"
    mkdir $bundle

    # A truncated archival .ots is an artifact of a past seal — it must not
    # crash verification of an unrelated proof
    0x[deadbeef] | save --raw --force $"($bundle)/tree-root.20260101-000000.ots"
    build-pending-ots --hash $root_hash | save --raw --force $"($bundle)/tree-root.ots"
    assert equal (merkle verify $proof --repo $repo).ots.status "pending"

    # An archived still-pending stamp sorts before <stem>.ots in glob order;
    # an anchored match must win regardless of ordering
    build-pending-ots --hash $root_hash | save --raw --force $"($bundle)/tree-root.20260102-000000.ots"
    build-bitcoin-ots --hash $root_hash | save --raw --force $"($bundle)/tree-root.ots"
    let result = merkle verify $proof --repo $repo
    assert equal $result.ots.status "anchored"
    assert equal $result.ots.ots $"($bundle)/tree-root.ots"
}

@test
def "proof against a different seal root throws loudly" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    merkle write-root --repo $repo
    let proof = merkle prove README.md --repo $repo

    # A later seal rewrote the root statement: verification must name the
    # seal mismatch, not report a quiet invalid
    root-statement ("other" | hash sha256) | save --raw --force $"($repo)/multiproofs/tree-root.txt"
    assert error {|| merkle verify $proof --repo $repo }
}
