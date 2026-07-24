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

    let result = merkle root --repo $tmp_dir
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
# by an --ipfs build: the point is what the leaf set covers, and the assertion
# must not depend on an ipfs daemon.
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
    let with_cid = merkle root --repo $tmp_dir

    assert equal $with_cid.leaves 2
    # "." is a provable row like any other
    let proof = open (merkle prove "." --repo $tmp_dir)
    assert equal $proof.leaf.content_cid $cid

    # Swap only the root CID: a different root means the signature over the old
    # root no longer covers this manifest.
    $rows | update 0 {|r| $r | update content_cid $other_cid } | to csv | save --force $"($tmp_dir)/multiproofs/tree-hashes.csv"
    let swapped = merkle root --repo $tmp_dir
    assert not ($swapped.root == $with_cid.root) "changing the root-CID row left the merkle root unchanged"
}

@test
def "duplicate filepaths are a hard error - equivocation guard" [] {
    let tmp_dir = $in.tmp_dir
    mkdir $"($tmp_dir)/multiproofs"
    let row = {filepath: "a.txt" content_sha256: ("one" | hash sha256) content_git: "" content_cid: ""}
    [$row $row] | to csv | save --force $"($tmp_dir)/multiproofs/tree-hashes.csv"

    # Not bare `assert error` because: it stays green on ANY error (e.g.
    # manifest-not-found) — pin the equivocation message
    let err = try { merkle root --repo $tmp_dir; null } catch {|e| $e.msg }
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
    let err = try { merkle root --repo $tmp_dir; null } catch {|e| $e.msg }
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

    let root_result = merkle root --repo $repo
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

    let root_result = merkle root --repo $repo
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

    let root_result = merkle root --repo $repo
    ssh-sign sign $root_result.path --key $mallory --pubkeys-dir $pubkeys
    let proof = merkle prove README.md --repo $repo

    # Default: any key in the bundle's list satisfies valid — internal
    # consistency only
    assert (merkle verify $proof --repo $repo).valid

    # Signature is cryptographically valid, but it is not alice's
    let wrong = merkle verify $proof --repo $repo --signer alice
    assert $wrong.structure_valid "structure must still verify"
    assert not $wrong.valid "a signature from another principal was accepted"
    assert ($wrong.error | str contains "alice")
    assert equal ($wrong.signatures | where valid | get signer) [mallory]
    assert error {|| merkle verify $proof --repo $repo --signer alice --fail }

    assert (merkle verify $proof --repo $repo --signer mallory).valid
}

@test
def "pubkeys-dir flag supplies the verifier trust list from outside the bundle" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"
    let root_result = merkle root --repo $repo
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
    let root_result = merkle root --repo $repo
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
    merkle root --repo $repo
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
    merkle root --repo $repo
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
    merkle root --repo $repo
    let proof = merkle prove README.md --repo $repo

    # A later seal rewrote the root statement: verification must name the
    # seal mismatch, not report a quiet invalid
    root-statement ("other" | hash sha256) | save --raw --force $"($repo)/multiproofs/tree-root.txt"
    assert error {|| merkle verify $proof --repo $repo }
}
