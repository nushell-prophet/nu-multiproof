use std/assert
use std/testing *

use ../nu-multiproof/merkle.nu
use ../nu-multiproof/tree-hashes.nu
use ../nu-multiproof/ssh-sign.nu
use ../nu-multiproof/pubkey.nu
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

# The principal a key signs under, and the value `--signer` takes: the
# fingerprint of the key's public half. Never a file name — that is the whole
# point of it (see nu-multiproof/pubkey.nu fingerprint).
def principal-of [key: path]: nothing -> string {
    open --raw $"($key).pub" | pubkey fingerprint
}

# A 40-hex stand-in for a git SHA-1 object hash: nushell's `hash` offers no
# sha1, and these rows are fixture bytes rather than values some git produced.
def fake-sha1 [seed: string]: nothing -> string {
    $seed | hash sha256 | str substring 0..<40
}

# Fixed 4-row manifest for golden-root pinning. Deliberately unsorted (builder
# must sort itself) with a numeric-looking filepath (must stay a string) and a
# directory row (empty sha256/cid).
def write-mini-manifest [repo: path] {
    mkdir $"($repo)/multiproofs"
    [
        {filepath: "z.txt" content_sha256: ("one" | hash sha256) content_git_sha1: (fake-sha1 "two") content_git_sha256: ("two" | hash sha256) content_cid: ""}
        {filepath: "docs" content_sha256: "" content_git_sha1: (fake-sha1 "three") content_git_sha256: ("three" | hash sha256) content_cid: ""}
        {filepath: "docs/a.md" content_sha256: ("four" | hash sha256) content_git_sha1: (fake-sha1 "five") content_git_sha256: ("five" | hash sha256) content_cid: "QmNwvubv2KpTeugGN29uBnaZhZkDCwG4kMrx2vAEBk9nPo"}
        {filepath: "42" content_sha256: ("six" | hash sha256) content_git_sha1: (fake-sha1 "seven") content_git_sha256: ("seven" | hash sha256) content_cid: ""}
    ] | to csv | save --force $"($repo)/multiproofs/tree-hashes.csv"
}

const GOLDEN_MINI_ROOT = "fffe0c09f1f3a7d030f6246c4b3bbdb07727cfc26e1b0433f57c07151180119a"

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
    assert equal $statement $"multiproof-merkle-v4 ($GOLDEN_MINI_ROOT) 0 genesis none\n"
    assert equal (parse-root-statement $"($tmp_dir)/multiproofs/tree-root.txt") {root: $GOLDEN_MINI_ROOT seq: 0 prev: "genesis" beacon: "none"}
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
        {filepath: "." content_sha256: "" content_git_sha1: "" content_git_sha256: "" content_cid: $cid}
        {filepath: "z.txt" content_sha256: ("one" | hash sha256) content_git_sha1: (fake-sha1 "two") content_git_sha256: ("two" | hash sha256) content_cid: ""}
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
    "filepath,content_sha256,content_git_sha1,content_git_sha256,content_cid\n"
        | save --force $"($tmp_dir)/multiproofs/tree-hashes.csv"

    let err = try { merkle write-root --repo $tmp_dir; null } catch {|e| $e.msg }
    assert ($err != null) "an empty manifest minted a root"
    assert ($err | str contains "lists no files")
    # Nothing written: a signature over e3b0c442… would carry no repo in it
    assert not ($"($tmp_dir)/multiproofs/tree-root.txt" | path exists)
}

# The end-to-end shape of the same replay: build-tree unconditionally appends
# the "." row, so an actual empty repo yields a ONE-row manifest and the
# zero-row form of the guard never fired — two distinct empty repos both
# sealed to the constant root ccc017f7… the guard exists to refuse.
@test
def "an empty git repo cannot mint a root - its one-row manifest is constant too" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/empty"
    mkdir $repo
    ^git -C $repo init -q
    tree-hashes --repo $repo

    let err = try { merkle write-root --repo $repo; null } catch {|e| $e.msg }
    assert ($err != null) "an empty repo minted a root"
    assert ($err | str contains "lists no files")
    assert not ($"($repo)/multiproofs/tree-root.txt" | path exists)
}

@test
def "duplicate filepaths are a hard error - equivocation guard" [] {
    let tmp_dir = $in.tmp_dir
    mkdir $"($tmp_dir)/multiproofs"
    let row = {filepath: "a.txt" content_sha256: ("one" | hash sha256) content_git_sha1: "" content_git_sha256: "" content_cid: ""}
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
    let evil = $"evil\n(('x' | hash sha256))\n((fake-sha1 'y'))\n(('z' | hash sha256))\n"
    [{filepath: $evil content_sha256: ("one" | hash sha256) content_git_sha1: "" content_git_sha256: "" content_cid: ""}]
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
            validate-leaf {filepath: $bad content_sha256: "" content_git_sha1: "" content_git_sha256: "" content_cid: ""}
            null
        } catch {|e| $e.msg }
        assert ($err != null) $"escaping filepath was accepted: ($bad)"
        assert ($err | str contains "must stay inside the repo")
    }
    # "." is the root-CID row — legal, and a file named "..foo" is not a
    # traversal either
    validate-leaf {filepath: "." content_sha256: "" content_git_sha1: "" content_git_sha256: "" content_cid: ""}
    validate-leaf {filepath: "..foo" content_sha256: "" content_git_sha1: "" content_git_sha256: "" content_cid: ""}
}

@test
def "uppercase hex in a leaf is rejected, not normalized" [] {
    assert error {||
        validate-leaf {
            filepath: "a.txt"
            content_sha256: ("one" | hash sha256 | str uppercase)
            content_git_sha1: "" content_git_sha256: ""
            content_cid: ""
        }
    }
}

@test
def "malformed root statements are rejected" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/tree-root.txt"
    let root = "one" | hash sha256
    let prev = "zero" | hash sha256

    let beacon = $"bitcoin:964771:($root)"
    for bad in [
        $"multiproof-merkle-v4 ($root) 1 ($prev) none\n\n" # extra trailing newline
        $"multiproof-merkle-v4 ($root) 1 ($prev) none" # missing newline
        $"multiproof-merkle-v4 ($root | str uppercase) 1 ($prev) none\n" # uppercase hex
        $"($root) 1 ($prev) none\n" # bare hash, no statement prefix
        $"multiproof-merkle-v2 ($root) 1 ($prev) none\n" # another schema — parser must track MERKLE_SCHEMA
        $"multiproof-merkle-v4 ($root)\n" # the v1 shape: no seq, no predecessor
        $"multiproof-merkle-v4 ($root) 01 ($prev) none\n" # leading zero — two spellings of one seq under one signature
        $"multiproof-merkle-v4 ($root) 0 ($prev) none\n" # seq 0 naming a predecessor its own count denies
        $"multiproof-merkle-v4 ($root) 3 genesis none\n" # genesis at seq 3 — four seals hidden
        $"multiproof-merkle-v3 ($root) 1 ($prev)\n" # the v3 shape: no beacon field at all
        $"multiproof-merkle-v4 ($root) 1 ($prev)\n" # v4 token, v3 body — the field is not optional
        $"multiproof-merkle-v4 ($root) 1 ($prev) ($beacon | str upcase)\n" # uppercase beacon hash
        $"multiproof-merkle-v4 ($root) 1 ($prev) bitcoin:0964771:($root)\n" # leading zero in the beacon height
        $"multiproof-merkle-v4 ($root) 1 ($prev) bitcoin:964771\n" # beacon height with no hash
        $"multiproof-merkle-v4 ($root) 1 ($prev) ethereum:964771:($root)\n" # a chain this format does not define
        $"multiproof-merkle-v4 ($root) 1 ($prev) ($beacon) ($beacon)\n" # a second beacon appended
    ] {
        $bad | save --raw --force $file
        assert error {|| parse-root-statement $file } $"accepted: ($bad | to json)"
    }
}

# read-root exists so a consumer never reimplements the statement regex — the
# test therefore reads through the command the way that consumer does: one
# snapshot file, named by path.
@test
def "read-root returns the statement as data" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    let written = merkle write-root --repo $repo

    let snapshot = $"($tmp_dir)/snap-tree-root.txt"
    cp $"($repo)/multiproofs/tree-root.txt" $snapshot
    assert equal (merkle read-root $snapshot) {root: $written.root seq: 0 prev: "genesis" beacon: "none"}

    # The one place a missing statement is reported, so the consumer walking
    # seals/ never needs a check of its own.
    let err = try { merkle read-root $"($tmp_dir)/absent.txt"; null } catch {|e| $e.msg }
    assert str contains $err "root statement not found"
}

@test
def "the first root statement is genesis at sequence 0" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir

    let first = merkle write-root --repo $repo
    assert equal $first.seq 0
    assert equal $first.prev "genesis"
}

# The beacon travels with the counter, so it inherits the counter's idempotence
# — deliberately. A fresh beacon on every derivation would rewrite bytes whose
# meaning never moved, and `seal` would then clear every co-signer's signature
# over them: the beacon would cost exactly what the seq counter was built to
# avoid. So a carry-over ignores the beacon it is handed.
@test
def "re-deriving an unchanged tree keeps the beacon it was sealed under" [] {
    let repo = make-test-repo $in.tmp_dir
    let statement = $"($repo)/multiproofs/tree-root.txt"
    let first_beacon = "bitcoin:0:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

    let first = merkle write-root --repo $repo --beacon $first_beacon
    assert equal $first.beacon $first_beacon
    let bytes = open --raw $statement

    let again = merkle write-root --repo $repo --beacon "bitcoin:800000:00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"
    assert equal $again.beacon $first_beacon
    assert equal (open --raw $statement) $bytes "an unchanged tree rewrote its statement"
}

@test
def "a new root carries the beacon it was minted with" [] {
    let repo = make-test-repo $in.tmp_dir
    let later_beacon = "bitcoin:800000:00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"
    merkle write-root --repo $repo --beacon "bitcoin:0:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

    "later\n" | save --force $"($repo)/new.txt"
    ^git -C $repo add new.txt
    tree-hashes --repo $repo
    let second = merkle write-root --repo $repo --beacon $later_beacon

    assert equal $second.seq 1
    assert equal $second.beacon $later_beacon
    assert equal (parse-root-statement $"($repo)/multiproofs/tree-root.txt").beacon $later_beacon
}

@test
def "a malformed beacon is refused before the statement is touched" [] {
    let repo = make-test-repo $in.tmp_dir
    let statement = $"($repo)/multiproofs/tree-root.txt"
    merkle write-root --repo $repo
    let bytes = open --raw $statement

    assert error {|| merkle write-root --repo $repo --beacon "bitcoin:0:not-a-hash" }
    assert equal (open --raw $statement) $bytes "a refused beacon still rewrote the statement"
}

# A statement with no beacon is legal, and is what an offline derivation writes:
# a bound nobody could mint is better stated as absent than faked.
@test
def "a derivation with no beacon says so" [] {
    let repo = make-test-repo $in.tmp_dir
    assert equal (merkle write-root --repo $repo).beacon "none"
}

# The counter is what makes a removed seal visible: seals are keyed by root, so
# without it a chain of three and a chain of two look alike from any single
# statement.
@test
def "each seal raises the sequence by one and names the root it supersedes" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    let first = merkle write-root --repo $repo

    "later\n" | save --force $"($repo)/new.txt"
    ^git -C $repo add new.txt
    tree-hashes --repo $repo
    let second = merkle write-root --repo $repo

    assert equal $second.seq 1
    assert equal $second.prev $first.root
    assert equal (parse-root-statement $"($repo)/multiproofs/tree-root.txt") {root: $second.root seq: 1 prev: $first.root beacon: "none"}
}

@test
def "a proof file holding a JSON scalar is refused, not a crash" [] {
    let tmp_dir = $in.tmp_dir
    for bad in ['"hello"' '42' '[1, 2]'] {
        let proof_file = $"($tmp_dir)/proof.json"
        $bad | save --raw --force $proof_file
        let err = try { merkle verify $proof_file --repo $tmp_dir; null } catch {|e| $e.msg }
        assert ($err != null) $"accepted: ($bad)"
        assert ($err | str contains "not a multiproof") $"opaque error for ($bad): ($err)"
    }
}

# Nushell completion appends the slash when the argument is a directory, so
# `merkle prove sub/` is what a user actually types. The manifest never carries
# one — `/` is the one byte a filename cannot contain — so the row lookup missed
# and the command reported a catalogued directory as absent from the catalogue.
@test
def "a directory row is provable with the trailing slash completion appends" [] {
    let repo = make-test-repo $in.tmp_dir

    let plain = merkle prove "sub" --repo $repo
    let slashed = merkle prove "sub/" --repo $repo

    # Same output path, and not the hidden inclusion-proofs/sub/.multiproof.json
    # that joining the untrimmed argument would have written.
    assert equal $slashed $plain
    assert equal ($slashed | path basename) "sub.multiproof.json"
    # The leaf comes from the matched row, so the trimmed key never reaches it
    assert equal (open $slashed | get leaf.filepath) "sub"
}

# The slash is one-way evidence: present, the caller means a directory; absent,
# it says nothing, since `merkle prove sub` asks for the same row. So it can
# only reject — and a file row under a directory argument is the caller and the
# catalogue disagreeing about what that path is.
@test
def "a trailing slash on a file row is refused rather than quietly dropped" [] {
    let repo = make-test-repo $in.tmp_dir

    let err = try { merkle prove "README.md/" --repo $repo; null } catch {|e| $e.msg }
    assert ($err != null) "a file row answered a proof request for a directory"
    assert ($err | str contains "lists README.md as a file")
    assert not ($repo | path join multiproofs inclusion-proofs README.md.multiproof.json | path exists)
}

# Trimming the slash leaves nothing at all for "/" and "//", so the
# not-in-the-manifest throw named nothing either — a message reading as if the
# argument were missing rather than absolute. The repo root is the "." row.
@test
def "an argument that is only slashes is refused by name, not as an empty key" [] {
    let repo = make-test-repo $in.tmp_dir

    for arg in ["/" "//"] {
        let err = try { merkle prove $arg --repo $repo; null } catch {|e| $e.msg }
        assert ($err != null) $"($arg) was accepted as a manifest row"
        assert ($err | str starts-with $"($arg) names no manifest row") $"the error does not name the argument: ($err)"
        assert ($err | str contains '"." row') "the error does not point at the row that is the repo root"
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

    # Directory row: attests only a content_cid, which verify re-derives from
    # the tracked files under it.
    let dir_result = merkle verify (merkle prove sub --repo $repo) --repo $repo
    assert $dir_result.valid
    assert equal $dir_result.content_verified true

    # The "." row is the same shape over the whole repo.
    let root_row = merkle verify (merkle prove "." --repo $repo) --repo $repo
    assert $root_row.valid
    assert equal $root_row.content_verified true
}

# The attack: alice's genuine root, her genuine signature and her genuine
# proof of the `sub` row, shipped with the attacker's own files inside sub/.
# Every other check passes — it is her seal — and the one thing that would
# notice is the directory's content. This repo's own manifest has four such
# rows, "." among them.
@test
def "a directory row does not verify against a directory that was rewritten" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"
    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"
    let dir_proof = merkle prove sub --repo $repo
    let root_proof = merkle prove "." --repo $repo

    # Control: untouched, both verify.
    assert (merkle verify $dir_proof --repo $repo).valid
    assert (merkle verify $root_proof --repo $repo).valid

    # A file ADDED under sub/ — invisible to any check driven by the manifest,
    # since it is by definition not catalogued. Tracked, because the CID is a
    # function of the tracked tree.
    "backdoor\n" | save --force $"($repo)/sub/backdoor.sh"
    ^git -C $repo add sub/backdoor.sh

    let tampered = merkle verify $dir_proof --repo $repo
    assert not $tampered.valid "an added file left the directory row verifying"
    assert equal $tampered.content_verified false
    assert ($tampered.error | str contains "content_cid")

    # "." covers it too — the added file is inside the repo root.
    let tampered_root = merkle verify $root_proof --repo $repo
    assert not $tampered_root.valid
    assert equal $tampered_root.content_verified false
}

# The dir-row edition of the symlink attack: the git index still lists
# sub/inner.txt as a regular file, so the builder's mode-120000 gate never
# fires — the swap happens on disk after sealing, which is exactly the state a
# verifier must not trust. The outside directory holds the EXACT sealed bytes,
# so a verifier that follows the link re-derives the proven CID and answers
# `content_verified: true, valid: true` for content the bundle does not
# contain — and a MISMATCH on other bytes makes it a confirmation oracle about
# the verifier's own files. The only non-oracle answer is a refusal.
@test
def "a proven directory swapped for a symlink is refused, not re-derived" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"
    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"
    let dir_proof = merkle prove sub --repo $repo
    let root_proof = merkle prove "." --repo $repo

    let outside = $"($tmp_dir)/outside-dir"
    mkdir $outside
    "world\n" | save --force $"($outside)/inner.txt" # the sealed bytes, byte for byte
    rm --recursive $"($repo)/sub"
    ^ln -s $outside $"($repo)/sub"

    # "outside", not true (the bytes match) and not false (false would be the
    # oracle's other half): the check refuses before reading anything.
    let swapped = merkle verify $dir_proof --repo $repo
    assert equal $swapped.content_verified "outside"
    assert not $swapped.valid "a symlinked-away directory verified against outside content"
    assert ($swapped.error | str contains "sub")

    # "." commits to the same subtree, so it must refuse identically.
    let root_row = merkle verify $root_proof --repo $repo
    assert equal $root_row.content_verified "outside"
    assert not $root_row.valid
}

# A tracked file deleted from the worktree is the ordinary mid-edit state, not
# an attack. Both row shapes must yield a verdict.
@test
def "a deleted tracked file gives every row a verdict, not a crash" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"
    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"
    let file_proof = merkle prove sub/inner.txt --repo $repo
    let dir_proof = merkle prove sub --repo $repo

    rm $"($repo)/sub/inner.txt"

    let file_row = merkle verify $file_proof --repo $repo
    assert equal $file_row.content_verified "missing"
    assert not $file_row.valid

    let dir_row = merkle verify $dir_proof --repo $repo
    assert equal $dir_row.content_verified "missing"
    assert not $dir_row.valid "a directory row verified over a deleted member"
    assert ($dir_row.error | str contains "sub")
}

# The scope line, stated as a test rather than left to be discovered: the
# manifest catalogues git-tracked files, so an untracked file is outside what
# any row commits to. Making it a divergence would fail verification on every
# build artifact. A directory verifying therefore means "the tracked contents
# are the sealed ones", NOT "nothing else sits here" — and `ipfs add` over a
# working tree with untracked files gives a different CID than the "." row.
@test
def "an untracked file under a proven directory is outside what the row commits to" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"
    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"
    let dir_proof = merkle prove sub --repo $repo

    "backdoor\n" | save --force $"($repo)/sub/backdoor.sh"
    let untracked = merkle verify $dir_proof --repo $repo
    assert $untracked.valid "an untracked file is not part of the tracked tree the CID commits to"
    assert equal $untracked.content_verified true

    # The same file, staged, IS part of it.
    ^git -C $repo add sub/backdoor.sh
    assert equal (merkle verify $dir_proof --repo $repo).content_verified false
}

# validate-leaf permits a row whose content_cid is empty, and the README tree
# spec says so too. Such a row commits to no content: verify has nothing to
# check, and "nothing to check" must not read as "checked and fine". Today's
# tree-hashes always writes a CID, so this is reachable only through a manifest
# built by hand — which is exactly the artifact a verifier does not trust.
@test
def "a leaf that commits to no content is not valid" [] {
    let tmp_dir = $in.tmp_dir
    let key = $"($tmp_dir)/attacker"
    ^ssh-keygen -t ed25519 -f $key -N "" -q
    let dir = $"($tmp_dir)/ghostly"
    mkdir $dir
    let proof = forge-bundle $dir {
        filepath: "ghost" content_sha256: "" content_git_sha1: "" content_git_sha256: "" content_cid: ""
    } $key

    let result = merkle verify $proof --repo $dir
    assert $result.structure_valid "the path still folds — the forgery is in what the row omits"
    assert not $result.valid "a row committing to nothing was reported valid"
    assert equal $result.content_verified "unverifiable"
    assert equal $result.content_enumeration null "a row with nothing to check still claimed a file set was enumerated"
    assert ($result.error | str contains "commits to no content")
}

# --- portable directory proofs ---

# A sealed repo and a genuine portable bundle of it: the sealed subtree, the
# root statement, its signature and the signer's key, laid out the way README
# "Verifying without the origin repo" pins. Every test below mutates exactly one
# thing away from this, so what each one proves is the mutation and nothing else.
def make-sealed-bundle [tmp_dir: path]: nothing -> record {
    let repo = make-test-repo $tmp_dir
    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"
    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"

    let bundle = $"($tmp_dir)/bundle"
    mkdir $"($bundle)/multiproofs/pubkeys" $"($bundle)/sub"
    cp $"($repo)/README.md" $"($bundle)/"
    cp $"($repo)/sub/inner.txt" $"($bundle)/sub/"
    cp $"($repo)/multiproofs/tree-root.txt" $"($bundle)/multiproofs/"
    cp $"($repo)/multiproofs/tree-root.txt.(principal-of $key_path).sig" $"($bundle)/multiproofs/"
    cp $"($repo)/multiproofs/pubkeys/sshkey.pub" $"($bundle)/multiproofs/pubkeys/"
    {
        repo: $repo
        bundle: $bundle
        dir_proof: (merkle prove sub --repo $repo)
        root_proof: (merkle prove "." --repo $repo)
    }
}

# The half that makes a bundle worth shipping: the sealed subtree re-derives its
# own CID away from the origin repo, with no git anywhere.
@test
def "a non-git bundle carrying the sealed subtree verifies a directory row" [] {
    let fx = make-sealed-bundle $in.tmp_dir

    let result = merkle verify $fx.dir_proof --repo $fx.bundle --bundle
    assert equal $result.content_verified true "the sealed subtree did not re-derive its own CID"
    assert $result.valid "a genuine portable directory proof was refused"
}

# multiproofs/ is excluded when the manifest is built, so a bundle proving the
# "." row carries the proof directory INSIDE the tree the walk covers. Keeping
# it folds a different CID for every bundle — no "." row could ever verify away
# from its repo, and the failure would look like tampering.
@test
def "a bundle proving the root row excludes its own proof directory from the walk" [] {
    let fx = make-sealed-bundle $in.tmp_dir

    let result = merkle verify $fx.root_proof --repo $fx.bundle --bundle
    assert equal $result.content_verified true "the bundle's own multiproofs/ was folded into the root CID"
    assert $result.valid "a genuine portable proof of the whole repo was refused"
}

# The same argument for the other directory the builder's enumeration cannot
# see. `git ls-files` never lists a path under .git, so those bytes were never in
# the sealed CID — and the shape that hits it is the most ordinary distribution
# there is, a clone of a sealed repo. The subtree tests above cannot catch it:
# .git sits outside their row's scope, so only the "." row breaks.
@test
def "the root row of a bundle distributed as a git repo still verifies" [] {
    let fx = make-sealed-bundle $in.tmp_dir
    ^git -C $fx.bundle init -q
    ^git -C $fx.bundle add README.md sub/inner.txt o+e>| ignore
    ^git -C $fx.bundle -c user.email=t@t -c user.name=t commit -q -m seed

    let result = merkle verify $fx.root_proof --repo $fx.bundle --bundle
    assert equal $result.content_verified true "the bundle's own .git was folded into the root CID"
    assert $result.valid "a genuine bundle shipped as a git repo was reported as tampered"
}

# The ordinary consumer case, and the one that must not read as tampering: a
# genuine bundle unpacked INSIDE some git repo of the consumer's own.
# `rev-parse --is-inside-work-tree` answers yes there, so `git ls-files` ran over
# the bundle path and listed whatever was tracked there — usually nothing — and
# sealed, untouched evidence was reported as `content_verified: false`, "the
# directory's tracked contents differ from the sealed catalogue". Claiming
# tampering about evidence nobody touched is as bad as missing tampering.
@test
def "a genuine bundle unpacked inside another git repo still verifies" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealed-bundle $tmp_dir

    let outer = $"($tmp_dir)/consumer"
    mkdir $outer
    ^git -C $outer init -q
    cp --recursive $fx.bundle $"($outer)/bundle"

    let nested = merkle verify $fx.dir_proof --repo $"($outer)/bundle" --bundle
    assert $nested.valid "a bundle inside a git repo was judged against that repo's index"
}

# A hostile bundle, hand-built rather than produced here: alice's real root, her
# real signature and her real proof of `sub`, with the attacker's bytes under
# sub/. Away from the origin repo the subtree the bundle carries IS the
# enumeration, so this is the case that decides whether walking it is safe. It
# is: the sealed content_cid commits to every entry, so substituted bytes fold
# to a different CID.
@test
def "a non-git bundle carrying the wrong bytes under a proven directory is refused" [] {
    let fx = make-sealed-bundle $in.tmp_dir
    "anything at all\n" | save --force $"($fx.bundle)/sub/inner.txt"

    let result = merkle verify $fx.dir_proof --repo $fx.bundle --bundle
    assert $result.structure_valid "structure is genuine — this is alice's real proof"
    assert not $result.valid "a bundle carrying the wrong bytes under a proven directory verified"
    assert equal $result.content_verified false
    assert ($result.error | str contains "differ from the sealed catalogue")
}

# The other two verbs the README claims. A directory CID commits to the entry
# list, not only to each file's bytes, so both have to be pinned separately from
# the substitution above — none of the three implies the others.
@test
def "a bundle that drops a file from a proven directory is refused" [] {
    let fx = make-sealed-bundle $in.tmp_dir
    rm $"($fx.bundle)/sub/inner.txt"

    let result = merkle verify $fx.dir_proof --repo $fx.bundle --bundle
    assert not $result.valid "a bundle missing a sealed file under the proven directory verified"
    assert equal $result.content_verified "missing" "an empty subtree read as a content mismatch, not as absent"
}

@test
def "a bundle that adds a file under a proven directory is refused" [] {
    let fx = make-sealed-bundle $in.tmp_dir
    "payload\n" | save --force $"($fx.bundle)/sub/extra.txt"

    let result = merkle verify $fx.dir_proof --repo $fx.bundle --bundle
    assert not $result.valid "a bundle with an added file under the proven directory verified"
    assert equal $result.content_verified false
}

# The blocking hole this flag exists to close. A `.git` costs a sender nothing,
# and one whose index lists exactly the sealed paths hands the sender the file
# set: the extra file becomes untracked, the git arm ignores it by design, and
# the bundle answers valid. The enumeration must be the verifier's choice, so
# --bundle ignores any index the target carries.
@test
def "a bundle cannot hand itself the git arm by shipping its own index" [] {
    let fx = make-sealed-bundle $in.tmp_dir
    "payload\n" | save --force $"($fx.bundle)/sub/extra.txt"
    ^git -C $fx.bundle init -q
    ^git -C $fx.bundle add sub/inner.txt o+e>| ignore
    ^git -C $fx.bundle -c user.email=m@m -c user.name=m commit -q -m seed

    let guarded = merkle verify $fx.dir_proof --repo $fx.bundle --bundle
    assert not $guarded.valid "the sender's own index decided the file set under --bundle"
    assert equal $guarded.content_verified false
    assert equal $guarded.content_enumeration "walk"

    # Without the flag the target still gets to be a git repo root, which is the
    # documented worktree behaviour — an untracked file is outside what the row
    # commits to. Asserted so the difference the flag makes stays visible: if
    # this ever starts failing, --bundle has become a no-op and the test above
    # would keep passing.
    #
    # This arm is the sender's choice, and the result must say so: the two
    # readings of content_verified: true are different claims, and a consumer
    # keying on .valid has nothing else to tell them apart by.
    let unguarded = merkle verify $fx.dir_proof --repo $fx.bundle
    assert equal $unguarded.content_verified true "the git arm stopped honouring the target's index"
    assert equal $unguarded.content_enumeration "git-index" "a verdict reached through the target's own index did not say so"
}

# A file row is checked against its own content_sha256 and never asks what else
# is on disk, so there is no enumeration to report — and reporting one anyway
# would suggest a file set was consulted when none was.
@test
def "a file row reports no enumeration at all" [] {
    let fx = make-sealed-bundle $in.tmp_dir
    let file_proof = merkle prove README.md --repo $fx.repo

    let file_row = merkle verify $file_proof --repo $fx.bundle --bundle
    assert equal $file_row.content_verified true
    assert equal $file_row.content_enumeration null "a file row claimed a directory enumeration"
}

# The walk covers everything on disk, where the git arm covered only the tracked
# set — so without scoping, one stray link ANYWHERE under the target reported a
# genuine proof as tampered, with a message naming a path that is neither
# tracked nor under the proven row. A directory node depends on nothing outside
# itself, so the walk is scoped to the row's own subtree.
@test
def "a symlink outside the proven subtree does not touch the verdict" [] {
    let fx = make-sealed-bundle $in.tmp_dir
    ^ln -s /etc/hosts $"($fx.bundle)/notes.lnk"

    let result = merkle verify $fx.dir_proof --repo $fx.bundle --bundle
    assert equal $result.content_verified true "a link beside the proven directory decided its verdict"
    assert $result.valid
}

# The same link INSIDE the subtree must still be refused, and refused before any
# bytes are read: following it would re-derive the CID from content the bundle
# does not carry, and a matches/MISMATCH answer over the verifier's own files is
# an oracle about them. _tracked.nu argues walked-entries needs no symlink gate
# of its own because resolve-leaf-file catches them one layer up — this is the
# hostile artifact that feeds the walk arm and checks that argument.
@test
def "a symlink inside a proven subtree is refused by the walk, not followed" [] {
    let fx = make-sealed-bundle $in.tmp_dir
    rm $"($fx.bundle)/sub/inner.txt"
    ^ln -s /etc/hosts $"($fx.bundle)/sub/inner.txt"

    let result = merkle verify $fx.dir_proof --repo $fx.bundle --bundle
    assert not $result.valid "a symlinked member of a proven directory was verified"
    assert equal $result.content_verified "symlink"
}


# The containment check runs on the resolved path, so it has to reject a
# sibling as well as a parent. `--repo /a/repo` with a link resolving to
# /a/repo-evil/x is the case a `str starts-with $root` (no separator) lets
# through, and the test above cannot see it — escaping to a parent fails
# either way.
@test
def "a leaf resolving into a sibling directory is outside, not inside" [] {
    let tmp_dir = $in.tmp_dir
    let key = $"($tmp_dir)/attacker"
    ^ssh-keygen -t ed25519 -f $key -N "" -q

    let repo = $"($tmp_dir)/repo"
    let sibling = $"($tmp_dir)/repo-evil"
    mkdir $repo $sibling
    "secret\n" | save --force $"($sibling)/x.txt"
    ^ln -s $sibling $"($repo)/out"

    let proof = forge-bundle $repo {
        filepath: "out/x.txt" content_sha256: ("secret\n" | hash sha256)
        content_git_sha1: "" content_git_sha256: "" content_cid: ""
    } $key
    let result = merkle verify $proof --repo $repo
    assert equal $result.content_verified "outside"
    assert not $result.valid
}

# A file row whose path is a directory on disk reached `open --raw <dir>` and
# died with a bare "I/O error" naming neither the path nor the leaf — a hostile
# artifact crashing the verifier instead of getting a verdict.
@test
def "a file row landing on a directory gets a verdict, not an I/O error" [] {
    let tmp_dir = $in.tmp_dir
    let key = $"($tmp_dir)/attacker"
    ^ssh-keygen -t ed25519 -f $key -N "" -q
    let dir = $"($tmp_dir)/dirrow"
    mkdir $"($dir)/notafile"

    let proof = forge-bundle $dir {
        filepath: "notafile" content_sha256: ("anything" | hash sha256)
        content_git_sha1: "" content_git_sha256: "" content_cid: ""
    } $key
    let result = merkle verify $proof --repo $dir
    assert equal $result.content_verified "directory"
    assert not $result.valid
    assert ($result.error | str contains "it is a directory")
}

# Every discovery step here (pubkeys for the allowed_signers body, the signer
# lookup, sig files beside the root statement, archived OTS bundles) takes a
# directory path. A glob pattern built from one matches nothing, silently, for
# a repo checked out under a name holding `[`, `]`, `*` or `?`: no keys in the
# trust list, no signature found.
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
    # Signing reads pubkeys/ to check the key is registered: one of the
    # discovery steps above.
    ssh-sign sign $root_result.path --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"

    let result = merkle verify (merkle prove README.md --repo $repo) --repo $repo
    assert $result.valid "a repo path with glob metacharacters broke the roundtrip"
    assert equal ($result.signatures | where valid | length) 1
    assert equal $result.signatures.0.signer (principal-of $key_path)
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
    # catalogue, not "nothing to check"
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

    # The verifier's own copy of the list, holding the same two keys.
    let trusted = $"($tmp_dir)/trusted"
    mkdir $trusted
    cp $"($alice).pub" $"($trusted)/alice.pub"
    cp $"($mallory).pub" $"($trusted)/mallory.pub"

    # Signature is cryptographically valid, but it is not alice's
    let wrong = merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer (principal-of $alice)
    assert $wrong.structure_valid "structure must still verify"
    assert not $wrong.valid "a signature from another principal was accepted"
    assert ($wrong.error | str contains (principal-of $alice))
    assert equal ($wrong.signatures | where valid | get signer) [(principal-of $mallory)]
    assert error {|| merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer (principal-of $alice) --fail }

    assert (merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer (principal-of $mallory)).valid
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

    let alice = $"($tmp_dir)/alice"
    ^ssh-keygen -t ed25519 -f $alice -N "" -q
    let err = try { merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer (principal-of $alice); null } catch {|e| $e.msg }
    assert ($err != null) "a signer the trust list cannot answer for got a verdict"
    assert ($err | str contains $"no key with fingerprint (principal-of $alice)")

    # Same list, a principal it does hold: answered, not refused.
    let answered = merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer (principal-of $bob)
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
    let leaf_bytes = [$leaf.filepath $leaf.content_sha256 $leaf.content_git_sha1 $leaf.content_git_sha256 $leaf.content_cid]
        | str join "\n" | into binary
    let root = 0x[00] | bytes add --end $leaf_bytes | hash sha256
    $"multiproof-merkle-v4 ($root) 0 genesis none\n" | save --force $"($dir)/multiproofs/tree-root.txt"
    ssh-sign sign $"($dir)/multiproofs/tree-root.txt" --key $key --pubkeys-dir $"($dir)/multiproofs/pubkeys"
    let proof_file = $"($dir)/proof.json"
    {schema: "multiproof-merkle-v4" leaf: $leaf path: [] root: $root} | to json | save --force $proof_file
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
        content_git_sha1: "" content_git_sha256: "" content_cid: ""
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
        content_git_sha1: "" content_git_sha256: "" content_cid: ""
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
        content_git_sha1: "" content_git_sha256: "" content_cid: ""
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
        content_git_sha1: "" content_git_sha256: "" content_cid: ""
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
        content_git_sha1: "" content_git_sha256: "" content_cid: ""
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
        content_git_sha1: "" content_git_sha256: "" content_cid: ""
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
        {filepath: "later.txt" content_sha256: ("later\n" | hash sha256) content_git_sha1: "" content_git_sha256: "" content_cid: ""}
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

# The fork-and-file-it-as-alice shape. Mallory's key, whose comment is
# mallory@evil, is registered in the bundle's own pubkeys/ under alice's file
# name and signs the root there. A principal is rendered from the key material,
# so the bundle can name its files anything and still cannot make its key answer
# for alice's.
#
# Everything here is checked against the trust list travelling *inside* the
# artifact — the weakest configuration the tool offers.
@test
def "a bundle cannot file one key under the fingerprint of another" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir

    let mallory = $"($tmp_dir)/mallory"
    let alice = $"($tmp_dir)/alice"
    ^ssh-keygen -t ed25519 -f $mallory -N "" -q -C "mallory@evil"
    ^ssh-keygen -t ed25519 -f $alice -N "" -q
    let pubkeys = $"($repo)/multiproofs/pubkeys"
    mkdir $pubkeys
    # Mallory's key, filed under alice's name AND under alice's fingerprint:
    # neither one buys anything, because the rendered principal comes from the
    # bytes in the file.
    cp $"($mallory).pub" $"($pubkeys)/alice.pub"
    cp $"($mallory).pub" $"($pubkeys)/(principal-of $alice).pub"

    let root_result = merkle write-root --repo $repo
    ssh-sign sign $root_result.path --key $mallory --pubkeys-dir $pubkeys
    let proof = merkle prove README.md --repo $repo

    # Asking for alice over the bundle's own list: the bundle holds no key of
    # alice's, whatever its files are called, so this cannot be answered — and
    # "alice did not sign it" is not the answer either.
    let err = try { merkle verify $proof --repo $repo --signer (principal-of $alice); null } catch {|e| $e.msg }
    assert ($err != null) "the bundle answered for a key it does not hold"
    assert ($err | str contains "no key with fingerprint")

    # Asking for the key that really signed: answered, and named for what it is.
    let honest = merkle verify $proof --repo $repo --signer (principal-of $mallory)
    assert $honest.valid "the key that signed the root was not recognized"
    assert equal ($honest.signatures | where valid | get signer) [(principal-of $mallory)]

    # And against alice's real key, held outside the artifact: not endorsed.
    let trusted = $"($tmp_dir)/trusted"
    mkdir $trusted
    cp $"($alice).pub" $"($trusted)/alice.pub"
    let result = merkle verify $proof --repo $repo --pubkeys-dir $trusted --signer (principal-of $alice)
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
    cp $"($repo)/multiproofs/tree-root.txt.(principal-of $key_path).sig" $"($bundle)/multiproofs/"
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

# --- endorsements: dating the signature, not just the content ---

# A signed repo plus a second registered signer, because dating endorsements
# is only interesting when there is more than one. Stamps are hand-built so a
# test chooses what each commits to — a stamp produced by `seal` could only
# ever agree with itself.
def make-cosigned-repo [tmp_dir: path]: nothing -> record {
    let repo = make-test-repo $tmp_dir
    let alice = $"($tmp_dir)/alice"
    let bob = $"($tmp_dir)/bob"
    let pubkeys = $"($repo)/multiproofs/pubkeys"
    ^ssh-keygen -t ed25519 -f $alice -N "" -q
    ^ssh-keygen -t ed25519 -f $bob -N "" -q
    mkdir $pubkeys
    cp $"($alice).pub" $"($pubkeys)/alice.pub"
    cp $"($bob).pub" $"($pubkeys)/bob.pub"

    let root_result = merkle write-root --repo $repo
    let alice_sig = ssh-sign sign $root_result.path --key $alice --pubkeys-dir $pubkeys
    let bob_sig = ssh-sign sign $root_result.path --key $bob --pubkeys-dir $pubkeys
    let bundle = $"($repo)/multiproofs/ots-timestamps/tree-root.cafe0000"
    mkdir $bundle

    {
        repo: $repo
        proof: (merkle prove README.md --repo $repo)
        root_file: $root_result.path
        alice_sig: $alice_sig
        bob_sig: $bob_sig
        alice: (principal-of $alice)
        bob: (principal-of $bob)
        bundle: $bundle
    }
}

# The property the whole design turns on: a stamp over a SIGNATURE dates that
# endorsement, and it is matched to its signer by hashing the signature file —
# never by a .sig file name, which whoever wrote the file chose. Two signers
# here because one row cannot show that the rows are per-signature.
@test
def "each signature gets its own dated endorsement" [] {
    let fx = make-cosigned-repo $in.tmp_dir

    # Nothing stamped yet: both endorsements are real but undated.
    let bare = merkle verify $fx.proof --repo $fx.repo
    assert equal ($bare.endorsements | get status | uniq) ["absent"]
    assert equal ($bare.endorsements | get signer | sort) ([$fx.alice $fx.bob] | sort)

    # Alice's signature stamped, bob's not.
    let alice_hash = open --raw $fx.alice_sig | hash sha256 | decode hex
    build-bitcoin-ots --hash $alice_hash | save --raw --force $"($fx.bundle)/alice.ots"
    let one = merkle verify $fx.proof --repo $fx.repo
    assert equal ($one.endorsements | where signer == $fx.alice | get status) ["anchored"]
    assert equal ($one.endorsements | where signer == $fx.bob | get status) ["absent"]

    # Bob's too, still pending — the two are independent.
    let bob_hash = open --raw $fx.bob_sig | hash sha256 | decode hex
    build-pending-ots --hash $bob_hash | save --raw --force $"($fx.bundle)/bob.ots"
    let both = merkle verify $fx.proof --repo $fx.repo
    assert equal ($both.endorsements | where signer == $fx.alice | get status) ["anchored"]
    assert equal ($both.endorsements | where signer == $fx.bob | get status) ["pending"]
}

# Hostile artifact: a real signature over this exact root by a key the trust
# list does not hold, with a genuine stamp over it. Everything about it checks
# out cryptographically — it is simply not an endorsement anyone here trusts,
# so it must not appear as a dated one. `ssh-sign verify` returns such a row as
# {valid: false, error: unrecognized_signer} WITH a principal attached, so
# listing rows without filtering on `valid` would show mallory's dated
# endorsement of your root beside the real ones.
@test
def "a dated signature by an unregistered key is not an endorsement" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-cosigned-repo $tmp_dir
    let mallory = $"($tmp_dir)/mallory"
    ^ssh-keygen -t ed25519 -f $mallory -N "" -q
    let mallory_sig = $"($fx.root_file).mallory.sig"
    open --raw $fx.root_file | into binary | ^ssh-keygen -Y sign -q -f $mallory -n file | save --raw --force $mallory_sig
    build-bitcoin-ots --hash (open --raw $mallory_sig | hash sha256 | decode hex)
    | save --raw --force $"($fx.bundle)/mallory.ots"

    let result = merkle verify $fx.proof --repo $fx.repo
    assert equal ($result.endorsements | get signer | sort) ([$fx.alice $fx.bob] | sort)
    assert equal ($result.endorsements | where status != "absent" | length) 0
}

# Hostile artifact: a stamp over bytes that are not any signature here. The
# match is on the signature's own hash, so a stamp of something else beside it
# dates nothing — pinning that discovery cannot be satisfied by proximity.
@test
def "a stamp over unrelated bytes dates no endorsement" [] {
    let fx = make-cosigned-repo $in.tmp_dir
    build-bitcoin-ots --hash ("some other file" | hash sha256 | decode hex)
    | save --raw --force $"($fx.bundle)/unrelated.ots"

    let result = merkle verify $fx.proof --repo $fx.repo
    assert equal ($result.endorsements | get status | uniq) ["absent"]
}

# Hostile artifact: alice's genuine signature over SOMETHING ELSE, planted at a
# name beside the root and stamped. Her key is registered, so `ssh-sign verify`
# identifies her and returns {valid: false, error: invalid_signature} — a row
# carrying a trusted principal. Dating bytes says when they existed, never that
# they endorse anything, so this must add no dated endorsement and must not
# upgrade the honest-but-unstamped row that already carries her name.
@test
def "a stamped signature over other content adds no endorsement" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-cosigned-repo $tmp_dir
    let decoy = $"($tmp_dir)/decoy.txt"
    "not the root statement" | save --force $decoy
    let decoy_sig = ssh-sign sign $decoy --key $"($tmp_dir)/alice" --pubkeys-dir $"($fx.repo)/multiproofs/pubkeys"
    let planted = $"($fx.root_file).planted.sig"
    cp $decoy_sig $planted
    build-bitcoin-ots --hash (open --raw $planted | hash sha256 | decode hex)
    | save --raw --force $"($fx.bundle)/planted.ots"

    let result = merkle verify $fx.proof --repo $fx.repo
    # alice appears once, from her real signature, and it is undated
    assert equal ($result.endorsements | where signer == $fx.alice | get status) ["absent"]
    assert equal ($result.endorsements | where status != "absent" | length) 0
}

@test
def "proof against a different seal root throws loudly" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-test-repo $tmp_dir
    merkle write-root --repo $repo
    let proof = merkle prove README.md --repo $repo

    # A later seal rewrote the root statement: verification must name the
    # seal mismatch, not report a quiet invalid
    root-statement ("other" | hash sha256) 1 ("earlier" | hash sha256) "none" | save --raw --force $"($repo)/multiproofs/tree-root.txt"
    assert error {|| merkle verify $proof --repo $repo }
}

# Two seals over one repo, seal #1 snapshotted before seal #2 overwrites the
# live artifacts: statement + signature copied flat into a bare directory —
# the shape nu-cybergraph freezes under seals/<root12>/: no CSV, no pubkeys,
# no OTS copies. Seal #2 only ADDS a tracked file, so seal #1's README row and
# the bytes on disk it attests stay exactly as sealed — the old proof is
# perfect, and only the seal artifacts around it have moved on.
def make-older-seal [tmp_dir: path]: nothing -> record {
    let repo = make-test-repo $tmp_dir
    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $"($repo)/multiproofs/pubkeys"
    cp $"($key_path).pub" $"($repo)/multiproofs/pubkeys/sshkey.pub"
    merkle write-root --repo $repo
    let old_sig = ssh-sign sign $"($repo)/multiproofs/tree-root.txt" --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"
    let proof = merkle prove README.md --repo $repo
    let old_root = (parse-root-statement $"($repo)/multiproofs/tree-root.txt").root

    let snap = $"($tmp_dir)/snap"
    mkdir $snap
    cp $"($repo)/multiproofs/tree-root.txt" $snap
    cp $old_sig $snap
    let old_csv = $"($tmp_dir)/old-tree-hashes.csv"
    cp $"($repo)/multiproofs/tree-hashes.csv" $old_csv

    "later\n" | save --force $"($repo)/new.txt"
    ^git -C $repo add new.txt
    tree-hashes --repo $repo
    merkle write-root --repo $repo
    let new_sig = ssh-sign sign $"($repo)/multiproofs/tree-root.txt" --key $key_path --pubkeys-dir $"($repo)/multiproofs/pubkeys"
    {repo: $repo snap: $snap proof: $proof old_root: $old_root old_csv: $old_csv new_sig: $new_sig}
}

# The scenario --multiproofs-dir exists for: a consumer freezes each seal's
# statement + signatures at birth and always verifies a proof against its
# BIRTH seal, while the live multiproofs/ belongs to the newest one. Without
# the flag the only way to check such a proof was to rebuild a directory
# around the snapshot.
@test
def "a proof of an older seal verifies against that snapshot of the seal" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-older-seal $tmp_dir

    # Against the live artifacts it is a proof of a DIFFERENT seal — the loud
    # throw, unchanged.
    let live = try { merkle verify $fx.proof --repo $fx.repo; "no throw" } catch {|e| $e.msg }
    assert ($live | str contains "different seal")

    let result = merkle verify $fx.proof --repo $fx.repo --multiproofs-dir $fx.snap
    assert $result.valid
    assert equal $result.root $fx.old_root
    # No CSV in the snapshot: "not here to check" — the portable-bundle shape
    assert equal $result.manifest_root null
    # The snapshot holds no pubkeys, so a valid signature proves the trust
    # default stayed with --repo rather than following the flag
    assert equal ($result.signatures | where valid | length) 1
    assert equal $result.content_verified true

    # A directory with no statement is named by the refusal, not read as an
    # unsealed repo that should run write-root
    let empty = $"($tmp_dir)/empty"
    mkdir $empty
    let missing = try { merkle verify $fx.proof --repo $fx.repo --multiproofs-dir $empty; "no throw" } catch {|e| $e.msg }
    assert ($missing | str contains "--multiproofs-dir")
}

# The manifest cross-check follows the flag: the seal's own CSV beside the
# snapshot statement cross-checks clean, and the LIVE repo's CSV planted there
# is caught as a catalogue from a different seal. Without the first half a
# verify that read no CSV at all would pass; without the second, one still
# reading the repo's CSV would fail every older-seal check.
@test
def "the manifest cross-check follows the multiproofs dir, not the repo" [] {
    let fx = make-older-seal $in.tmp_dir

    cp $fx.old_csv $"($fx.snap)/tree-hashes.csv"
    let matched = merkle verify $fx.proof --repo $fx.repo --multiproofs-dir $fx.snap
    assert $matched.valid
    assert equal $matched.manifest_root $fx.old_root

    cp $"($fx.repo)/multiproofs/tree-hashes.csv" $"($fx.snap)/tree-hashes.csv"
    let desync = merkle verify $fx.proof --repo $fx.repo --multiproofs-dir $fx.snap
    assert not $desync.valid
    assert ($desync.error | str contains "different seals")
}

# Hostile snapshot: the OLD statement with the NEW seal's signature planted
# beside it under its own name. The signature is genuine key material from a
# trusted key, just over other bytes — so if signatures were checked over
# anything but the flagged statement (the live root, say), it would validate.
@test
def "a planted signature over another statement does not endorse the snapshot" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-older-seal $tmp_dir
    let forged = $"($tmp_dir)/forged-snap"
    mkdir $forged
    cp $"($fx.snap)/tree-root.txt" $forged
    cp $fx.new_sig $forged

    let result = merkle verify $fx.proof --repo $fx.repo --multiproofs-dir $forged
    assert not $result.valid
    assert equal ($result.signatures | where valid | length) 0
    assert ($result.error | str contains "no valid signature")
}

# Pins the claim that OTS stamp discovery stays keyed to --repo under
# --multiproofs-dir: the snapshot carries no stamp copies, so the anchor this
# finds can only have come from the live archive. Discovery is by content
# hash, so the stamp dates the OLD statement even though the live
# tree-root.txt has moved on to the next seal.
@test
def "an anchor in the live archive dates an older seal verified via its snapshot" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-older-seal $tmp_dir
    let bundle = $"($fx.repo)/multiproofs/ots-timestamps/tree-root.cafe0000"
    mkdir $bundle
    build-bitcoin-ots --hash (open --raw $"($fx.snap)/tree-root.txt" | hash sha256 | decode hex)
    | save --raw --force $"($bundle)/tree-root.ots"

    let result = merkle verify $fx.proof --repo $fx.repo --multiproofs-dir $fx.snap
    assert $result.valid
    assert equal $result.ots.status "anchored"
}
