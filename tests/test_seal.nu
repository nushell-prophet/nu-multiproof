use std/assert
use std/testing *

use ../nu-multiproof/seal.nu
use ../nu-multiproof/ssh-sign.nu
use ../nu-multiproof/ots.nu
use ../nu-multiproof/_sig.nu sig-files-for
use ../nu-multiproof/pubkey.nu
use ../nu-multiproof/_fs.nu list-files
use _ots-fixtures.nu [build-calendar-response build-bitcoin-ots]

# A repo with one commit and one registered signer — the state every test here
# starts from. Returns the paths the assertions need.
def make-sealable-repo [tmp_dir: path]: nothing -> record {
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q
    ^git -C $repo config user.email "seal-test@example.com"
    ^git -C $repo config user.name "Seal Test"

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    ^git -C $repo config user.signingKey $"($key_path).pub"
    let pubkeys = $"($repo)/multiproofs/pubkeys"
    mkdir $pubkeys
    cp $"($key_path).pub" $"($pubkeys)/sshkey.pub"

    "v1\n" | save --force $"($repo)/file.txt"
    ^git -C $repo add file.txt
    ^git -C $repo commit -q -m "init"

    {repo: $repo key: $key_path pubkeys: $pubkeys ots_dir: $"($repo)/multiproofs/ots-timestamps"}
}

# The principal a key signs under: the fingerprint of its public half, which is
# what every `.sig` file here is named for.
def principal-of [key: path]: nothing -> string {
    open --raw $"($key).pub" | pubkey fingerprint
}

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

# seal happy path with --no-stamp: avoids the OTS calendar network call, but
# still exercises tree-hashes regen + signing-key resolution + sig clearing.
@test
def "seal produces manifest and signed root statement" [] {
    # The fixture leaves a SHA-1 repo, which seal must handle: it hashes file
    # contents itself rather than leaning on git's object hash.
    let fx = make-sealable-repo $in.tmp_dir
    let repo = $fx.repo

    let result = seal --repo $repo --no-stamp

    let manifest = $"($repo)/multiproofs/tree-hashes.csv"
    assert ($manifest | path exists) "manifest not created"
    # The CSV itself is unsigned — the signed root statement covers every row.
    # Not a glob: a pattern built from a temp path silently matches nothing, so
    # `== 0` would pass for the wrong reason (test_lint.nu rule 1).
    assert equal (sig-files-for $manifest) []

    # Merkle root statement derived from the fresh manifest and signed
    let root_file = $"($repo)/multiproofs/tree-root.txt"
    assert ($root_file | path exists) "root statement not created"
    assert equal (open --raw $root_file | into string) $"multiproof-merkle-v1 ($result.merkle_root)\n"
    assert ($result.root_sig | str ends-with $".(principal-of $fx.key).sig")
}

# Second seal must succeed even though the previous seal left a sig next to
# the root statement — seal clears stale sigs itself before re-signing.
@test
def "seal re-runs without sig conflict" [] {
    let repo = (make-sealable-repo $in.tmp_dir).repo

    seal --repo $repo --no-stamp
    # Second invocation must not error: stale sig from first run gets cleared
    seal --repo $repo --no-stamp

    # Stale root-statement sig from the first run cleared, exactly one live sig
    let root_sigs = sig-files-for $"($repo)/multiproofs/tree-root.txt"
    assert equal ($root_sigs | length) 1
}

# `ssh-sign sign multiproofs/tree-hashes.csv` is a public command, and seal
# used to sweep whatever it produced on the next run, silently — reading
# "leftover from the era when seal signed the CSV" into a file that only says
# who signed which bytes. The manifest now follows the same rule as the root
# statement: a signature over bytes regen did not change still verifies, so it
# stays; once the bytes change it is stale and goes.
@test
def "a deliberate manifest signature survives an unchanged reseal" [] {
    let fx = make-sealable-repo $in.tmp_dir

    let manifest = $"($fx.repo)/multiproofs/tree-hashes.csv"
    seal --repo $fx.repo --no-stamp
    # A signature the user made on purpose, not a planted stub: what must
    # survive is a sig that still verifies.
    ssh-sign sign $manifest --key $fx.key --pubkeys-dir $fx.pubkeys

    seal --repo $fx.repo --no-stamp
    let kept = sig-files-for $manifest | each {|f| $f | path basename }
    assert equal $kept [$"tree-hashes.csv.(principal-of $fx.key).sig"] "seal deleted a signature over bytes it did not change"
    assert equal (ssh-sign verify $manifest --pubkeys-dir $fx.pubkeys | get valid) [true]

    # Changed content: the manifest's bytes change with it, and a sig over the
    # old bytes is stale — that is when clearing is right.
    "v2\n" | save --force $"($fx.repo)/file.txt"
    seal --repo $fx.repo --no-stamp
    assert equal (sig-files-for $manifest) []
}

# The same rule on the root statement, and on a signature this seal did not
# make. Bytes are the only thing seal can check: unchanged bytes mean the sig
# still verifies, whoever made it; changed bytes make it stale wherever it came
# from. Written with a co-signer rather than --no-sign, which used to be the
# only way to see a surviving sig — the flag is gone, the rule is not.
@test
def "seal keeps a co-signer sig over unchanged bytes and clears it once they change" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir

    let bob_key = $"($tmp_dir)/bob"
    ^ssh-keygen -t ed25519 -f $bob_key -N "" -q
    cp $"($bob_key).pub" $"($fx.pubkeys)/bob.pub"

    seal --repo $fx.repo --no-stamp
    let root_file = $"($fx.repo)/multiproofs/tree-root.txt"
    ssh-sign sign $root_file --key $bob_key --pubkeys-dir $fx.pubkeys

    # Unchanged content: regen writes identical bytes, so bob's signature over
    # them still verifies and must survive the reseal.
    seal --repo $fx.repo --no-stamp
    let kept = sig-files-for $root_file | each {|f| $f | path basename } | sort
    assert equal $kept (
        [$"tree-root.txt.(principal-of $bob_key).sig" $"tree-root.txt.(principal-of $fx.key).sig"] | sort
    ) "seal deleted a co-signer sig over bytes it did not change"
    assert equal (ssh-sign verify $root_file --pubkeys-dir $fx.pubkeys | get valid) [true true]

    # Changed content: the root statement's bytes change, so bob's sig is stale
    # and goes; the sealer signs the new bytes.
    "v2\n" | save --force $"($fx.repo)/file.txt"
    seal --repo $fx.repo --no-stamp
    assert equal (sig-files-for $root_file | each {|f| $f | path basename }) [$"tree-root.txt.(principal-of $fx.key).sig"]
}

# Step 4, which every other test here skipped with --no-stamp. What it has to
# get right is not the OTS bytes — test_ots.nu owns those — but that the bundle
# lands in the repo seal was pointed at, holding the artifact it just signed
# and the signature it just made. `--repo /other` writing its bundle into the
# CWD's repo was a real bug, found by reading rather than by this suite.
@test
def "seal stamps the root statement into the target repo and bundles its signature" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response

    let result = seal --repo $fx.repo --response-file $response

    let root_file = $"($fx.repo)/multiproofs/tree-root.txt"
    let bundle = $result.root_ots | path dirname
    assert equal ($bundle | path dirname) $fx.ots_dir "bundle landed outside the target repo"
    assert equal ($result.root_ots | path basename) "tree-root.ots"

    # The proof commits to the bytes that were signed, not to some other file.
    assert equal (ots info $result.root_ots | get hash) (open --raw $root_file | hash sha256)
    assert equal (open --raw $"($bundle)/tree-root.txt") (open --raw $root_file)

    # A bundle answers "who endorsed this content" on its own, so the signature
    # seal made in step 3 has to be snapshotted beside the frozen copy.
    assert equal (
        list-files $bundle --suffix ".sig" | each {|f| $f | path basename }
    ) [$"tree-root.txt.(principal-of $fx.key).sig"]
}

# Step 1, the opportunistic upgrade loop, also skipped by every other test.
# Two properties, and the first is visible only on stdout — which is why seal
# runs in a subprocess here. Asserted on the return value alone, a seal that
# never entered the loop, and one that swallowed every failure, both passed:
# measured, by deleting the loop and by replacing its error branch with null.
#
#   reported — "not yet confirmed" is the normal case for hours or days and is
#     rightly silent, but a proof that no longer parses is a corrupt artifact
#     or a misconfig, and seal is the only thing that will ever look at it
#   it cannot cost the seal — this run's manifest, root and signature are
#     produced anyway, and anything already anchored is left byte-identical,
#     since `ots upgrade` returns early rather than refetching
@test
def "seal reports an archived proof it cannot read, and seals anyway" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let bundle = $"($fx.ots_dir)/tree-root.DEADBEEF"
    mkdir $bundle

    let anchored = $"($bundle)/tree-root.ots"
    build-bitcoin-ots | save --raw --force $anchored
    let anchored_before = open --raw $anchored | into binary
    "not an OTS file at all" | save --raw --force $"($bundle)/broken.ots"

    # Same idiom as test_temp-helpers.nu's subprocess test: the suite runs from
    # the repo root, so assert that rather than fail as "module not found".
    let seal_nu = $env.PWD | path join "nu-multiproof" "seal.nu"
    assert ($seal_nu | path exists) $"expected the suite to run from the repo root, got ($env.PWD)"
    let run = do {
        ^nu --no-config-file -c $"use ($seal_nu); seal --repo ($fx.repo) --no-stamp | ignore"
    } | complete
    assert equal $run.exit_code 0 $"seal failed: ($run.stderr)"
    assert (
        $run.stdout | str contains $"upgrade failed for ($bundle)/broken.ots"
    ) $"an unreadable archived proof went unreported:(char newline)($run.stdout)"

    assert equal (open --raw $anchored | into binary) $anchored_before "seal rewrote an already-anchored proof"
    assert equal (ots info $anchored | get attestation.height) 123456
    let root_file = $"($fx.repo)/multiproofs/tree-root.txt"
    assert ($root_file | path exists) "seal stopped before writing the root statement"
    assert (sig-files-for $root_file | is-not-empty) "seal stopped before signing"
}
