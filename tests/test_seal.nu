use std/assert
use std/testing *

use ../nu-multiproof/seal.nu
use ../nu-multiproof/ssh-sign.nu
use ../nu-multiproof/ots.nu
use ../nu-multiproof/_sig.nu sig-files-for
use ../nu-multiproof/pubkey.nu
use ../nu-multiproof/_fs.nu [list-files list-dirs]
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

@test
def "an unregistered signing key refuses the seal before it rewrites anything" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let manifest = $"($fx.repo)/multiproofs/tree-hashes.csv"
    let root_statement = $"($fx.repo)/multiproofs/tree-root.txt"
    seal --repo $fx.repo --no-stamp

    # A registered-signer seal exists; now the operator switches to a key
    # nobody registered and edits a file, so a rerun would rewrite the
    # manifest and the root statement and clear the sig over them.
    let rogue = $"($in.tmp_dir)/rogue"
    ^ssh-keygen -t ed25519 -f $rogue -N "" -q
    ^git -C $fx.repo config user.signingKey $"($rogue).pub"
    "v2\n" | save --force $"($fx.repo)/file.txt"

    let pre_manifest = open --raw $manifest | hash sha256
    let pre_root = open --raw $root_statement | hash sha256
    let pre_sigs = sig-files-for $root_statement

    let err = try { seal --repo $fx.repo --no-stamp; null } catch {|e| $e.msg }
    assert ($err != null) "seal accepted an unregistered signing key"
    assert ($err | str contains "is not registered")
    assert equal (open --raw $manifest | hash sha256) $pre_manifest "the refusal came after the manifest was rewritten"
    assert equal (open --raw $root_statement | hash sha256) $pre_root "the refusal came after the root statement was rewritten"
    assert equal (sig-files-for $root_statement) $pre_sigs "the refusal came after signatures were cleared"
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
# get right is not the OTS bytes — test_ots.nu owns those — but that ONE bundle
# lands in the repo seal was pointed at, holding all four parts of the claim:
# the artifact it signed, that artifact's anchor, the signature it made, and
# that signature's anchor. `--repo /other` writing its bundle into the CWD's
# repo was a real bug, found by reading rather than by this suite.
#
# Why the directory count is asserted: the signature's proof used to derive its
# own bundle name, so one seal moment produced two directories — the content
# bundle holding an endorsement it could not date, and a second bundle holding a
# date for content it did not carry. Both proofs verify either way, so only the
# listing catches a regression here.
@test
def "seal puts the root statement, its signature and both anchors in one bundle" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response

    let result = seal --repo $fx.repo --response-file $response

    let root_file = $"($fx.repo)/multiproofs/tree-root.txt"
    let bundle = $result.root_ots | path dirname
    assert equal ($bundle | path dirname) $fx.ots_dir "bundle landed outside the target repo"
    assert equal ($result.root_ots | path basename) "tree-root.ots"
    assert equal (list-dirs $fx.ots_dir) [$bundle] "the seal spread itself over more than one bundle"

    # The proof commits to the bytes that were signed, not to some other file.
    assert equal (ots info $result.root_ots | get hash) (open --raw $root_file | hash sha256)
    assert equal (open --raw $"($bundle)/tree-root.txt") (open --raw $root_file)

    # A bundle answers "who endorsed this content" on its own, so the signature
    # seal made in step 3 has to be snapshotted beside the frozen copy.
    let sig_name = $"tree-root.txt.(principal-of $fx.key).sig"
    assert equal (
        list-files $bundle --suffix ".sig" | each {|f| $f | path basename }
    ) [$sig_name]

    # ...and it answers "by when did that endorsement exist" out of the same
    # directory, which is the half a bundle could not make before.
    assert equal ($result.sig_ots | each {|f| $f | path basename }) [
        $"tree-root.txt.(principal-of $fx.key).ots"
    ]
    assert equal ($result.sig_ots | each {|f| $f | path dirname }) [$bundle] "the endorsement anchor landed outside the bundle it endorses"
    assert equal (ots info ($result.sig_ots | first) | get hash) (
        open --raw $"($bundle)/($sig_name)" | hash sha256
    ) "the endorsement anchor does not commit to the signature beside it"
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

# --- seal status ---

# Nothing sealed is an empty report, not an error and not a row of nulls. A
# bundle is discovered from the proofs it holds, so a repo with pubkeys and no
# proofs has no bundles — and `seal --no-stamp`, which writes a manifest, a root
# and a signature but no proof, is exactly that state.
@test
def "seal status reports nothing for a repo with no proofs" [] {
    let fx = make-sealable-repo $in.tmp_dir
    seal --repo $fx.repo --no-stamp | ignore

    assert equal (seal status --repo $fx.repo) [] "a repo with no OTS proof reported a bundle"
}

# The report after one seal: the whole point of the command is that this row
# answers "is it sealed, and is it dated yet" without reading directory names or
# running `ots info` by hand.
@test
def "seal status reports the seal in force with both anchors" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response
    let result = seal --repo $fx.repo --response-file $response

    let rows = seal status --repo $fx.repo
    assert equal ($rows | length) 1 "one seal produced more than one bundle"
    let row = $rows | first
    assert equal $row.bundle ($result.root_ots | path dirname | path relative-to $fx.repo)
    assert equal $row.file "tree-root.txt"
    assert equal $row.current true "the bundle this seal just wrote is not reported as the one in force"
    assert equal $row.content "pending" "a fresh calendar stamp is pending, not anchored"
    assert equal $row.signers 1
    assert equal $row.endorsed "pending" "the signature's own anchor went unreported"
}

# `current` is the column that makes the folder navigable: ten archival bundles
# and one live seal look alike on disk, and only a byte compare against the live
# artifact tells them apart. Asserted by re-sealing changed content, because a
# `current` hardcoded to true — or read off the newest directory — passes any
# single-bundle test.
@test
def "seal status marks only the bundle whose snapshot is the live artifact" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response

    seal --repo $fx.repo --response-file $response | ignore
    "v2\n" | save --force $"($fx.repo)/file.txt"
    ^git -C $fx.repo add file.txt
    ^git -C $fx.repo commit -q -m "v2"
    let second = seal --repo $fx.repo --response-file $response

    let rows = seal status --repo $fx.repo
    assert equal ($rows | length) 2 "the second seal did not produce its own bundle"
    assert equal ($rows | where current | get bundle) [
        ($second.root_ots | path dirname | path relative-to $fx.repo)
    ] "current does not single out the seal in force"
}

# A bundle carrying a proof and no snapshot: the shape the oldest bundles in this
# repo have, and one `stamp` never writes, so it is hand-built here rather than
# produced. It must report rather than throw — a status command that dies on the
# archive cannot describe the folder it is for. `file: null` says "no snapshot"
# instead of naming a file that is not there.
@test
def "seal status reports a bundle with no frozen copy instead of failing" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let bundle = $"($fx.ots_dir)/tree-root.DEADBEEF"
    mkdir $bundle
    build-bitcoin-ots | save --raw --force $"($bundle)/tree-root.ots"

    let rows = seal status --repo $fx.repo
    assert equal ($rows | length) 1
    let row = $rows | first
    assert equal $row.file null "a bundle with no snapshot named one anyway"
    assert equal $row.current null "current claimed to know about content that is not in the bundle"
    assert equal $row.content "absent" "an anchor was reported over content the bundle does not carry"
    assert equal $row.signers 0
}

# Bundles outside ots-timestamps/ are still part of the folder. This repo keeps
# two under multiproofs/origin-proofs/, and `merkle verify` never looks there by
# design — it consults the operational set. A report that inherited that one-level
# scan would silently omit directories the person reading it can see, so status
# walks the whole tree.
@test
def "seal status reports a bundle in an archival subtree, not just ots-timestamps" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let archival = $"($fx.repo)/multiproofs/origin-proofs/tree-root.DEADBEEF"
    mkdir $archival
    build-bitcoin-ots | save --raw --force $"($archival)/tree-root.ots"

    assert equal (seal status --repo $fx.repo | get bundle) [
        "multiproofs/origin-proofs/tree-root.DEADBEEF"
    ] "a bundle outside ots-timestamps/ went unreported"
}

# The height is the point of reporting an anchor at all: "anchored" alone says a
# block confirmed it, not which. A block's wall-clock time is in its header,
# which no .ots carries, so this is the only time available without the network —
# and `status` stays offline. Both anchors in the bundle are hand-built so each
# commits to real bytes beside it; `build-bitcoin-ots` fixes the height at 123456.
@test
def "seal status reports the block height an anchor binds to" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let bundle = $"($fx.ots_dir)/tree-root.CAFEBABE"
    mkdir $bundle

    let snapshot = $"($bundle)/tree-root.txt"
    let sig = $"($bundle)/tree-root.txt.alice.sig"
    "multiproof-merkle-v1 abc\n" | save --force $snapshot
    "alice-sig" | save --force $sig
    build-bitcoin-ots --hash (open --raw $snapshot | hash sha256 | decode hex)
        | save --raw --force $"($bundle)/tree-root.ots"
    build-bitcoin-ots --hash (open --raw $sig | hash sha256 | decode hex)
        | save --raw --force $"($bundle)/tree-root.txt.alice.ots"

    let row = seal status --repo $fx.repo | first
    assert equal $row.content "anchored 123456" "the content anchor reported no block height"
    assert equal $row.endorsed "anchored 123456" "the endorsement anchor reported no block height"

    # A pending proof has no height, and must not grow a bogus one. The response
    # file is left inside the bundle on purpose: it is a file no proof commits
    # to, and reading the snapshot positionally — the first entry that is neither
    # a proof nor a signature — made *it* the reported snapshot, so the bundle's
    # content came back `absent` while the anchored frozen copy sat beside it.
    build-calendar-response | save --raw --force $"($bundle)/pending.bin"
    rm $"($bundle)/tree-root.ots"
    ots stamp $snapshot --into $bundle --response-file $"($bundle)/pending.bin" | ignore

    let row = seal status --repo $fx.repo | first
    assert equal $row.file "tree-root.txt" "a file no proof commits to was reported as the bundle's snapshot"
    assert equal $row.content "pending" "a pending stamp was given a block height"
}

# A report that describes the archive must not die on it. `open --raw` runs over
# every non-proof, non-signature entry in a bundle, and nushell types a symlink
# as `symlink` whatever it points at — so a link to a directory, and a dangling
# one, both reached `open` and threw "Eval block failed with pipeline input",
# naming no file. Bytes behind a link are not the ones the name describes, which
# is why a symlink is dropped rather than followed.
@test
def "seal status reports a bundle holding symlinks instead of failing" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let bundle = $"($fx.ots_dir)/tree-root.CAFED00D"
    mkdir $bundle
    let snapshot = $"($bundle)/tree-root.txt"
    "multiproof-merkle-v1 abc\n" | save --force $snapshot
    build-bitcoin-ots --hash (open --raw $snapshot | hash sha256 | decode hex)
        | save --raw --force $"($bundle)/tree-root.ots"
    ^ln -s "/nowhere/at/all" $"($bundle)/dangling"
    ^ln -s $fx.pubkeys $"($bundle)/points-at-a-dir"

    let rows = seal status --repo $fx.repo
    assert equal ($rows | length) 1
    let row = $rows | first
    assert equal $row.file "tree-root.txt" "a symlink displaced the real snapshot"
    assert equal $row.content "anchored 123456"
}

# Two stamped non-signature files in one bundle — what --into permits. `get 0?`
# picked by `ls` order, so the row could name a file the bundle is not named
# after and drop the other anchor with no sign. The bundle's own
# `<stem>.<8 hex>` name is the tie-break: that hash is its reason to exist.
@test
def "seal status names the file the bundle is keyed by when it holds two" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response
    let result = seal --repo $fx.repo --response-file $response
    let bundle = $result.root_ots | path dirname

    # `aaa.csv` sorts before `tree-root.txt`, so ls order picks the wrong one.
    let other = $"($fx.repo)/multiproofs/aaa.csv"
    "unrelated stamped content\n" | save --force $other
    ots stamp $other --into $bundle --response-file $response | ignore

    let row = seal status --repo $fx.repo | first
    assert equal $row.file "tree-root.txt" $"the row named ($row.file), not the file the bundle is keyed by"
    assert equal $row.current true "the bundle in force stopped being recognized once it held a second stamp"
}

# `current: false` says "a later seal superseded this". A bundle over a file with
# no live counterpart under multiproofs/ is not superseded — there is nothing to
# compare — and `null` is the value this command already uses for that.
@test
def "seal status reports current as null when no live artifact shares the name" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let bundle = $"($fx.ots_dir)/README.D15EA5E0"
    mkdir $bundle
    let snapshot = $"($bundle)/README.md"
    "a file that never lived under multiproofs/\n" | save --force $snapshot
    build-bitcoin-ots --hash (open --raw $snapshot | hash sha256 | decode hex)
        | save --raw --force $"($bundle)/README.ots"

    let row = seal status --repo $fx.repo | first
    assert equal $row.file "README.md"
    assert equal $row.current null "a bundle with no live counterpart was reported as superseded"
}

# Among several anchored proofs of one file the LOWEST block wins: the claim is
# "these bytes existed no later than T", so the earliest anchor is the strongest
# and every later one follows from it. This was `ls` order, which no assertion
# could see while only the word "anchored" came out of `pick-stamp` — and became a
# wrong number the moment the height was printed.
#
# The heights are arranged so filename order and block order DISAGREE, otherwise
# the test passes either way — measured: `list-files` returns
# `tree-root.20260101-…ots` before `tree-root.ots`, so the archival name is what
# `first` would pick, and it is the one given the LATER block here. That is a real
# state, not a contrived one: a proof still pending when a re-stamp archived it is
# upgraded by a later `seal` (step 1 walks every .ots), so it anchors in a higher
# block than the `<stem>.ots` that replaced it.
@test
def "seal status reports the earliest anchor when a bundle holds several" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let bundle = $"($fx.ots_dir)/tree-root.B10CB10C"
    mkdir $bundle
    let snapshot = $"($bundle)/tree-root.txt"
    "multiproof-merkle-v1 abc\n" | save --force $snapshot
    let file_hash = open --raw $snapshot | hash sha256 | decode hex

    build-bitcoin-ots --hash $file_hash --height 100 | save --raw --force $"($bundle)/tree-root.ots"
    build-bitcoin-ots --hash $file_hash --height 900000
        | save --raw --force $"($bundle)/tree-root.20260101-000000-deadbeef.ots"

    assert equal (seal status --repo $fx.repo | first | get content) "anchored 100" "the anchor was chosen by filename order, not by block"
}

# --- re-sealing with stamping, the case the fixture key hides ---

# A repo whose signing key is ECDSA, so signing the same bytes twice yields
# DIFFERENT signature bytes (measured: ed25519 is deterministic, ECDSA and
# ecdsa-sk are not — and this repo's own key is ecdsa-sk, per README). Every other
# test here uses the ed25519 fixture, which is why the state below stayed green.
def make-sealable-repo-ecdsa [tmp_dir: path]: nothing -> record {
    let fx = make-sealable-repo $tmp_dir
    let key_path = $"($tmp_dir)/ecdsakey"
    ^ssh-keygen -t ecdsa -f $key_path -N "" -q
    ^git -C $fx.repo config user.signingKey $"($key_path).pub"
    cp $"($key_path).pub" $"($fx.pubkeys)/ecdsakey.pub"
    $fx | update key $key_path
}

# Sealing twice over unchanged content, with stamping. Step 3 re-signs and a
# randomized key makes new signature bytes for the same `.sig` name, so step 4
# stamps content that changed under a name that did not — which is what a
# re-stamp IS. Guarding the `.ots` name by hash inequality refused exactly this,
# and refused it AFTER step 4 had already refreshed the frozen sig snapshot: the
# bundle kept an endorsement anchor over bytes that existed nowhere, and `seal
# status` read `endorsed: absent` for a bundle plainly holding one.
@test
def "a second seal over unchanged content re-anchors the new signature" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo-ecdsa $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response

    let first = seal --repo $fx.repo --response-file $response
    let first_sig = open --raw ($first.root_sig) | hash sha256
    let second = seal --repo $fx.repo --response-file $response
    let second_sig = open --raw ($second.root_sig) | hash sha256
    assert ($first_sig != $second_sig) "the key turned out deterministic — this test proves nothing"

    # One bundle still, and its endorsement anchor covers the signature actually
    # sitting in it. This is the assertion the regression broke.
    let bundle = $second.root_ots | path dirname
    assert equal (list-dirs $fx.ots_dir) [$bundle] "the reseal spread itself over a second bundle"
    let sig_name = $"tree-root.txt.(principal-of $fx.key).sig"
    assert equal (open --raw $"($bundle)/($sig_name)" | hash sha256) $second_sig "the bundle kept a stale signature snapshot"
    assert equal (ots info ($second.sig_ots | first) | get hash) $second_sig "the endorsement anchor dates bytes the bundle does not hold"

    let row = seal status --repo $fx.repo | first
    assert equal $row.endorsed "pending" "status reported no endorsement for a bundle that holds one"
    assert equal $row.current true

    # The superseded proofs are kept, not overwritten: two archived .ots beside
    # the two live ones, each an independent attestation.
    assert equal (list-files $bundle --suffix ".ots" | length) 4 "a superseded proof was lost to the reseal"
}

# Two signatures in one bundle. `endorsed` is one entry per signature in sorted
# signature-file order, and with a co-signer that order is the only way to read
# the column — so it is pinned rather than left to chance.
@test
def "seal status reports one endorsement entry per signature" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response

    let bob_key = $"($tmp_dir)/bob"
    ^ssh-keygen -t ed25519 -f $bob_key -N "" -q
    cp $"($bob_key).pub" $"($fx.pubkeys)/bob.pub"

    seal --repo $fx.repo --no-stamp | ignore
    ssh-sign sign $"($fx.repo)/multiproofs/tree-root.txt" --key $bob_key --pubkeys-dir $fx.pubkeys
    seal --repo $fx.repo --response-file $response | ignore

    let row = seal status --repo $fx.repo | first
    assert equal $row.signers 2 "the co-signer's signature was not carried into the bundle"
    assert equal $row.endorsed "pending, pending" "one of the two endorsements went undated"
}

# The docstring and README claim a bundle behind a symlink is not listed. That is
# `list-files --recursive` descending real directories only, and a claimed
# property needs its own test.
@test
def "seal status does not list a bundle behind a symlinked directory" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let real = $"($in.tmp_dir)/elsewhere/tree-root.FEEDFACE"
    mkdir $real
    let snapshot = $"($real)/tree-root.txt"
    "multiproof-merkle-v1 abc\n" | save --force $snapshot
    build-bitcoin-ots --hash (open --raw $snapshot | hash sha256 | decode hex)
        | save --raw --force $"($real)/tree-root.ots"
    mkdir $fx.ots_dir
    ^ln -s $real $"($fx.ots_dir)/tree-root.FEEDFACE"

    assert equal (seal status --repo $fx.repo) [] "a bundle behind a symlink was listed"
}

# A bundle whose only stamped content is a signature — the layout `seal` wrote
# before the two anchors shared a directory, so it is what a repo sealed on an
# older version still holds. It reads as an endorsement with a date and no
# content snapshot, and `signers` is what separates it from an empty bundle.
@test
def "seal status reports a signature-only bundle as an undated-content endorsement" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let bundle = $"($fx.ots_dir)/tree-root.txt.abcdef.1234ABCD"
    mkdir $bundle
    let sig = $"($bundle)/tree-root.txt.abcdef.sig"
    "a signature, stamped on its own\n" | save --force $sig
    build-bitcoin-ots --hash (open --raw $sig | hash sha256 | decode hex)
        | save --raw --force $"($bundle)/tree-root.txt.abcdef.ots"

    let row = seal status --repo $fx.repo | first
    assert equal $row.file null "a signature was reported as the bundle's content snapshot"
    assert equal $row.current null
    assert equal $row.content "absent" "content was claimed for a bundle carrying none"
    assert equal $row.signers 1
    assert equal $row.endorsed "anchored 123456" "the endorsement this bundle exists for went unreported"
}

# A parked rejected calendar answer is the one `.ots` this repo writes that is
# deliberately NOT a proof (README, "rejected"), and it lives directly under
# ots-timestamps/ rather than in a bundle. Parsing it only to print "skipping
# unparsable OTS file" is a note about an expected file, on every run of a command
# whose whole job is to be read. Asserted in a subprocess because the note goes to
# stdout, not into the returned table — the same idiom as the upgrade-loop test.
@test
def "seal status says nothing about a parked rejected calendar answer" [] {
    let fx = make-sealable-repo $in.tmp_dir
    mkdir $fx.ots_dir
    "an assembled proof the parser refused" | save --raw --force $"($fx.ots_dir)/tree-root.DEADBEEF.rejected-20260101-000000-abcdef12.ots"

    let seal_nu = $env.PWD | path join "nu-multiproof" "seal.nu"
    assert ($seal_nu | path exists) $"expected the suite to run from the repo root, got ($env.PWD)"
    let run = do {
        ^nu --no-config-file -c $"use ($seal_nu); seal status --repo ($fx.repo) | to nuon"
    } | complete
    assert equal $run.exit_code 0 $"seal status failed: ($run.stderr)"
    assert not ($run.stdout | str contains "unparsable") $"a rejected answer was reported as a broken proof:(char newline)($run.stdout)"
    assert equal ($run.stdout | str trim) "[]" $"a non-proof produced a row: ($run.stdout)"
}
