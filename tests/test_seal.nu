use std/assert
use std/testing *

# A seal that stamps also mints a beacon, and both reach the network. The
# calendar half is stood down by --response-file; this is the other half, and it
# is the same kind of seam: without it the path from a minted token to the signed
# bytes could only run against live explorers, so it would not run here at all.
# The value is the Bitcoin genesis block, so nothing about it can go stale.
const TEST_BEACON = "bitcoin:0:000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

use ../nu-multiproof/seal.nu
use ../nu-multiproof/ssh-sign.nu
use ../nu-multiproof/ots.nu
use ../nu-multiproof/_sig.nu sig-files-for
use ../nu-multiproof/pubkey.nu
use ../nu-multiproof/_fs.nu [list-files list-dirs]
use _ots-fixtures.nu [build-calendar-response build-bitcoin-ots]
use ../nu-multiproof/_commit-proposal.nu seal-commit-line
use ../nu-multiproof/_layout.nu MULTIPROOFS_DIR
use _fixtures.nu [ setup cleanup ]

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

# seal happy path with --no-stamp: avoids the OTS calendar network call, but
# still exercises tree-hashes regen + signing-key resolution + sig clearing.
# The beacon is minted before anything is rewritten, so an offline seal states
# no bound rather than claiming one — and a seal handed a token puts exactly
# that token under the signature.
@test
def "an offline seal states no lower bound, and a given beacon lands under the signature" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let statement = $"($fx.repo)/multiproofs/tree-root.txt"

    let offline = seal --repo $fx.repo --no-stamp
    assert equal $offline.beacon "none"
    assert ((open --raw $statement | into string) | str ends-with " none\n")

    "v2\n" | save --force $"($fx.repo)/file.txt"
    ^git -C $fx.repo add file.txt
    let bounded = seal --repo $fx.repo --no-stamp --beacon $TEST_BEACON
    assert equal $bounded.beacon $TEST_BEACON
    assert ((open --raw $statement | into string) | str ends-with $" ($TEST_BEACON)\n")
    # The signature is over the bytes the beacon is part of — that is the whole
    # point of putting it in the statement rather than beside it.
    assert (ssh-sign verify $statement --pubkeys-dir $fx.pubkeys | any { $in.valid })
}

@test
def "seal refuses a malformed beacon before touching the repo" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let statement = $"($fx.repo)/multiproofs/tree-root.txt"
    assert error {|| seal --repo $fx.repo --no-stamp --beacon "bitcoin:1:zz" }
    assert not ($statement | path exists) "a refused beacon still wrote a statement"
}

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
    assert equal (open --raw $root_file | into string) $"multiproof-merkle-v4 ($result.merkle_root) 0 genesis none\n"
    assert ($result.root_sig | str ends-with $".(principal-of $fx.key).sig")
}

# `commandline edit` only reaches a prompt from the REPL. Outside one it still
# writes the engine's repl buffer — it is harmless, not a no-op — and only the
# REPL reads that back, so the flag is inert in a script without being an error.
# "Inert" is a claim about a command that runs, so it is pinned here rather than
# assumed. What the proposal SAYS is tested against a known result in
# test_commit-proposal.nu; this pins only that asking for it changes nothing
# else about the seal.
@test
def "asking for a commit proposal leaves the seal result untouched" [] {
    let repo = (make-sealable-repo $in.tmp_dir).repo

    let plain = seal --repo $repo --no-stamp
    let proposed = seal --repo $repo --no-stamp --propose-commit

    assert equal $proposed $plain
}

# Never write an artifact you have not parsed back. The proposal is Nushell
# source handed to a prompt ready to run, so the only honest check is to run it
# and read what git ended up with — a string assertion proves the builder agrees
# with itself, never that the block parses.
@test
def "the proposed block runs and produces the commit it describes" [] {
    let fx = make-sealable-repo $in.tmp_dir
    let result = seal --repo $fx.repo --no-stamp
    let signer = principal-of $fx.key

    # `complete` so git's own chatter does not leak into the test report — and
    # so a failure reports the block's stderr, which a bare throw would drop.
    let run = do { ^nu --commands (seal-commit-line $result $fx.repo $signer) } | complete
    assert equal $run.exit_code 0 $"the proposed block did not run: ($run.stderr)"

    let message = ^git -C $fx.repo log -1 --format=%B
    assert str contains $message $"seal: multiproofs/ describes the tree at merkle root ($result.merkle_root | str substring 0..<8)"
    assert str contains $message $"Merkle root: ($result.merkle_root)"
    assert str contains $message $"Signed by: ($signer)"
    # A blank line between subject and body, or `git log --oneline` prints the
    # whole record as the subject.
    assert equal ($message | lines | get 1) ""

    # The seal's own artifacts are what landed, and nothing outside multiproofs/.
    let committed = ^git -C $fx.repo show --name-only --format= HEAD | lines | where $it != ""
    assert ($committed | all {|f| $f | str starts-with $"($MULTIPROOFS_DIR)/"})
    assert ($"($MULTIPROOFS_DIR)/tree-root.txt" in $committed)
    assert ($"($MULTIPROOFS_DIR)/tree-hashes.csv" in $committed)
}

# The escaping only matters where it is USED. `quote-arg` has its own tests, but
# nothing pinned that `seal-commit-line` actually calls it: both calls could be
# replaced with raw interpolation and the whole suite stayed green. Round-tripping
# the builder proves self-consistency, never that a hostile path is handled.
@test
def "a repo root holding a quote and a backslash still commits" [] {
    let hostile = $in.tmp_dir | path join 'we"ird\dir'
    let fx = make-sealable-repo $hostile
    let result = seal --repo $fx.repo --no-stamp

    let run = do {
        ^nu --commands (seal-commit-line $result $fx.repo (principal-of $fx.key))
    } | complete
    assert equal $run.exit_code 0 $"the proposed block did not run: ($run.stderr)"

    # The commit landed, so the path survived as ONE argument to `git -C`.
    let committed = ^git -C $fx.repo show --name-only --format= HEAD | lines | where $it != ""
    assert ($"($MULTIPROOFS_DIR)/tree-root.txt" in $committed)
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

# `ssh-sign sign multiproofs/tree-hashes.csv` is a public command, and the
# manifest follows the same rule as the root statement: a signature over bytes
# regen did not change still verifies, so it stays; once the bytes change it is
# stale and goes.
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
# from.
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
# repo is how that goes wrong.
#
# Why the directory count is asserted: both proofs verify whether they sit in
# one bundle or two, so only the listing catches a split — one bundle holding an
# endorsement it cannot date, another holding a date for content it does not carry.
@test
def "seal puts the root statement, its signature and both anchors in one bundle" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response

    let result = seal --repo $fx.repo --beacon $TEST_BEACON --response-file $response

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

# --no-content-anchor: the seal moment anchors the endorsements and nothing else.
# Asserted over the whole bundle rather than over `root_ots` alone, because the
# directory is normally minted BY the root's stamp: skipping that stamp could not
# be a guard around one line — the bundle name, its frozen copy and the `--into`
# target all had to come from somewhere else, and only the files on disk show
# whether they did.
@test
def "seal --no-content-anchor dates every signature and leaves the content undated" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response

    let result = seal --repo $fx.repo --no-content-anchor --beacon $TEST_BEACON --response-file $response

    assert equal ($result | get --optional root_ots) null "the root statement was stamped anyway"
    assert equal (list-dirs $fx.ots_dir) [$result.bundle] "the seal spread itself over more than one bundle"

    # Same name a stamped seal would have written: the bundle is keyed by the
    # root statement's own hash whether or not that hash was posted anywhere, so
    # a retry after a rejected calendar answer lands in this same directory.
    let root_file = $"($fx.repo)/multiproofs/tree-root.txt"
    let root_prefix = open --raw $root_file | hash sha256 | str uppercase | str substring 0..<8
    assert equal (
        $result.bundle | path basename
    ) $"tree-root.($root_prefix)" "the bundle is not keyed by the root statement's own hash"

    # The frozen copy is what the endorsement is over and the only thing
    # nu-cybergraph matches a bundle by, so it has to survive the missing stamp.
    assert equal (open --raw $"($result.bundle)/tree-root.txt") (open --raw $root_file)

    let sig_name = $"tree-root.txt.(principal-of $fx.key).sig"
    let sig_ots_name = $"tree-root.txt.(principal-of $fx.key).ots"
    assert equal (
        list-files $result.bundle --suffix ".ots" | each {|f| $f | path basename }
    ) [$sig_ots_name] "the bundle holds a proof that is not an endorsement anchor"
    assert equal ($result.sig_ots | each {|f| $f | path basename }) [$sig_ots_name]
    assert equal (ots info ($result.sig_ots | first) | get hash) (
        open --raw $"($result.bundle)/($sig_name)" | hash sha256
    ) "the endorsement anchor does not commit to the signature beside it"
}

# The row for the bundle above. It is the shape SPEC already describes for a
# signature-only bundle — `file: null`, `content: absent`, a dated `endorsed` —
# and this is the first thing that produces one, where the test below it builds
# the same reading by hand from the pre-merge layout.
@test
def "seal status reports a --no-content-anchor seal as an undated-content endorsement" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response
    seal --repo $fx.repo --no-content-anchor --beacon $TEST_BEACON --response-file $response | ignore

    let rows = seal status --repo $fx.repo
    assert equal ($rows | length) 1
    let row = $rows | first
    assert equal $row.file null "content was named for a bundle that anchors none"
    assert equal $row.current null
    assert equal $row.content "absent" "an anchor was reported over content nothing stamped"
    assert equal $row.signers 1
    assert equal $row.endorsed "pending" "the endorsement this seal exists for went unreported"
}

# The frozen copy is written before any digest is posted, and nothing later in
# the seal looks at it again — so this guard is the only thing between a bundle
# named for one content and a frozen copy of another, which would leave the
# endorsement proofs sitting beside bytes they do not describe. The bundle is
# planted by hand: a seal can only ever produce a copy that matches, so a
# round-trip would pin nothing here.
@test
def "seal --no-content-anchor refuses to overwrite a frozen copy of other content" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let response = $"($tmp_dir)/calendar-response.bin"
    build-calendar-response | save --raw --force $response
    # A first offline seal only to learn the root statement's hash — the planted
    # bundle has to carry the name the next seal will derive.
    seal --repo $fx.repo --no-stamp | ignore
    let root_file = $"($fx.repo)/multiproofs/tree-root.txt"
    let root_prefix = open --raw $root_file | hash sha256 | str uppercase | str substring 0..<8
    let planted = $"($fx.ots_dir)/tree-root.($root_prefix)"
    mkdir $planted
    let other = "content this bundle's proofs do not describe\n"
    $other | save --force $"($planted)/tree-root.txt"

    let err = try {
        seal --repo $fx.repo --no-content-anchor --beacon $TEST_BEACON --response-file $response
        null
    } catch {|e| $e.msg }

    assert ($err | default "" | str contains "collision") $"expected a refusal, got: ($err)"
    assert equal (open --raw $"($planted)/tree-root.txt") $other "the seal overwrote a frozen copy of different content"
}

# The bundle has to be minted before the first digest is posted — `ots stamp
# --into` refuses a directory that is not already there — so a rejected calendar
# answer leaves a directory holding the frozen copy and no proof. The argument
# for minting that early is that nothing reading this tree calls such a directory
# a bundle, and that the retry fills it rather than adding a second one.
@test
def "a rejected calendar answer leaves no bundle behind for --no-content-anchor" [] {
    let tmp_dir = $in.tmp_dir
    let fx = make-sealable-repo $tmp_dir
    let garbage = $"($tmp_dir)/garbage.bin"
    "not a calendar answer" | save --raw --force $garbage

    # Read from `debug` and not `msg`: the stamp runs inside the `each` over the
    # signatures, and nushell's own wrapper is what `msg` carries there ("Eval
    # block failed with pipeline input"). The inner error is what a user sees
    # rendered, and `debug` is where a catch can still find it.
    let err = try {
        seal --repo $fx.repo --no-content-anchor --beacon $TEST_BEACON --response-file $garbage
        null
    } catch {|e| $e.debug }

    assert ($err | default "" | str contains "readable proof") $"expected the stamp to refuse: ($err)"
    assert equal (seal status --repo $fx.repo) [] "a directory holding no proof was reported as a bundle"
    let root_file = $"($fx.repo)/multiproofs/tree-root.txt"
    let root_prefix = open --raw $root_file | hash sha256 | str uppercase | str substring 0..<8
    assert equal (
        open --raw $"($fx.ots_dir)/tree-root.($root_prefix)/tree-root.txt"
    ) (open --raw $root_file) "the frozen copy is not where a retry would expect it"
}

# The two flags ask for different things — "no stamps at all" and "stamp the
# signatures only" — so one winning silently would either post a digest the
# caller meant to keep offline or skip the post they asked for. Refused before
# step 2, since everything from there on rewrites artifacts: an argument error
# must not leave a regenerated manifest and a cleared signature behind.
@test
def "seal refuses --no-stamp together with --no-content-anchor, before touching anything" [] {
    let fx = make-sealable-repo $in.tmp_dir

    let err = try { seal --repo $fx.repo --no-stamp --no-content-anchor; null } catch {|e| $e.msg }

    assert ($err | default "" | str contains "alternatives") $"unexpected error: ($err)"
    assert not (
        $"($fx.repo)/multiproofs/tree-hashes.csv" | path exists
    ) "the seal rewrote artifacts before refusing"
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
    let result = seal --repo $fx.repo --beacon $TEST_BEACON --response-file $response

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

    seal --repo $fx.repo --beacon $TEST_BEACON --response-file $response | ignore
    "v2\n" | save --force $"($fx.repo)/file.txt"
    ^git -C $fx.repo add file.txt
    ^git -C $fx.repo commit -q -m "v2"
    let second = seal --repo $fx.repo --beacon $TEST_BEACON --response-file $response

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
    let result = seal --repo $fx.repo --beacon $TEST_BEACON --response-file $response
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
# test here uses the ed25519 fixture, so nothing else reaches the state below.
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

    let first = seal --repo $fx.repo --beacon $TEST_BEACON --response-file $response
    let first_sig = open --raw ($first.root_sig) | hash sha256
    let second = seal --repo $fx.repo --beacon $TEST_BEACON --response-file $response
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
    seal --repo $fx.repo --beacon $TEST_BEACON --response-file $response | ignore

    let row = seal status --repo $fx.repo | first
    assert equal $row.signers 2 "the co-signer's signature was not carried into the bundle"
    assert equal $row.endorsed "pending, pending" "one of the two endorsements went undated"
}

# The docstring and SPEC claim a bundle behind a symlink is not listed. That is
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
# deliberately NOT a proof (SPEC, "rejected"), and it lives directly under
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
