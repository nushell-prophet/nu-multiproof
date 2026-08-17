use std/assert
use std/testing *

use ../nu-multiproof/tree-hashes.nu
use ../nu-multiproof/merkle.nu
use ../nu-multiproof/_snapshot.nu [ parse-snapshot-statement snapshot-state ]
use ../nu-multiproof/_layout.nu snapshot-path

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

# A committed repo with one file at the root and one in a subdirectory. Returns
# the commit it made.
def make-repo [repo: path]: nothing -> string {
    mkdir ($repo | path join sub)
    ^git -C $repo init -q
    "alpha\n" | save --force ($repo | path join a.txt)
    "beta\n" | save --force ($repo | path join sub b.txt)
    ^git -C $repo add -- . o+e>| ignore
    ^git -C $repo -c user.email=t@t -c user.name=t commit -q -m init
    ^git -C $repo rev-parse HEAD | str trim
}

# The claim the record makes, checked the only way that means anything: take the
# commit the record names, check it out somewhere else, rebuild from scratch, and
# compare the merkle root. This is a conformance check against something outside
# the builder's own round-trip — re-reading the file the builder just wrote would
# prove nothing about whether the commit it names describes that manifest.
@test
def "the recorded commit rebuilds to the same merkle root in a fresh checkout" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $tmp_dir | path join origin
    let head = make-repo $repo

    tree-hashes --repo $repo | ignore
    let root = merkle write-root --repo $repo | get root

    let recorded = parse-snapshot-statement (snapshot-path $repo)
    assert equal $recorded $head "the record does not name the commit that was HEAD"

    let clone = $tmp_dir | path join clone
    ^git clone --quiet -- $repo $clone
    # No `--` before the commit: for checkout that separator introduces PATHS,
    # so it would ask for a file by this name instead of a revision.
    ^git -C $clone checkout --quiet --detach $recorded

    tree-hashes --repo $clone | ignore
    let rebuilt = merkle write-root --repo $clone | get root

    assert equal $rebuilt $root "a fresh checkout of the recorded commit rebuilt to a different root"
}

@test
def "a dirty tree removes the record an earlier clean run wrote" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $tmp_dir | path join repo
    make-repo $repo

    tree-hashes --repo $repo | ignore
    assert (snapshot-path $repo | path exists) "no record was written for a clean tree"

    "changed\n" | save --force ($repo | path join a.txt)
    tree-hashes --repo $repo | ignore

    assert (not (snapshot-path $repo | path exists)) "a stale record survived a rebuild from a dirty tree"
}

@test
def "a change staged but not committed counts as dirty" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $tmp_dir | path join repo
    make-repo $repo

    # The manifest enumerates the INDEX (git ls-files), so a staged file is in it
    # while HEAD knows nothing about it — the record would name a commit that
    # cannot rebuild this manifest.
    "gamma\n" | save --force ($repo | path join c.txt)
    ^git -C $repo add -- c.txt
    tree-hashes --repo $repo | ignore

    assert (not (snapshot-path $repo | path exists)) "a staged change was treated as a clean tree"
}

@test
def "an untracked file leaves the record standing" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $tmp_dir | path join repo
    let head = make-repo $repo

    # Untracked files cannot enter the manifest, so they cannot make the recorded
    # commit wrong. Counting them would suppress the record for nothing.
    "scratch\n" | save --force ($repo | path join notes.txt)
    tree-hashes --repo $repo | ignore

    assert equal (parse-snapshot-statement (snapshot-path $repo)) $head
}

@test
def "a change outside the sealed subtree leaves the record standing" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $tmp_dir | path join repo
    let head = make-repo $repo
    # --repo need not be the git root: nu-cybergraph seals a subdirectory, and the
    # manifest then covers exactly that subtree. git status does not — it answers
    # for the whole repository — so without a pathspec the operator's unrelated
    # work would suppress a record their change cannot falsify.
    let sealed = $repo | path join sub

    tree-hashes --repo $sealed | ignore
    assert equal (parse-snapshot-statement (snapshot-path $sealed)) $head

    "edited outside\n" | save --force ($repo | path join a.txt)
    tree-hashes --repo $sealed | ignore
    assert equal (parse-snapshot-statement (snapshot-path $sealed)) $head "a change outside the sealed subtree suppressed the record"

    "edited inside\n" | save --force ($sealed | path join b.txt)
    tree-hashes --repo $sealed | ignore
    assert (not (snapshot-path $sealed | path exists)) "a change inside the sealed subtree left the record standing"
}

@test
def "a repo before its first commit gets no record" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $tmp_dir | path join repo
    mkdir $repo
    ^git -C $repo init -q
    "alpha\n" | save --force ($repo | path join a.txt)
    ^git -C $repo add -- . o+e>| ignore

    # The manifest builds fine — ls-files reads the index — but there is no commit
    # to name. Nothing is wrong, so this is silence, not an error.
    tree-hashes --repo $repo | ignore

    assert (not (snapshot-path $repo | path exists))
    assert equal (snapshot-state $repo) null
}

@test
def "echo writes no record" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $tmp_dir | path join repo
    make-repo $repo

    tree-hashes --echo --repo $repo | ignore

    assert (not (snapshot-path $repo | path exists)) "--echo wrote a record for a manifest it did not save"
}

const SHA1_HEX = "0123456789abcdef0123456789abcdef01234567"
const SHA256_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

@test
def "both git object formats are read by hex length" [] {
    let file = $in.tmp_dir | path join snapshot.txt
    for commit in [$SHA1_HEX $SHA256_HEX] {
        $"multiproof-snapshot-v1 ($commit)\n" | save --raw --force $file
        assert equal (parse-snapshot-statement $file) $commit
    }
}

# Hand-built records, not ones this module produced: the parser is the only thing
# standing between a file someone else wrote and a commit hash reported as fact.
@test
def "a malformed record is refused rather than read" [] {
    let file = $in.tmp_dir | path join snapshot.txt
    let hostile = [
        $"multiproof-snapshot-v1 ($SHA1_HEX)\n\n" # extra trailing newline
        $"multiproof-snapshot-v1 ($SHA1_HEX)" # no trailing newline
        $"multiproof-snapshot-v1 ($SHA1_HEX | str upcase)\n" # uppercase hex
        $"multiproof-snapshot-v2 ($SHA1_HEX)\n" # another schema
        "multiproof-snapshot-v1 deadbeef\n" # too short to be either format
        $"multiproof-snapshot-v1 ($SHA1_HEX) extra\n" # a field nobody defined
        $"($SHA1_HEX)\n" # a bare hash, no schema token
    ]
    for bad in $hostile {
        $bad | save --raw --force $file
        let err = try { parse-snapshot-statement $file; null } catch {|e| $e.msg }
        assert ($err != null) $"a malformed record was accepted: ($bad | to json)"
    }
}
