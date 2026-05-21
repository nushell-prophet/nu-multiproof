use std/assert
use std/testing *

use ../nu-multiproof/tree-hashes.nu

const EXPECTED_COLUMNS = [
    filepath
    content_sha256
    content_git
    content_cid
]

@test
def "echo returns table with expected columns" [] {
    let result = tree-hashes --echo
    assert equal ($result | columns) $EXPECTED_COLUMNS
}

@test
def "echo returns non-empty table" [] {
    let result = tree-hashes --echo
    assert (($result | length) > 0)
}

@test
def "small files have non-empty content_cid" [] {
    let result = tree-hashes --echo
    let files_with_cid = $result | where content_sha256 != "" and content_cid != ""
    assert (($files_with_cid | length) > 0)
}

@test
def "directories have empty content_sha256 and content_cid" [] {
    let result = tree-hashes --echo
    let dirs = $result | where content_sha256 == ""
    if ($dirs | length) > 0 {
        let bad = $dirs | where content_cid != ""
        assert equal ($bad | length) 0
    }
}

@test
def "directories have non-empty content_git" [] {
    let result = tree-hashes --echo
    let dirs = $result | where content_sha256 == ""
    if ($dirs | length) > 0 {
        let with_git = $dirs | where content_git != ""
        assert (($with_git | length) > 0)
    }
}

@test
def "no root row with empty filepath" [] {
    let result = tree-hashes --echo
    let empty = $result | where { $in.filepath | into string | is-empty }
    assert equal ($empty | length) 0
}

@test
def "hidden tracked files are included" [] {
    let result = tree-hashes --echo
    let tracked = ^git ls-files | lines
    let hidden = $tracked | where { $in | path basename | str starts-with "." }
    # Test only runs assertion if the repo has any hidden tracked files
    for f in $hidden {
        let row = $result | where filepath == $f
        assert equal ($row | length) 1 $"hidden tracked file ($f) missing from manifest"
        assert ($row.0.content_sha256 | is-not-empty) $"hidden tracked file ($f) has empty content_sha256"
    }
}

@test
def "root-cid appends . row with cid v0" [] {
    # Why gated on ipfs binary: root-cid shells out to `ipfs add`. Skip
    # silently when not installed (mirror OTS_NETWORK_TEST pattern in spirit:
    # don't fail on missing optional deps).
    if (which ipfs | is-empty) { return }

    let tmp_dir = (^mktemp -d | str trim)
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q
    "hello\n" | save --force $"($repo)/file.txt"
    ^git -C $repo add file.txt
    ^git -C $repo -c user.email=t@t -c user.name=t commit -q -m init

    tree-hashes --path $repo

    let cid = tree-hashes root-cid --path $repo
    let manifest = open $"($repo)/multiproofs/tree-hashes.csv"
    let dot = $manifest | where filepath == "."
    assert equal ($dot | length) 1
    assert equal $dot.0.content_cid $cid
    assert ($cid | str starts-with "Qm") $"expected CIDv0 \(Qm…\), got ($cid)"

    rm --recursive $tmp_dir
}

# root-cid must refuse to clobber sigs sitting next to the manifest —
# the sig signs the pre-rewrite content and would silently go stale.
@test
def "root-cid refuses to clobber sibling sigs" [] {
    if (which ipfs | is-empty) { return }

    let tmp_dir = (^mktemp -d | str trim)
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q
    "hello\n" | save --force $"($repo)/file.txt"
    ^git -C $repo add file.txt
    ^git -C $repo -c user.email=t@t -c user.name=t commit -q -m init

    tree-hashes --path $repo
    let manifest = $"($repo)/multiproofs/tree-hashes.csv"
    "stale-sig" | save --force $"($manifest).alice.sig"

    let outcome = (try {
        tree-hashes root-cid --path $repo
        "ok"
    } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"

    rm --recursive $tmp_dir
}

@test
def "directory content_git matches working-tree blob hashes of its files" [] {
    let result = tree-hashes --echo
    let dirs = $result | where content_sha256 == "" and filepath != "."
    # For each directory row, the content_git must be non-empty AND must derive
    # from the same snapshot as its file rows (i.e., the temp-index tree).
    # We assert parity by recomputing: for each dir, the hash listed in the
    # manifest must match the tree hash for that path in a fresh temp index
    # built from the same files.
    let files = $result | where content_sha256 != "" and filepath != "."
    let tmp_index = $nu.temp-dir | path join $"nutest-tree-(random uuid)"
    rm --force $tmp_index
    let ls_tree = with-env {GIT_INDEX_FILE: $tmp_index} {
        $files.filepath | str join (char nl) | ^git update-index --add --stdin
        let tree = ^git write-tree | str trim
        ^git ls-tree -r -t $tree
    }
    rm --force $tmp_index
    let expected = (
        $ls_tree
        | lines
        | parse "{mode} {type} {hash}\t{path}"
        | reduce --fold {} {|row acc| $acc | insert $row.path $row.hash }
    )
    for d in $dirs {
        assert ($d.content_git | is-not-empty) $"directory ($d.filepath) has empty content_git"
        assert equal $d.content_git ($expected | get $d.filepath) $"directory ($d.filepath) content_git mismatch"
    }
}
