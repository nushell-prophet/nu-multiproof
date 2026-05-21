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
