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
def "nushell-only echo returns table with expected columns" [] {
    let result = tree-hashes --nushell-only --echo
    assert equal ($result | columns) $EXPECTED_COLUMNS
}

@test
def "nushell-only echo returns non-empty table" [] {
    let result = tree-hashes --nushell-only --echo
    assert (($result | length) > 0)
}

@test
def "small files have non-empty content_cid" [] {
    let result = tree-hashes --nushell-only --echo
    let files_with_cid = $result | where content_sha256 != "" and content_cid != ""
    assert (($files_with_cid | length) > 0)
}

@test
def "directories have empty content_sha256 and content_cid" [] {
    let result = tree-hashes --nushell-only --echo
    let dirs = $result | where content_sha256 == ""
    if ($dirs | length) > 0 {
        let bad = $dirs | where content_cid != ""
        assert equal ($bad | length) 0
    }
}

@test
def "directories have non-empty content_git" [] {
    let result = tree-hashes --nushell-only --echo
    let dirs = $result | where content_sha256 == ""
    if ($dirs | length) > 0 {
        let with_git = $dirs | where content_git != ""
        assert (($with_git | length) > 0)
    }
}

@test
def "no root row with empty filepath" [] {
    let result = tree-hashes --nushell-only --echo
    let empty = $result | where { $in.filepath | into string | is-empty }
    assert equal ($empty | length) 0
}
