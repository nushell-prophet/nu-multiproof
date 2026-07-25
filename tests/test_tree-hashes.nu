use std/assert
use std/testing *

use ../nu-multiproof/tree-hashes.nu

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
def "every row carries a CID, directories included" [] {
    let result = tree-hashes --echo
    let missing = $result | where content_cid == ""
    assert equal ($missing | length) 0 $"rows without a CID: ($missing.filepath?)"
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

# B2: one in-process pass yields per-file, per-dir AND the root "." CID, so the
# manifest is written complete in a single pass and `root-cid` is a thin wrapper
# returning that "." CID. The CIDs themselves are pinned against the reference
# client in tests/test_cid-v0.nu; this test pins the manifest shape.
@test
def "one pass emits . row, per-dir CIDs, and root-cid wrapper" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $"($repo)/sub"
    ^git -C $repo init -q
    "hello\n" | save --force $"($repo)/file.txt"
    "world\n" | save --force $"($repo)/sub/inner.txt"
    # Hidden tracked file: `ipfs add` used to skip dotfiles without --hidden,
    # which dropped it from per-file CIDs and from the dir/root CIDs the seal
    # signs. The file set now comes from git, so nothing can skip it silently.
    "hidden\n" | save --force $"($repo)/.hidden"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo -c user.email=t@t -c user.name=t commit -q -m init

    let table = tree-hashes --echo --repo $repo

    # Root "." row present, and it is the CID `ipfs add -r` reports for exactly
    # this tree (recorded in tests/test_cid-v0.nu from ipfs 0.42.0) — the whole
    # manifest fold, from git file set to root, checked against the client.
    let dot = $table | where filepath == "."
    assert equal ($dot | length) 1
    assert equal $dot.0.content_cid "Qme53cg5u81Hh13JAU57drw7Rpm391Pwi2PkbAhF7k3pMS"
    assert equal ($table | where filepath == "sub" | get content_cid.0) "QmQV8kBgwwShkLLLvEej44qvbwTncKJmbwfz5E8e4ApNkj"

    # The "." row participates in the sort (first byte-wise), not appended last —
    # the manifest must honor its own ordering rule
    assert equal $table.filepath.0 "."
    assert equal $table.filepath ($table.filepath | sort)

    # Directory rows now carry their CID (A3), not an empty string
    let dirs = $table | where content_sha256 == "" and filepath != "."
    assert (($dirs | length) > 0)
    for d in $dirs {
        assert ($d.content_cid | str starts-with "Qm") $"dir ($d.filepath) has no CID: ($d.content_cid)"
    }

    # The hidden tracked file gets a CID like any other file
    let hidden = $table | where filepath == ".hidden"
    assert equal ($hidden | length) 1
    assert ($hidden.0.content_cid | str starts-with "Qm") $"hidden file has no CID: ($hidden.0.content_cid)"

    # root-cid regenerates the manifest and returns the "." CID matching it
    let cid = tree-hashes root-cid --repo $repo
    let saved_dot = open $"($repo)/multiproofs/tree-hashes.csv" | where filepath == "."
    assert equal ($saved_dot | length) 1
    assert equal $saved_dot.0.content_cid $cid
}

@test
def "non-ascii filenames come through raw, not C-quoted" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q
    "привет\n" | save --force $"($repo)/文件.md"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo -c user.email=t@t -c user.name=t commit -q -m init

    let table = tree-hashes --echo --repo $repo

    # core.quotePath would render the name as "\346\226\207\344\273\266.md";
    # -z plumbing must yield the raw path bytes as stored in git
    let row = $table | where filepath == "文件.md"
    assert equal ($row | length) 1 $"raw non-ascii filepath missing; got ($table.filepath)"
    assert ($row.0.content_sha256 | is-not-empty)
    # content_git exercises the update-index/ls-tree -z path: a quoted path
    # would silently miss the git_hashes lookup and land empty
    assert ($row.0.content_git | is-not-empty)
}

@test
def "control-byte filename is rejected at generation, before any write" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q
    # git allows tab in a tracked filename; sealing must fail at tree-hashes
    # (before the CSV regen), not later at merkle write-root
    "x\n" | save --force ($repo | path join $"a(char tab)b.txt")
    ^git -C $repo add . o+e>| ignore

    let err = try { tree-hashes --echo --repo $repo; null } catch {|e| $e.msg }
    assert ($err != null) "control-byte filename was accepted"
    assert ($err | str contains "control bytes")
}

@test
def "live symlink is rejected and named" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q
    "x\n" | save --force $"($repo)/real.txt"
    ^ln -s real.txt $"($repo)/link.txt"
    ^git -C $repo add . o+e>| ignore

    let err = try { tree-hashes --echo --repo $repo; null } catch {|e| $e.msg }
    assert ($err != null) "tracked symlink was accepted"
    assert ($err | str contains "symlink")
    assert ($err | str contains "link.txt") $"error does not name the symlink: ($err)"
}

@test
def "broken symlink is rejected by name, not an opaque open failure" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q
    ^ln -s missing.txt $"($repo)/dangling.txt"
    ^git -C $repo add . o+e>| ignore

    let err = try { tree-hashes --echo --repo $repo; null } catch {|e| $e.msg }
    assert ($err != null) "broken tracked symlink was accepted"
    assert ($err | str contains "dangling.txt") $"error does not name the broken symlink: ($err)"
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
        $files.filepath | str join (char -i 0) | ^git update-index --add -z --stdin
        let tree = ^git write-tree | str trim
        ^git ls-tree -r -t -z $tree
    }
    rm --force $tmp_index
    let expected = (
        $ls_tree
        | split row (char -i 0)
        | where { $in != "" }
        | parse "{mode} {type} {hash}\t{path}"
        | reduce --fold {} {|row acc| $acc | insert $row.path $row.hash }
    )
    for d in $dirs {
        assert ($d.content_git | is-not-empty) $"directory ($d.filepath) has empty content_git"
        assert equal $d.content_git ($expected | get $d.filepath) $"directory ($d.filepath) content_git mismatch"
    }
}
