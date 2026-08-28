use std/assert
use std/testing *

use ../nu-multiproof/tree-hashes.nu
use ../nu-multiproof/_tracked.nu content-tree

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
    content_git_sha1
    content_git_sha256
    content_cid
]

# Why every shape test builds its own repo: `tree-hashes` without --repo hashes
# whatever git root the CWD happens to sit in, so these tests used to state a
# property of a neighbouring checkout, not of this code. They only held while
# that neighbour stayed convenient — a monorepo that tracks one symlink (which
# _tracked.nu rejects, by design) failed all of them at once.
# The tree carries what those assertions need: files, two levels of directory,
# and hidden tracked files at both levels.
def make-repo [tmp_dir: path]: nothing -> string {
    let repo = $"($tmp_dir)/repo"
    mkdir $"($repo)/sub/deeper"
    ^git -C $repo init -q
    "hello\n" | save --force $"($repo)/file.txt"
    "apple\n" | save --force $"($repo)/apple.txt"
    "world\n" | save --force $"($repo)/sub/inner.txt"
    "deep\n" | save --force $"($repo)/sub/deeper/x.txt"
    "hidden\n" | save --force $"($repo)/.hidden"
    "nested hidden\n" | save --force $"($repo)/sub/.dotfile"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo -c user.email=t@t -c user.name=t commit -q -m init
    $repo
}

@test
def "echo returns table with expected columns" [] {
    let repo = make-repo $in.tmp_dir
    let result = tree-hashes --echo --repo $repo
    assert equal ($result | columns) $EXPECTED_COLUMNS
}

@test
def "echo returns non-empty table" [] {
    let repo = make-repo $in.tmp_dir
    let result = tree-hashes --echo --repo $repo
    assert (($result | length) > 0)
}

@test
def "small files have non-empty content_cid" [] {
    let repo = make-repo $in.tmp_dir
    let result = tree-hashes --echo --repo $repo
    let files_with_cid = $result | where content_sha256 != "" and content_cid != ""
    assert (($files_with_cid | length) > 0)
}

@test
def "every row carries a CID, directories included" [] {
    let repo = make-repo $in.tmp_dir
    let result = tree-hashes --echo --repo $repo
    let missing = $result | where content_cid == ""
    assert equal ($missing | length) 0 $"rows without a CID: ($missing.filepath?)"
}

@test
def "directories carry a git hash in both formats" [] {
    let repo = make-repo $in.tmp_dir
    let result = tree-hashes --echo --repo $repo
    # "." has no git hash of its own; every other directory row must have both
    let dirs = $result | where content_sha256 == "" and filepath != "."
    assert (($dirs | length) > 0) "the fixture tree lost its directory rows"
    for d in $dirs {
        assert ($d.content_git_sha1 =~ '^[0-9a-f]{40}$') $"($d.filepath) content_git_sha1: ($d.content_git_sha1)"
        assert ($d.content_git_sha256 =~ '^[0-9a-f]{64}$') $"($d.filepath) content_git_sha256: ($d.content_git_sha256)"
    }
}

@test
def "no root row with empty filepath" [] {
    let repo = make-repo $in.tmp_dir
    let result = tree-hashes --echo --repo $repo
    let empty = $result | where { $in.filepath | into string | is-empty }
    assert equal ($empty | length) 0
}

@test
def "hidden tracked files are included" [] {
    let repo = make-repo $in.tmp_dir
    let result = tree-hashes --echo --repo $repo
    let tracked = ^git -C $repo ls-files | lines
    let hidden = $tracked | where { $in | path basename | str starts-with "." }
    assert (($hidden | length) > 0) "the fixture tree lost its hidden tracked files"
    for f in $hidden {
        let row = $result | where filepath == $f
        assert equal ($row | length) 1 $"hidden tracked file ($f) missing from manifest"
        assert ($row.0.content_sha256 | is-not-empty) $"hidden tracked file ($f) has empty content_sha256"
    }
}

# One in-process pass yields per-file, per-dir AND the root "." CID, so the
# manifest is written complete in a single pass and `root-cid` is a thin wrapper
# returning that "." CID. The CIDs themselves are pinned against the reference
# client in tests/test_cid-v0.nu; this test pins the manifest shape.
@test
def "one pass emits . row, per-dir CIDs, and root-cid wrapper" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $"($repo)/sub/deeper"
    ^git -C $repo init -q
    "hello\n" | save --force $"($repo)/file.txt"
    "world\n" | save --force $"($repo)/sub/inner.txt"
    # Two levels of directory: the fold must build sub/deeper before sub, or sub
    # has no CID to link. One level cannot tell a deepest-first walk from any
    # other order.
    "deep\n" | save --force $"($repo)/sub/deeper/x.txt"
    # Why an uppercase name beside lowercase ones: directory links are ordered by
    # name bytes, so "Zebra.txt" sorts before "apple.txt". Under a
    # case-insensitive sort it would go last and the root CID would change — a
    # tree of all-lowercase names cannot catch that.
    "zebra\n" | save --force $"($repo)/Zebra.txt"
    "apple\n" | save --force $"($repo)/apple.txt"
    # Hidden tracked file: `ipfs add` used to skip dotfiles without --hidden,
    # which dropped it from per-file CIDs and from the dir/root CIDs the seal
    # signs. The file set now comes from git, so nothing can skip it silently.
    "hidden\n" | save --force $"($repo)/.hidden"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo -c user.email=t@t -c user.name=t commit -q -m init

    let table = tree-hashes --echo --repo $repo

    # Root "." row present, and it is the CID `ipfs add -r` reports for exactly
    # this tree (recorded from ipfs 0.42.0) — the whole manifest fold, from git
    # file set through both directory levels to the root, against the client.
    let dot = $table | where filepath == "."
    assert equal ($dot | length) 1
    assert equal $dot.0.content_cid "QmZ57tAfENkUzcCC9CUpXV4kn9QhW4knEHWq96A9MwrybP"
    assert equal ($table | where filepath == "sub" | get content_cid.0) "QmZFmeyvidcJYhsZRopSFbi3TP7Pwqy93HZ2XHBBXaWaKi"
    assert equal ($table | where filepath == "sub/deeper" | get content_cid.0) "Qmam1jLqzkQdswuhTKaJDcoN7Zve237vwCBY8nirCYowjW"

    # The "." row participates in the sort (first byte-wise), not appended last —
    # the manifest must honor its own ordering rule
    assert equal $table.filepath.0 "."
    assert equal $table.filepath ($table.filepath | sort)

    # Directory rows carry their CID, not an empty string
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
    # The git columns exercise the update-index/ls-tree -z path: a quoted path
    # would silently miss the lookup and land empty
    assert ($row.0.content_git_sha1 | is-not-empty)
    assert ($row.0.content_git_sha256 | is-not-empty)
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

# A scoped walk covers one row's subtree, but tracked-dirs derives a parent for
# every path and cid-nodes always folds "." — so folding "a/b" alone also
# synthesized "a" and ".". Those are CIDs of a tree that exists nowhere: neither
# the target's real root nor a full walk's. A record whose job is handing out
# directory CIDs must not carry a plausible wrong root among them.
@test
def "a walk scoped to a subtree offers no node above that subtree" [] {
    let target = $"($in.tmp_dir)/bundle"
    mkdir $"($target)/a/b"
    "deep\n" | save --force $"($target)/a/b/inner.txt"
    "beside\n" | save --force $"($target)/a/sibling.txt"

    let scoped = content-tree $target --walk --under "a/b"
    let whole = content-tree $target --walk

    assert equal ($scoped.nodes | columns | sort) ["a/b" "a/b/inner.txt"]
    assert equal $scoped.dirs ["a/b"]
    assert ("." in ($whole.nodes | columns)) "an unscoped walk stopped folding the root"
    # The node the scope exists FOR is untouched: a UnixFS directory commits to
    # its own entries and to nothing above them, which is what makes scoping sound.
    assert equal ($scoped.nodes | get "a/b") ($whole.nodes | get "a/b")
}

# Builder and verifier share one enumeration (content-tree), but not one
# behavior: the verifier turns a deleted tracked file into a "missing" verdict,
# while the builder must refuse to seal a tree it cannot read — loudly, naming
# the path, not with the bare "Eval block failed" `open` used to die with.
@test
def "a tracked file deleted from the worktree fails the build by name" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q
    "x\n" | save --force $"($repo)/kept.txt"
    "y\n" | save --force $"($repo)/gone.txt"
    ^git -C $repo add . o+e>| ignore
    rm $"($repo)/gone.txt"

    let err = try { tree-hashes --echo --repo $repo; null } catch {|e| $e.msg }
    assert ($err != null) "a build over a deleted tracked file did not fail"
    assert ($err | str contains "gone.txt") $"error does not name the missing file: ($err)"
    assert ($err | str contains "missing")
}

@test
def "directory git hashes match a working-tree index built independently" [] {
    let repo = make-repo $in.tmp_dir
    let result = tree-hashes --echo --repo $repo
    let dirs = $result | where content_sha256 == "" and filepath != "."
    # The manifest carries both formats; this rebuild asks the fixture repo's
    # own git, so it can only answer for the format that repo runs. The other
    # column is pinned by the external vectors below, which is the stronger
    # check anyway — it does not rebuild anything.
    let format = ^git -C $repo rev-parse --show-object-format | str trim
    let column = $"content_git_($format)"
    let files = $result | where content_sha256 != "" and filepath != "."
    let tmp_index = $nu.temp-dir | path join $"nutest-tree-(random uuid)"
    rm --force $tmp_index
    # -C $repo on all three: the manifest side of the comparison came from that
    # repo, so the index side must be built there too, or the two describe
    # different trees.
    let ls_tree = with-env {GIT_INDEX_FILE: $tmp_index} {
        $files.filepath | str join (char -i 0) | ^git -C $repo update-index --add -z --stdin
        let tree = ^git -C $repo write-tree | str trim
        ^git -C $repo ls-tree -r -t -z $tree
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
        assert equal ($d | get $column) ($expected | get $d.filepath) $"directory ($d.filepath) ($column) mismatch"
    }
}

# The vectors below came from git itself, outside this codebase: a working tree
# holding a.txt = "hello" and d/b.txt = "world", hashed by `git write-tree` in a
# repo of each object format. They are what makes this more than a round-trip of
# our own builder — and they are the whole point of the change, since one of the
# two columns can never come from the repo the manifest describes.
const HELLO_WORLD_TREE = {
    sha1: {
        "a.txt": "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0"
        "d": "0980762b58316262116e0b114d3bd5d44256399f"
        "d/b.txt": "04fea06420ca60892f73becee3614f6d023a4b7f"
    }
    sha256: {
        "a.txt": "8aec4e4876f854f688d0ebfc8f37598f38e5fd6903cccc850ca36591175aeb60"
        "d": "866ab7eca3c129182cf41594e1234c0827856d9770c2be1b7e611f20262b433c"
        "d/b.txt": "8df3dab4ddfa6eb2a34065cda27d95af2709d4d2658e1b5fbd145822acf42b28"
    }
}

@test
def "both git columns hold the same values whatever format the repo runs" [] {
    let tmp_dir = $in.tmp_dir
    for format in [sha1 sha256] {
        let repo = $"($tmp_dir)/($format)"
        mkdir $"($repo)/d"
        ^git -C $repo init --quiet --object-format $format
        "hello" | save --raw --force $"($repo)/a.txt"
        "world" | save --raw --force $"($repo)/d/b.txt"
        ^git -C $repo add -- a.txt d/b.txt
        let rows = tree-hashes --echo --repo $repo | select filepath content_git_sha1 content_git_sha256

        for path in [a.txt d d/b.txt] {
            let row = $rows | where filepath == $path | first
            assert equal $row.content_git_sha1 ($HELLO_WORLD_TREE.sha1 | get $path) $"($format) repo, ($path), sha1 column"
            assert equal $row.content_git_sha256 ($HELLO_WORLD_TREE.sha256 | get $path) $"($format) repo, ($path), sha256 column"
        }
    }
}
