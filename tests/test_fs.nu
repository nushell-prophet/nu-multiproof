use std/assert
use std/testing *

use ../nu-multiproof/_fs.nu [ list-files list-dirs copy-file ]

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

# Directory holding one dotfile, one plain file, one subdirectory with a file,
# under a name full of glob metacharacters.
def make-tree [tmp_dir: path]: nothing -> path {
    let dir = $"($tmp_dir)/re[po] v*1?"
    mkdir $"($dir)/sub"
    "x" | save --force $"($dir)/alice.pub"
    "x" | save --force $"($dir)/.hidden.pub"
    "x" | save --force $"($dir)/notes.txt"
    "x" | save --force $"($dir)/sub/bob.pub"
    $dir
}

def basenames []: list<path> -> list<string> {
    path basename | sort
}

# The reason this module exists: `glob ($dir | path join "*.pub")` interpolates
# the directory into the pattern, so `[`, `]`, `*` and `?` in the path are read
# as pattern syntax and the call returns nothing at all.
@test
def "listing works when the directory name holds glob metacharacters" [] {
    let dir = make-tree $in.tmp_dir
    assert equal (list-files $dir | basenames) [".hidden.pub" "alice.pub" "notes.txt"]
    assert equal (list-dirs $dir | basenames) ["sub"]
    # The returned paths must be usable as-is, not merely look right
    list-files $dir | each {|f| assert ($f | path exists) $"listed path does not exist: ($f)" }
}

@test
def "suffix filters by literal name, recursive walks subdirectories" [] {
    let dir = make-tree $in.tmp_dir
    assert equal (list-files $dir --suffix ".pub" | basenames) [".hidden.pub" "alice.pub"]
    assert equal (list-files $dir --recursive --suffix ".pub" | basenames) [".hidden.pub" "alice.pub" "bob.pub"]
    assert equal (list-files $dir --recursive | length) 4
}

# Discovery over a directory that does not exist is "nothing there" — the
# answer glob gave. Callers list proof and stamp directories before any command
# has created them.
# The reason copy-file exists: `cp` prints a failed copy on stderr and exits 0,
# so a caller cannot tell a short bundle from a full one. An unwritable
# destination is the vector that separates the two — `cp` refuses a same-file
# copy silently and leaves the bytes intact, so a hard-link test alone would
# leave a mutation back to `cp` alive here. Needs a non-root uid; root ignores
# the mode and this fails loudly rather than passing for the wrong reason.
@test
def "a copy that cannot be written raises instead of returning" [] {
    let tmp_dir = $in.tmp_dir
    let src = $"($tmp_dir)/src.bin"
    "payload" | save --force $src
    let locked = $"($tmp_dir)/locked"
    mkdir $locked
    ^chmod 500 $locked

    let failed = try { copy-file $src $"($locked)/dest.bin"; false } catch { true }
    ^chmod 700 $locked

    assert $failed "copy-file returned although the destination could not be written"
    assert equal (ls --all $locked | get name) [] "the copy landed after all, so this test proves nothing"
}

# Streaming `open --raw $src | save --raw $dest` truncates the destination while
# the source is still being read from it whenever the two names are one file.
# Nushell's own same-file check is by path, so an alias walks past it: measured,
# both names were left at 0 bytes and nothing raised. copy-file collects first.
@test
def "copying a file onto a hard link of itself keeps the bytes" [] {
    let tmp_dir = $in.tmp_dir
    let src = $"($tmp_dir)/src.bin"
    let alias = $"($tmp_dir)/alias.bin"
    (0..2000 | each { "payload" } | str join) | save --force $src
    ^ln $src $alias

    copy-file $src $alias --force
    # Length as well as hash: truncating both names to 0 bytes leaves them
    # equal to each other, which is exactly the failure being ruled out.
    assert equal (open --raw $alias | into binary | hash sha256) (open --raw $src | into binary | hash sha256)
    assert ((open --raw $alias | into binary | bytes length) > 0) "the copy truncated the file it was reading"
}

@test
def "an absent directory lists as empty, not an error" [] {
    let missing = $"($in.tmp_dir)/nope"
    assert equal (list-files $missing) []
    assert equal (list-files $missing --recursive --suffix ".pub") []
    assert equal (list-dirs $missing) []
}
