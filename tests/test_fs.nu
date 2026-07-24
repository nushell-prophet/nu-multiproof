use std/assert
use std/testing *

use ../nu-multiproof/_fs.nu [list-files list-dirs]

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
    each { path basename } | sort
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
@test
def "an absent directory lists as empty, not an error" [] {
    let missing = $"($in.tmp_dir)/nope"
    assert equal (list-files $missing) []
    assert equal (list-files $missing --recursive --suffix ".pub") []
    assert equal (list-dirs $missing) []
}
