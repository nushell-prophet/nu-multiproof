use std/assert
use std/testing *

use ../nu-multiproof/_temp-helpers.nu [with-temp-dir with-temp-file]

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

@test
def "with-temp-dir gives an empty dir, returns the closure value, and removes it" [] {
    let path = with-temp-dir "unit" {|dir|
        assert ($dir | path exists) "the directory must exist inside the closure"
        assert equal (ls --all $dir | length) 0
        "hi" | save --force ($dir | path join "written")
        $dir
    }
    assert not ($path | path exists) $"directory survived the happy path: ($path)"
}

# The reason the helper exists: a hand-written `rm` after the work is skipped
# on every throw. Five separate commits fixed one instance of that each.
@test
def "with-temp-dir removes the dir when the closure throws" [] {
    let receipt = $"($in.tmp_dir)/dir-path"
    try {
        with-temp-dir "unit" {|dir|
            $dir | save --force $receipt
            error make {msg: "work failed"}
        }
        assert false "the closure error must propagate"
    } catch {}
    let path = open --raw $receipt | str trim
    assert not ($path | path exists) $"directory leaked on the error path: ($path)"
}

@test
def "with-temp-file removes the file on both paths" [] {
    let path = with-temp-file "unit" {|file|
        "content" | save --force $file
        $file
    }
    assert not ($path | path exists) $"file survived the happy path: ($path)"

    let receipt = $"($in.tmp_dir)/file-path"
    try {
        with-temp-file "unit" {|file|
            $file | save --force $receipt
            "content" | save --force $file
            error make {msg: "work failed"}
        }
        assert false "the closure error must propagate"
    } catch {}
    let thrown_path = open --raw $receipt | str trim
    assert not ($thrown_path | path exists) $"file leaked on the error path: ($thrown_path)"
}

# Cleanup must not cost the diagnosis. `catch {|e| rm …; error make {msg: $e.msg}}`
# cleans up correctly and still reduces "File not found, at line N of x.nu" to a
# bare message with no span, no help and no error code — this pins that the
# helper's `finally` keeps the original error intact.
@test
def "with-temp-dir propagates the original error, not a flattened copy" [] {
    let err = try {
        with-temp-dir "unit" {|dir|
            open --raw ($dir | path join "does-not-exist")
        }
        null
    } catch {|e| $e }

    assert ($err != null) "the error must propagate"
    assert ($err.rendered | str contains "file_not_found") $"error type was lost: ($err.rendered)"
}
