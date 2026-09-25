use std/assert
use std/testing *

use ../nu-multiproof/_temp-helpers.nu [ with-temp-dir with-temp-file ]
use _fixtures.nu [ setup cleanup ]

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
# on every throw. Six separate commits fixed one instance of that each.
@test
def "with-temp-dir removes the dir when the closure throws" [] {
    let receipt = $"($in.tmp_dir)/dir-path"
    try {
        with-temp-dir "unit" {|dir|
            $dir | save --force $receipt
            error make {msg: "work failed"}
        }
        assert false "the closure error must propagate"
    } catch { }
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
    } catch { }
    let thrown_path = open --raw $receipt | str trim
    assert not ($thrown_path | path exists) $"file leaked on the error path: ($thrown_path)"
}

# Nushell 0.114.1 deadlocks — forever, no error, no timeout — when an external
# command's stdout crosses a `try` boundary and exceeds 256 KiB, which is this
# helper's exact shape. `seal` never returned on any repo whose `git ls-tree`
# output passed that, about 1000 tracked paths.
#
# Why a subprocess with a timeout: a regression here does not fail, it hangs,
# and a hanging test takes the whole suite with it instead of reporting anything.
@test
def "with-temp-file returns more than 256 KiB of external output" [] {
    # The suite runs from the repo root (as tests calling `tree-hashes` with no
    # --repo already assume); assert it rather than fail as "module not found"
    let helpers = $env.PWD | path join "nu-multiproof" "_temp-helpers.nu"
    assert ($helpers | path exists) $"expected the suite to run from the repo root, got ($env.PWD)"
    let script = $"use ($helpers) with-temp-file; with-temp-file 'probe' {|f| ^head -c 400000 /dev/zero | ^tr '\\0' 'x' } | str length | print"
    let run = do { ^timeout 60 nu --no-config-file -c $script } | complete
    assert equal $run.exit_code 0 $"helper did not return \(124 = deadlock\): ($run.stderr)"
    assert equal ($run.stdout | str trim) "400000"
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
