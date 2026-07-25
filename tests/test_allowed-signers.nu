# An allowed_signers file is a trust list, and the only thing between a
# directory of files and OpenSSH's parser. Every case here is a hostile file
# name or a hostile file body — not something `init` would ever write.
use std/assert
use std/testing *

use ../nu-multiproof/_allowed-signers.nu allowed-signers-body

const ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOi7LinplEQewM3/l8Ol9rE85+YwhvLPKf+ZUUf36Xuf"
const RSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDExnwUVhsIh66w1OIGHFyr0prionxHoHEmkSdgDvMo86vDarHwO88H5yQ4ZhRcUTBS4pLYMbGMeGQfHQBbJI4P8Xarsgys7TfMZ9oJq7/tvSnt85xfkXixhSSTMml3D80FAvhS4hPjnSbqaaVeBcW6d3uCDGpibXZ9eted9nY1PsVtsvET57ooJ8qGh4e3lqkwCXJaCKGAY4zqtTZKAEjsm0PcCueFDuN9zWTTzYy9XZucqcGaBDslrylix5AW81QwOzWlkE7nukWGCguSLUezms8yr1NU9Z2HBlwt3hVC5BLqPOrDWR55jhEQuGV8RVZBT6LaVfVdPqhNA1lJTn9j"

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

@test
def "one line per key: principal is the stem, the key is canonical" [] {
    let dir = $in.tmp_dir
    $"($ED25519) alice@laptop\n" | save --force $"($dir)/alice.pub"
    $"($RSA) bob@desktop\n" | save --force $"($dir)/bob.pub"

    let lines = allowed-signers-body $dir | lines | sort
    assert equal $lines [
        $"alice namespaces=\"file\" ($ED25519)"
        $"bob namespaces=\"file\" ($RSA)"
    ]
    # the comment is dropped, so the rendered line is the same on every machine
    assert equal (allowed-signers-body $dir --namespace "git" --wildcard | lines | length) 2
    assert (allowed-signers-body $dir --wildcard | lines | all {|l| $l | str starts-with "* " })
}

# One file, several principals: the stem is interpolated into the line, so a
# newline in it ends the line early and starts another.
@test
def "a file name that would inject a second line is refused" [] {
    let dir = $in.tmp_dir
    # No slash in the injected text: it has to survive as one file name.
    $"($ED25519)\n" | save --force $"($dir)/alice\nmallory namespaces=\"file\" ssh-ed25519 AAAA\n#.pub"

    let outcome = try { allowed-signers-body $dir; "rendered" } catch {|e| $e.msg }
    # Asserting on the message, not merely on "an error": nushell's `open`
    # happens to fail on a file name holding a newline, so a bare `assert error`
    # here would pass with no principal check at all.
    assert ($outcome | str contains "signer name") $"expected the name to be refused, got: ($outcome)"
}

@test
def "a file name that would claim more than its own principal is refused" [] {
    for stem in ["alice bob" "alice,mallory" "*" "ali?e" "!alice" 'ali"ce' 'ali\ce'] {
        let dir = mktemp --directory
        $"($ED25519)\n" | save --force $"($dir)/($stem).pub"
        let outcome = try { allowed-signers-body $dir; "rendered" } catch { "refused" }
        rm --recursive --force $dir
        assert equal $outcome "refused" $"stem ($stem) was rendered into a principal"
    }
}

# `*` is the whole point of --wildcard: the collective statement is deliberate
# there, so the stem is never read.
@test
def "wildcard mode does not care what the file is called" [] {
    let dir = $in.tmp_dir
    $"($ED25519)\n" | save --force $"($dir)/alice bob*.pub"
    assert equal (allowed-signers-body $dir --wildcard) $"* namespaces=\"file\" ($ED25519)"
}

# ssh-keygen rejects the whole allowed_signers file over one bad entry, so a
# malformed key does not merely lose its own line — it disables verification
# for every signer in the repo. Fail where the broken file is, naming it.
@test
def "a malformed key in the directory is an error, not a skipped line" [] {
    let dir = $in.tmp_dir
    $"($ED25519)\n" | save --force $"($dir)/alice.pub"
    $"($ED25519)\n($RSA)\n" | save --force $"($dir)/two-lines.pub"

    let outcome = try { allowed-signers-body $dir; "rendered" } catch {|e| $e.msg }
    assert ($outcome | str contains "two-lines.pub") $"error should name the broken file, got: ($outcome)"
}

@test
def "a key that is not a key is an error too" [] {
    let dir = $in.tmp_dir
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITAMPERED tampered\n" | save --force $"($dir)/mallory.pub"
    assert error {|| allowed-signers-body $dir }
}
