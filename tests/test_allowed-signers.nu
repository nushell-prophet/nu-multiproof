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

# A malformed key silently loses its own line (see the test below for what
# ssh-keygen really does with one), so the rendered trust list stops matching
# pubkeys/ and the affected signer just reads as unrecognized. Fail where the
# broken file is, naming it.
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

# The claim this module leans on, checked against ssh-keygen itself rather
# than assumed. A malformed entry does NOT take the file down with it: the bad
# line is warned about on stderr and skipped, and every other signer still
# verifies. That is why rendering one anyway is unacceptable — the loss is
# silent, and the warning never reaches the caller through `complete`. If a
# later OpenSSH turns this into a hard failure, this test says so.
@test
def "ssh-keygen skips a malformed entry rather than failing" [] {
    let dir = $in.tmp_dir
    let key = $"($dir)/alice_key"
    let doc = $"($dir)/doc.txt"
    let signers_file = $"($dir)/allowed_signers"

    "hello world" | save --force $doc
    ^ssh-keygen -t ed25519 -f $key -N "" -q
    ^ssh-keygen -Y sign -q -f $key -n file $doc
    let good = $"alice namespaces=\"file\" (open --raw $"($key).pub" | str trim)"
    # Both shapes a bad `.pub` produces here: a line whose key does not parse,
    # and the principal-less line a two-line key file emitted.
    let bad_lines = [
        'mallory namespaces="file" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITAMPERED'
        (open --raw $"($key).pub" | str trim)
    ]

    for bad in $bad_lines {
        [$bad $good] | str join "\n" | save --force $signers_file

        let fp = (do { ^ssh-keygen -Y find-principals -s $"($doc).sig" -f $signers_file } | complete)
        assert equal $fp.exit_code 0 $"a bad line took the whole file down: ($bad | str substring 0..40)"
        assert equal ($fp.stdout | lines | last) "alice"
        # the only notice of the broken entry, and `complete` is where it dies
        assert ($fp.stderr | str contains ":1: ") $"no warning for: ($bad | str substring 0..40)"

        let verified = (do {
            open --raw $doc | ^ssh-keygen -Y verify -f $signers_file -I alice -n file -s $"($doc).sig"
        } | complete)
        assert equal $verified.exit_code 0
    }
}
