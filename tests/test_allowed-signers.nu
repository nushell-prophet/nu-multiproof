# An allowed_signers file is a trust list, and the only thing between a
# directory of files and OpenSSH's parser. Every case here is a hostile file
# name or a hostile file body — not something `init` would ever write.
use std/assert
use std/testing *

use ../nu-multiproof/_allowed-signers.nu allowed-signers-body

const ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOi7LinplEQewM3/l8Ol9rE85+YwhvLPKf+ZUUf36Xuf"
const RSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDExnwUVhsIh66w1OIGHFyr0prionxHoHEmkSdgDvMo86vDarHwO88H5yQ4ZhRcUTBS4pLYMbGMeGQfHQBbJI4P8Xarsgys7TfMZ9oJq7/tvSnt85xfkXixhSSTMml3D80FAvhS4hPjnSbqaaVeBcW6d3uCDGpibXZ9eted9nY1PsVtsvET57ooJ8qGh4e3lqkwCXJaCKGAY4zqtTZKAEjsm0PcCueFDuN9zWTTzYy9XZucqcGaBDslrylix5AW81QwOzWlkE7nukWGCguSLUezms8yr1NU9Z2HBlwt3hVC5BLqPOrDWR55jhEQuGV8RVZBT6LaVfVdPqhNA1lJTn9j"
# The principal each of those keys renders under: sha256 of its key blob.
# Spelled out rather than computed here — a test that asks the module for its own
# expectation checks nothing. The values are pinned against `ssh-keygen -lf` in
# tests/test_pubkey.nu "fingerprint is the digest ssh-keygen prints, written as
# hex".
const ED25519_FP = "b610a91de8fa99e224f6b2e7fb6bb8c9e8f0303f8d72d14e5a494ab8d1c68011"
const RSA_FP = "4faa889e999e5fa3d43e47d90b487260526594804a5048c067be20748f16b88a"

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

@test
def "one line per key: the principal is the key fingerprint, not the file name" [] {
    let dir = $in.tmp_dir
    $"($ED25519) alice@laptop\n" | save --force $"($dir)/alice.pub"
    $"($RSA) bob@desktop\n" | save --force $"($dir)/bob.pub"

    let body = allowed-signers-body $dir
    assert equal ($body | lines | sort) [
        $"($RSA_FP) namespaces=\"file\" ($RSA)"
        $"($ED25519_FP) namespaces=\"file\" ($ED25519)"
    ]
    # Neither the file names nor the key comments they mirror reach the file.
    for name in ["alice" "bob"] {
        assert (not ($body | str contains $name)) $"($name) reached the trust list from a file name"
    }
}

# Every stem below used to be refused, and had to be: the stem WAS the principal,
# so a newline in it wrote a second trust-list entry, a space or comma claimed two
# principals, `*` claimed every signer at once, and an invisible U+200B or U+202E
# wrote a principal that *reads* as another one. The whole class is gone rather
# than defended: the principal is derived from the key, so none of these names
# reaches a line at all. Each renders exactly one entry, under the key's own
# fingerprint. Hostile input here is the file name, which no key `init` writes
# would ever carry.
@test
def "a file name that used to write its own trust-list entry now writes nothing" [] {
    let stems = [
        "alice bob"
        "alice,mallory"
        "*"
        "ali?e"
        "!alice"
        'ali"ce'
        'ali\ce'
        "ali\u{200b}ce"
        "ali\u{202e}ce"
    ]
    for stem in $stems {
        let dir = mktemp --directory
        $"($ED25519)\n" | save --force $"($dir)/($stem).pub"
        let body = try { allowed-signers-body $dir } catch {|e| $"threw: ($e.msg)" }
        rm --recursive --force $dir
        assert equal ($body | lines) [
            $"($ED25519_FP) namespaces=\"file\" ($ED25519)"
        ] $"file name ($stem | to nuon) changed what the trust list says"
    }
}

# The one file name that still cannot be rendered, and it is not a principal
# problem: nushell's `ls` returns a name holding a control byte with that byte
# escaped as the literal text `\u{a}`, so the path it hands back does not exist
# and `open` fails. Measured on 0.114.1; see
# todo/20260727-*-ls-escapes-control-bytes-in-names.md.
#
# What matters here is that it fails loudly. A trust list that quietly renders
# one line fewer says nothing while the affected signer reads as unrecognized —
# the same silent-loss shape the two-line-key guard below exists for. The message
# blames the key file rather than its name, which is the cost of leaning on
# `open` for this; it is noted in the parked finding.
@test
def "a file name holding a control byte fails loudly rather than dropping a line" [] {
    let dir = $in.tmp_dir
    # No slash in the injected text: it has to survive as one file name.
    $"($ED25519)\n" | save --force $"($dir)/alice\nmallory namespaces=\"file\" ssh-ed25519 AAAA\n#.pub"
    $"($RSA)\n" | save --force $"($dir)/bob.pub"

    let outcome = try { allowed-signers-body $dir; "rendered" } catch {|e| $e.msg }
    assert ($outcome != "rendered") $"a name `ls` cannot round-trip was silently skipped: ($outcome)"
    assert ($outcome | str contains "mallory") $"the error must name the file to fix, got: ($outcome)"
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
