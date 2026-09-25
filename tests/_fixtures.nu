# What every suite shares: the per-test temp dir, and how a key names its
# signer. The `_` name keeps nutest from picking this up as a suite (discovery
# matches test_*.nu); import names explicitly. nutest discovers the attributes
# through the import.

use std/testing *
use ../nu-multiproof/pubkey.nu

# Why a fixture, not rm at the end of test bodies: after-each runs even when
# the test throws, so a failing test does not leak its /tmp/tmp.* dir.
@before-each
export def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
export def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

# The principal a key signs under: the fingerprint of its public half. Every
# expectation about a `.sig` file name and about a reported signer goes through
# this, because that is where a signer's identity comes from — never from what
# the key's file, or its entry in pubkeys/, happens to be called.
export def principal-of [key: path]: nothing -> string {
    open --raw $"($key).pub" | pubkey fingerprint
}
