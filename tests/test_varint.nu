use std/assert
use std/testing *

use ../nu-multiproof/_varint.nu encode-varint

# Vectors from outside this codebase: base-128 varint is specified identically
# by protobuf and LEB128, and 300 -> 0xAC 0x02 is the worked example in
# protobuf's own encoding documentation. Round-tripping our own encoder would
# prove only that it agrees with itself.
@test
def "known base-128 varint vectors" [] {
    assert equal (0 | encode-varint) 0x[00]
    assert equal (1 | encode-varint) 0x[01]
    assert equal (127 | encode-varint) 0x[7f]
    assert equal (128 | encode-varint) 0x[8001]
    assert equal (300 | encode-varint) 0x[ac02]
    assert equal (16383 | encode-varint) 0x[ff7f]
    assert equal (16384 | encode-varint) 0x[808001]
    # The UnixFS chunk size, so this one also appears in every multi-chunk CID.
    assert equal (262144 | encode-varint) 0x[808010]
}

# The encoding has no representation for a negative number. The old form fed it
# to `into binary` and returned two's-complement bytes: -1 became 0xFF, which
# any reader decodes as 127. Silently the wrong number, never an error.
@test
def "a negative input is refused, not encoded as something else" [] {
    for n in [-1 -128 -262144] {
        let outcome = try { $n | encode-varint | encode hex } catch {|e| $e.msg }
        assert ($outcome | str contains "non-negative") $"expected a refusal for ($n), got: ($outcome)"
    }
}
