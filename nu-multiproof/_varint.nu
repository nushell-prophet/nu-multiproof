# LEB128 / protobuf base-128 varint encoding. Shared by ots.nu (OTS varuint)
# and cid-v0.nu (protobuf varint) — the two encodings are byte-identical, so
# they live here once. Not named `encode`: that would shadow the `encode hex`
# builtin the callers rely on.
# Why --endian little and not the default: `into binary` defaults to NATIVE, so
# `bytes at 0..0` takes the low byte only on a little-endian host. On a
# big-endian one it takes the high byte of an i64 — every varint byte becomes
# 0x00, and every CID and every OTS varuint is silently wrong. It never
# crashes; the values are simply not what they claim. The endianness half of
# this cannot be pinned by a test on an x86/arm host, which is exactly why it
# is written explicitly rather than left to the default.
#
# Why the negative gate: `-1 | into binary` is two's complement, so the old
# form returned 0xFF for it — a byte no LEB128 reader would decode back to -1.
# The encoding has no representation for a negative number; refuse rather than
# emit bytes that mean something else. Pinned by tests/test_varint.nu.
export def encode-varint []: int -> binary {
    mut n = $in
    if $n < 0 {
        error make {msg: $"encode-varint takes a non-negative integer, got ($n)"}
    }
    mut out = 0x[]
    while $n >= 128 {
        let byte = ($n mod 128) | bits or 128
        $out = ($out | bytes add --end ($byte | into binary --endian little | bytes at 0..0))
        $n = $n // 128
    }
    $out | bytes add --end ($n | into binary --endian little | bytes at 0..0)
}
