# LEB128 / protobuf base-128 varint encoding. Shared by ots.nu (OTS varuint)
# and cid-v0.nu (protobuf varint) — the two encodings are byte-identical, so
# they live here once. Not named `encode`: that would shadow the `encode hex`
# builtin the callers rely on.
export def encode-varint []: int -> binary {
    mut n = $in
    mut out = 0x[]
    while $n >= 128 {
        let byte = ($n mod 128) | bits or 128
        $out = ($out | bytes add --end ($byte | into binary | bytes at 0..0))
        $n = $n // 128
    }
    $out | bytes add --end ($n | into binary | bytes at 0..0)
}
