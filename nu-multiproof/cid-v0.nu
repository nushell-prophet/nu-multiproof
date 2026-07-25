# Pure Nushell CID v0 computation for single-chunk data (< 256 KB).
# Reproduces: ipfs add --only-hash --quieter --cid-version=0 --raw-leaves=false --hash=sha2-256

use _varint.nu encode-varint

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Exported: tree-hashes.nu both size-checks against it and builds the ipfs
# `--chunker=size-…` flag from it, so the pure-nu CID and the ipfs CLI cannot
# drift apart on the chunk size.
export const MAX_SINGLE_CHUNK = 262144

# Wrap content in UnixFS dag-pb protobuf (single-chunk leaf node, no links)
def unixfs-dag-pb []: binary -> binary {
    let content = $in
    let n = $content | bytes length
    if $n > $MAX_SINGLE_CHUNK {
        error make {msg: $"content exceeds single chunk: ($n) > ($MAX_SINGLE_CHUNK)"}
    }
    let nv = $n | encode-varint
    # UnixFS Data: type=File(2), data=content (omitted when empty), filesize=n
    let data_field = if $n > 0 { 0x[12] | bytes add --end $nv | bytes add --end $content } else { 0x[] }
    let unixfs = (0x[08 02] | bytes add --end $data_field | bytes add --end 0x[18] | bytes add --end $nv)
    # dag-pb PBNode: data=unixfs
    let ulen = ($unixfs | bytes length) | encode-varint
    0x[0a] | bytes add --end $ulen | bytes add --end $unixfs
}

# Base58btc encoding
def base58-encode []: binary -> string {
    let hex = $in | encode hex
    let pair_count = ($hex | str length) // 2
    let byte_list = (
        0..<$pair_count | each {|i|
            let s = $i * 2
            let hex_pair = $hex | str substring ($s)..<($s + 2)
            $"0x($hex_pair)" | into int
        }
    )
    let chars = $BASE58_ALPHABET | split chars
    let leading = $byte_list | take while { $in == 0 } | length
    mut nums = $byte_list
    mut digits = []
    while not ($nums | is-empty) {
        mut carry = 0
        mut quotient = []
        for b in $nums {
            let val = $carry * 256 + $b
            $quotient ++= [($val // 58)]
            $carry = $val mod 58
        }
        $digits = [$carry ...$digits]
        $nums = ($quotient | skip while { $in == 0 })
    }
    let ones = (0..<$leading | each { '1' } | str join)
    let encoded = ($digits | each {|d| $chars | get $d } | str join)
    $"($ones)($encoded)"
}

# Compute CID v0 from raw binary content in pure Nushell (must be ≤ 256 KB)
#
# Why string input is accepted: `open --raw f` collects to a *string* whenever
# the file's bytes are valid UTF-8, so `open --raw README.md | cid-v0` — the
# main way to use this command — hit a bare `Type mismatch` on a binary-only
# signature. `into binary` on that string yields the same bytes back, so this
# widens the accepted type without changing what gets hashed.
@example "CID v0 of in-memory bytes" { "hello" | into binary | cid-v0 } --result "QmWfVY9y3xjsixTgbd9AorQxH7VtMpzfx2HaWtsoUYecaX"
@example "same bytes arriving as a string, as `open --raw` returns them" { "hello" | cid-v0 } --result "QmWfVY9y3xjsixTgbd9AorQxH7VtMpzfx2HaWtsoUYecaX"
export def main []: [binary -> string, string -> string] {
    let hash_bytes = $in | into binary | unixfs-dag-pb | hash sha256 | decode hex
    0x[1220] | bytes add --end $hash_bytes | base58-encode
}
