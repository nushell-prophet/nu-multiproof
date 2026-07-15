# Internal helpers for ots.nu. Not part of the public nu-multiproof API
# (mod.nu does not re-export this file). Lives separately so the pure
# extensionless-input case can be tested without invoking `stamp` and the
# calendar network call.

# Bundle copy-path for an input file. Pure; extracted from `stamp`.
# Why no trailing dot: extensionless input ("README") was producing "README."
# because `($stem).($ext)` collapsed to "README." when `$ext` was empty.
export def copy-path-for [file: path, bundle_dir: path]: nothing -> string {
    let parsed = $file | path parse
    if ($parsed.extension | is-empty) {
        $"($bundle_dir)/($parsed.stem)"
    } else {
        $"($bundle_dir)/($parsed.stem).($parsed.extension)"
    }
}

# Big-endian binary of `n` zero bytes (0x[] when n <= 0).
export def zero-bytes [n: int]: nothing -> binary {
    if $n <= 0 { 0x[] } else { 0..<$n | each { 0x[00] } | bytes collect }
}

# Decode Bitcoin's compact "bits" field into a 32-byte big-endian target.
# Why bytes, not int: a real mainnet target is ~2^216, far past Nushell's i64,
# so the whole computation and comparison stay in fixed-width byte arrays.
export def bits-to-target [bits: int]: nothing -> binary {
    let exp = $bits // (256 ** 3)
    let coeff = $bits mod (256 ** 3)
    let coeff_be = $coeff | into binary --endian big | bytes at 5..7
    (zero-bytes (32 - $exp)) | bytes add --end $coeff_be | bytes add --end (zero-bytes ($exp - 3))
}

# Self-verify a raw 80-byte Bitcoin block header with no network access:
#   1. double-SHA256(header), reversed, equals `claimed_hash` (display order)
#   2. the header's merkle-root field equals `expected_root` (internal order)
#   3. the block hash meets the proof-of-work target encoded in `bits`
# Why fail-fast (error on any mismatch): a header that fails any check is not
# evidence of anything — the caller must not proceed on a partial match.
export def check-block-header [
    header: binary          # raw 80-byte header
    expected_root: binary   # merkle root the OTS commitment replays to (internal order)
    claimed_hash: string    # block hash the height lookup returned (display hex)
]: nothing -> record {
    if ($header | bytes length) != 80 {
        error make {msg: $"expected an 80-byte header, got ($header | bytes length) bytes"}
    }
    let h256d = $header | hash sha256 | decode hex | hash sha256 | decode hex
    let block_hash = $h256d | bytes reverse | encode hex | str lowercase
    if $block_hash != ($claimed_hash | str lowercase) {
        error make {msg: $"header hashes to ($block_hash), not the looked-up ($claimed_hash)"}
    }
    let header_root = $header | bytes at 36..67
    if $header_root != $expected_root {
        error make {msg: $"merkle root mismatch: header commits to ($header_root | encode hex | str lowercase), proof replays to ($expected_root | encode hex | str lowercase)"}
    }
    let bits = $header | bytes at 72..75 | into int --endian little
    # Why hex string compare: both sides are fixed 32-byte big-endian, so
    # lexical order matches numeric order — and it sidesteps the i64 overflow.
    if ($h256d | bytes reverse | encode hex) > (bits-to-target $bits | encode hex) {
        error make {msg: $"block hash ($block_hash) does not meet its proof-of-work target"}
    }
    let time = $header | bytes at 68..71 | into int --endian little
    {
        block_hash: $block_hash
        merkle_root: ($header_root | encode hex | str lowercase)
        time: ($time * 1_000_000_000 | into datetime | date to-timezone UTC)
        bits: $bits
    }
}
