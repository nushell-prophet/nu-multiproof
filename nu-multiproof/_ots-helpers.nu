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

# Bitcoin mainnet's `powLimit` in compact form: the largest target the network
# ever allows, i.e. difficulty 1. Every mainnet header from genesis on encodes
# this or something harder.
export const POW_LIMIT_BITS = 0x1d00ffff

# Decode Bitcoin's compact "bits" field into a 32-byte big-endian target.
# Why bytes, not int: a real mainnet target is ~2^216, far past Nushell's i64,
# so the whole computation and comparison stay in fixed-width byte arrays.
export def bits-to-target [bits: int]: nothing -> binary {
    let exp = $bits // (256 ** 3)
    let coeff = $bits mod (256 ** 3)
    let bits_hex = $bits | into binary --endian big | bytes at 4..7 | encode hex | str lowercase
    # Fail closed outside the range that encodes a 256-bit target. Measured
    # before this guard: exp=2 returned 33 bytes, exp=0 → 35, exp=255 → 255,
    # so check-block-header's "both sides are fixed 32-byte" comparison was
    # comparing hex strings of different length — correct by luck below 3,
    # neither correct nor fail-closed above 32. Bitcoin Core normalizes exp < 3
    # by shifting the coefficient down; we reject instead, per this repo's
    # reject-never-normalize rule, and no mainnet header has ever used it.
    if $exp < 3 or $exp > 32 {
        error make {msg: $"compact target 0x($bits_hex) has exponent ($exp), outside 3..32 — it does not encode a 256-bit target"}
    }
    # Bitcoin's sign flag. Ignored, it reads as coefficient value and inflates
    # the target ~128x, i.e. makes the work requirement that much cheaper.
    if $coeff >= 0x800000 {
        error make {msg: $"compact target 0x($bits_hex) sets the negative bit \(0x00800000\)"}
    }
    let coeff_be = $coeff | into binary --endian big | bytes at 5..7
    (zero-bytes (32 - $exp)) | bytes add --end $coeff_be | bytes add --end (zero-bytes ($exp - 3))
}

# Self-verify a raw 80-byte Bitcoin block header with no network access:
#   1. double-SHA256(header), reversed, equals `claimed_hash` (display order)
#   2. the header's merkle-root field equals `expected_root` (internal order)
#   3. `bits` decodes to a target no easier than mainnet's powLimit, and the
#      block hash meets it
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
    let target = bits-to-target $bits
    # Why a floor before the target compare, and why it is only a floor: `bits`
    # travels inside the header being checked, so "hash <= target(bits)" on its
    # own is self-referential. Measured: a header carrying regtest bits
    # (0x207fffff) and nonce 0 passed with zero work behind it. Refusing any
    # target easier than mainnet's powLimit puts ~2^32 hashes between a forger
    # and a header this accepts. That is minutes on a GPU, not a security
    # boundary — a real bound needs the difficulty expected AT this height, or
    # a pinned block hash, and neither the proof nor the explorer answer
    # carries data we could check that against. README says exactly this much.
    if ($target | encode hex) > (bits-to-target $POW_LIMIT_BITS | encode hex) {
        error make {msg: $"header claims difficulty below the Bitcoin mainnet minimum: bits ($bits) decode to an easier target than powLimit — not a mainnet block header"}
    }
    # Why hex string compare: both sides are fixed 32-byte big-endian, so
    # lexical order matches numeric order — and it sidesteps the i64 overflow.
    if ($h256d | bytes reverse | encode hex) > ($target | encode hex) {
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
