# Internal helpers for ots.nu. Not part of the public nu-multiproof API
# (mod.nu does not re-export this file). Lives separately so the pure
# extensionless-input case can be tested without invoking `stamp` and the
# calendar network call.

# Bundle copy-path for an input file. Pure; extracted from `stamp`.
# Why no trailing dot: extensionless input ("README") was producing "README."
# because `($stem).($ext)` collapsed to "README." when `$ext` was empty.
export def copy-path-for [file: path bundle_dir: path]: nothing -> string {
    let parsed = $file | path parse
    if ($parsed.extension | is-empty) {
        $"($bundle_dir)/($parsed.stem)"
    } else {
        $"($bundle_dir)/($parsed.stem).($parsed.extension)"
    }
}

# The explorer's answer to /block/<hash>/header, admitted only if it really is
# that block's header. Everything here is about the source, not the proof: the
# block hash was already cross-checked across explorers before the header was
# fetched, so an answer that is not hex, not 80 bytes, or hashes to something
# else can only be this explorer's fault. Each check throws naming the
# explorer — none is a verdict about the proof. Pinned by tests/test_ots.nu
# "a corrupted header blames the explorer, not the proof".
export def check-fetched-header [
    src: string # explorer base URL, named in every refusal
    block_hash: string # cross-checked block hash (display hex)
    header_hex: string # the explorer's response body
]: nothing -> binary {
    let bytes = try { $header_hex | decode hex } catch {
        error make {msg: $"explorer ($src) answered with a block header that is not hex — cannot verify"}
    }
    if ($bytes | bytes length) != 80 {
        error make {msg: $"explorer ($src) answered with ($bytes | bytes length) bytes where a block header is 80 — cannot verify"}
    }
    let hashes_to = $bytes | hash sha256 | decode hex | hash sha256 | decode hex | bytes reverse | encode hex | str lowercase
    if $hashes_to != ($block_hash | str lowercase) {
        error make {msg: $"explorer ($src) answered with a header that hashes to ($hashes_to), not the cross-checked ($block_hash) — cannot verify"}
    }
    $bytes
}

# Self-verify a raw 80-byte Bitcoin block header with no network access:
#   1. double-SHA256(header), reversed, equals `claimed_hash` (display order)
#   2. the header's merkle-root field equals `expected_root` (internal order)
# Why no proof-of-work check: `bits` travels inside the header being checked,
# so "hash <= target(bits)" is self-referential. A floor at mainnet's powLimit
# used to sit here; it only bought ~2^32 hashes (minutes on a GPU) against an
# attacker who already controls every explorer that answered, and it cost 91
# lines. A real bound needs the difficulty expected AT this height, or a pinned
# block hash, and neither the proof nor the explorer answer carries data we
# could check that against. The defence is the cross-check in `ots verify`:
# independent explorers must agree on the height -> hash mapping.
# Why fail-fast (error on any mismatch): a header that fails any check is not
# evidence of anything — the caller must not proceed on a partial match.
export def check-block-header [
    header: binary # raw 80-byte header
    expected_root: binary # merkle root the OTS commitment replays to (internal order)
    claimed_hash: string # block hash the height lookup returned (display hex)
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
    let time = $header | bytes at 68..71 | into int --endian little
    {
        block_hash: $block_hash
        merkle_root: ($header_root | encode hex | str lowercase)
        time: ($time * 1_000_000_000 | into datetime | date to-timezone UTC)
        bits: $bits
    }
}
