use std/assert
use std/testing *

use ../nu-multiproof/ots.nu
use ../nu-multiproof/_ots-helpers.nu [copy-path-for check-block-header bits-to-target]

# --- Embedded test vectors ---

const HEADER = 0x[00 4f70656e54696d657374616d7073 0000 50726f6f66 00 bf89e2e884e89294]
const ZERO_HASH = 0x[0000000000000000000000000000000000000000000000000000000000000000]
const ATT_PENDING_TAG = 0x[83dfe30d2ef90c8e]
const ATT_BITCOIN_TAG = 0x[0588960d73d71901]

def build-pending-ots [--with-ops] {
    let url_bytes = "https://a.pool.opentimestamps.org" | into binary
    mut ots = ($HEADER | bytes add --end 0x[01 08] | bytes add --end $ZERO_HASH)
    if $with_ops {
        $ots = (
            $ots
            | bytes add --end 0x[f0 04 deadbeef]
            | bytes add --end 0x[08]
        )
    }
    let url_len = $url_bytes | bytes length
    let inner_len = ($url_len | into binary | bytes at 0..0)
    let outer_len = ($url_len + 1 | into binary | bytes at 0..0)
    $ots
    | bytes add --end 0x[00]
    | bytes add --end $ATT_PENDING_TAG
    | bytes add --end $outer_len
    | bytes add --end $inner_len
    | bytes add --end $url_bytes
}

def build-bitcoin-ots [] {
    # Block height 123456 as LEB128 = 0xC0C407 (3 bytes)
    $HEADER
    | bytes add --end 0x[01 08]
    | bytes add --end $ZERO_HASH
    | bytes add --end 0x[f1 02 aabb]
    | bytes add --end 0x[08]
    | bytes add --end 0x[00]
    | bytes add --end $ATT_BITCOIN_TAG
    | bytes add --end 0x[03 C0C407]
}

# --- parse-ots / info tests ---

@test
def "info pending without ops" [] {
    let ots_bytes = build-pending-ots
    $ots_bytes | save --raw --force /tmp/test_ots_pending.ots
    let result = ots info "/tmp/test_ots_pending.ots"
    assert equal $result.attestation.type "pending"
    assert equal $result.attestation.url "https://a.pool.opentimestamps.org"
    assert equal ($result.hash | str downcase) "0000000000000000000000000000000000000000000000000000000000000000"
}

@test
def "info pending with ops" [] {
    let ots_bytes = build-pending-ots --with-ops
    $ots_bytes | save --raw --force /tmp/test_ots_ops.ots
    let result = ots info "/tmp/test_ots_ops.ots"
    assert equal ($result.ops | where type == "append" | get data.0 | str upcase) "DEADBEEF"
    assert ($result.ops | any {|o| $o.type == "sha256"})
    assert equal $result.attestation.type "pending"
}

@test
def "info bitcoin attestation" [] {
    let ots_bytes = build-bitcoin-ots
    $ots_bytes | save --raw --force /tmp/test_ots_btc.ots
    let result = ots info "/tmp/test_ots_btc.ots"
    assert equal ($result.ops | where type == "prepend" | get data.0 | str upcase) "AABB"
    assert ($result.ops | any {|o| $o.type == "sha256"})
    assert equal $result.attestation.type "bitcoin"
    assert equal $result.attestation.height 123456
}

@test
def "bad header rejected" [] {
    mut bad = 0x[ff ff ff ff 00]; for _ in 1..6 { $bad = $bad | bytes add --end $bad }
    $bad | save --raw --force /tmp/test_ots_bad.ots
    let result = try { ots info "/tmp/test_ots_bad.ots"; null } catch { $in }
    assert ($result != null)
}

@test
def "fork produces error" [] {
    let forked = (
        $HEADER
        | bytes add --end 0x[01 08]
        | bytes add --end $ZERO_HASH
        | bytes add --end 0x[ff]
    )
    $forked | save --raw --force /tmp/test_ots_fork.ots
    let result = try { ots info "/tmp/test_ots_fork.ots"; null } catch { $in }
    assert ($result != null)
}

# --- Upgrade offline tests (use --response-file to bypass calendar fetch) ---

# Construct a valid bitcoin attestation payload that, when spliced at att_offset
# of a pending OTS, produces a parseable upgraded buffer.
# Format: TAG_ATTESTATION (0x00) + ATT_BITCOIN_TAG (8 bytes) + varbytes payload.
# Payload encodes the block height as varuint, length-prefixed.
def build-bitcoin-attestation-bytes [] {
    # Height 123456 as LEB128 = 0xC0C407 (3 bytes); outer varbytes len = 3.
    0x[00]
    | bytes add --end $ATT_BITCOIN_TAG
    | bytes add --end 0x[03 C0C407]
}

@test
def "upgrade splices valid response and writes atomically" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let ots_path = $"($tmp_dir)/pending.ots"
    build-pending-ots | save --raw --force $ots_path
    let original = open --raw $ots_path

    let response = $"($tmp_dir)/response.bin"
    build-bitcoin-attestation-bytes | save --raw --force $response

    ots upgrade $ots_path --response-file $response

    let upgraded = open --raw $ots_path
    assert ($upgraded != $original) "ots not modified"
    let info = ots info $ots_path
    assert equal $info.attestation.type "bitcoin"
    assert equal $info.attestation.height 123456

    rm --recursive $tmp_dir
}

@test
def "upgrade rejects malformed response and leaves original intact" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let ots_path = $"($tmp_dir)/pending.ots"
    build-pending-ots | save --raw --force $ots_path
    let original = open --raw $ots_path

    let response = $"($tmp_dir)/garbage.bin"
    0x[deadbeefcafebabe] | save --raw --force $response

    let outcome = (try {
        ots upgrade $ots_path --response-file $response
        "ok"
    } catch {|e| $"err:($e.msg)" })

    # Why both checks: error surfaces the failure, and the file content
    # check proves the atomic-rename design held — no partial write.
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    let after = open --raw $ots_path
    assert equal $after $original "original ots was modified despite validation failure"

    rm --recursive $tmp_dir
}

# Pure-function regression checks on the copy-path construction. Why split
# from stamp: the trailing-dot bug lived in string transformation, not in the
# network call — testing it directly removes the OTS_NETWORK_TEST gate.
@test
def "copy-path-for extensionless input has no trailing dot" [] {
    let result = (copy-path-for "/tmp/x/README" "/tmp/x/README.deadbeef")
    assert equal $result "/tmp/x/README.deadbeef/README"
}

@test
def "copy-path-for preserves extension" [] {
    let result = (copy-path-for "/tmp/x/data.csv" "/tmp/x/data.deadbeef")
    assert equal $result "/tmp/x/data.deadbeef/data.csv"
}

# --- verify: pure block-header checks (offline, real mainnet fixture) ---

# Bitcoin block 939896, the origin-proof anchor. Raw 80-byte header, its merkle
# root (bytes 36..67, internal order), and its block hash (display order).
const BLOCK_939896_HEADER = 0x[00000022ce95f1d363fc8ea1ecaab1cc89eeeb68af8a40a0a01500000000000000000000928035a9331c9588353ae1358ab431fd70aa9c45bf23c8bf3d6e6681ec3c142082e4ad69ccf00117fe66cc33]
const BLOCK_939896_ROOT = 0x[928035a9331c9588353ae1358ab431fd70aa9c45bf23c8bf3d6e6681ec3c1420]
const BLOCK_939896_HASH = "00000000000000000000f6eaadba82c65955a8f09dfc09aaa9b41738e721479d"

@test
def "check-block-header accepts a valid header" [] {
    let r = check-block-header $BLOCK_939896_HEADER $BLOCK_939896_ROOT $BLOCK_939896_HASH
    assert equal $r.block_hash $BLOCK_939896_HASH
    assert equal $r.merkle_root ($BLOCK_939896_ROOT | encode hex | str downcase)
    # Header timestamp is 1773003906 -> 2026-03-08 21:05:06 UTC.
    assert equal ($r.time | format date "%Y-%m-%d %H:%M:%S") "2026-03-08 21:05:06"
}

@test
def "check-block-header rejects a merkle root the block does not commit to" [] {
    let wrong_root = 0x[0000000000000000000000000000000000000000000000000000000000000000]
    let result = try { check-block-header $BLOCK_939896_HEADER $wrong_root $BLOCK_939896_HASH; null } catch { $in.msg }
    assert ($result != null)
    assert ($result | str contains "merkle root mismatch")
}

@test
def "check-block-header rejects a header that hashes to a different block" [] {
    let wrong_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    let result = try { check-block-header $BLOCK_939896_HEADER $BLOCK_939896_ROOT $wrong_hash; null } catch { $in.msg }
    assert ($result != null)
    assert ($result | str contains "not the looked-up")
}

@test
def "check-block-header rejects a wrong-length header" [] {
    let result = try { check-block-header 0x[0011 2233] $BLOCK_939896_ROOT $BLOCK_939896_HASH; null } catch { $in.msg }
    assert ($result != null)
    assert ($result | str contains "80-byte")
}

@test
def "bits-to-target decodes the compact difficulty field" [] {
    # bits 0x1701f0cc (exp 0x17, coeff 0x01f0cc) -> 32-byte big-endian target.
    let target = bits-to-target 0x1701f0cc
    assert equal ($target | bytes length) 32
    assert equal ($target | encode hex | str downcase) "00000000000000000001f0cc0000000000000000000000000000000000000000"
}

# --- Network-dependent tests ---

@test
def "verify confirms a real Bitcoin-anchored bundle" [] {
    if ($env.OTS_NETWORK_TEST? | default "false") != "true" { return }

    let bundle = "tests/../multiproofs/origin-proofs/tree-hashes.CCA016A8"
    let result = ots verify $"($bundle)/tree-hashes.ots" --file $"($bundle)/tree-hashes.csv"
    assert $result.valid
    assert equal $result.height 939896
    assert $result.content_verified
    assert (($result.sources_confirmed | length) >= 1)
}

@test
def "verify rejects a pending proof" [] {
    let ots_bytes = build-pending-ots
    $ots_bytes | save --raw --force /tmp/test_ots_verify_pending.ots
    let result = try { ots verify /tmp/test_ots_verify_pending.ots; null } catch { $in.msg }
    assert ($result != null)
    assert ($result | str contains "pending")
}

@test
def "stamp and info round-trip" [] {
    if ($env.OTS_NETWORK_TEST? | default "false") != "true" { return }

    let test_file = "/tmp/test_ots_stamp_input.txt"
    "hello opentimestamps" | save --raw --force $test_file
    ots stamp $test_file

    let result = ots info $"($test_file).ots"
    let expected_hash = open --raw $test_file | hash sha256
    assert equal ($result.hash | str downcase) $expected_hash
    assert equal $result.attestation.type "pending"
}
