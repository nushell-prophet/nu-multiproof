use std/assert
use std/testing *

use ../nu-multiproof/ots.nu
use ../nu-multiproof/_ots-helpers.nu [copy-path-for check-block-header bits-to-target]
use _ots-fixtures.nu [build-pending-ots build-bitcoin-ots build-calendar-response OTS_HEADER ZERO_HASH ATT_BITCOIN_TAG]

# Why a fixture, not rm at the end of test bodies: after-each runs even when
# the test throws, so a failing test does not leak its /tmp/tmp.* dir.
@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
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
        $OTS_HEADER
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
    let tmp_dir = $in.tmp_dir
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
}

@test
def "upgrade rejects malformed response and leaves original intact" [] {
    let tmp_dir = $in.tmp_dir
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

@test
def "bits-to-target refuses encodings that are not a 256-bit target" [] {
    # Measured before the guard: exp=2 returned 33 bytes, exp=0 → 35,
    # exp=255 → 255 — silently breaking the fixed-width compare that decides
    # whether a block met its target.
    for bad in [0x0200ffff 0x0000ffff 0xff00ffff 0x2100ffff] {
        let err = try { bits-to-target $bad; null } catch {|e| $e.msg }
        assert ($err != null) $"out-of-range exponent accepted: ($bad)"
        assert ($err | str contains "exponent")
    }
    # The sign flag, which read as coefficient value and inflated the target
    let neg = try { bits-to-target 0x1d80ffff; null } catch {|e| $e.msg }
    assert ($neg != null) "the negative bit was accepted"
    assert ($neg | str contains "negative bit")

    # powLimit itself decodes, and every real header is at least this hard
    assert equal (bits-to-target 0x1d00ffff | bytes length) 32
}

@test
def "check-block-header rejects a header below mainnet minimum difficulty" [] {
    # Hand-built, not mined, and not from any chain: version 1, zero
    # prev-hash, an arbitrary merkle root, regtest bits 0x207fffff (target
    # ~2^255, so roughly every other nonce wins) and nonce 4, which does. The
    # audit's PoC shape — before the floor this returned a full result record,
    # i.e. `ots verify` would have called a forged block "verified
    # independently" on a compromised explorer's word, with zero work behind
    # the header.
    let root = "forged" | hash sha256 --binary
    let header = 0x[01000000]
        | bytes add --end (0..<32 | each { 0x[00] } | bytes collect)
        | bytes add --end $root
        | bytes add --end 0x[00000000]
        | bytes add --end 0x[ffff7f20]
        | bytes add --end 0x[04000000]
    assert equal ($header | bytes length) 80
    let block_hash = $header | hash sha256 | decode hex | hash sha256 | decode hex
        | bytes reverse | encode hex | str downcase

    let err = try { check-block-header $header $root $block_hash; null } catch {|e| $e.msg }
    assert ($err != null) "a zero-work regtest header was accepted"
    # Naming the difficulty message, not just "some error": the block-hash and
    # merkle-root checks run first and have their own wording, so this pins
    # that the header got past them and died on the floor alone.
    assert ($err | str contains "below the Bitcoin mainnet minimum")
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
def "verify reports content mismatch without touching the network" [] {
    # A wrong --file is caught before any explorer lookup: verify computes the
    # file hash, sees it differs from the proof commitment, and returns
    # valid:false early. So this exercises the real command's parse ->
    # content-check -> early-return path against a committed bitcoin bundle
    # with zero network dependence — no OTS_NETWORK_TEST gate.
    let bundle = "tests/../multiproofs/origin-proofs/tree-hashes.CCA016A8"
    let result = ots verify $"($bundle)/tree-hashes.ots" --file "tests/test_ots.nu"
    assert equal $result.valid false
    assert equal $result.content_verified false
    assert ($result.error | str contains "content mismatch")
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

# --- stamp: what gets written, and what does not ---

@test
def "stamp writes a proof its own parser can read" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    build-calendar-response | save --raw --force $"($tmp_dir)/response.bin"

    let result = (ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/response.bin")

    let parsed = (ots info $result.ots)
    assert equal $parsed.attestation.type "pending"
    assert equal $parsed.hash (open --raw $file | hash sha256)
    # the frozen copy is the content that was stamped
    assert equal (open --raw $result.copy) "hello world"
}

# The failure this guard exists for: only the HTTP status was checked, so a
# calendar answering 200 with a garbage body produced a success record, exit 0,
# and an .ots that `info` cannot read — while the digest had already reached
# the calendar, so the proof is unrecoverable.
@test
def "stamp writes no bundle when the calendar body is not a timestamp" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    "x" | save --raw --force $"($tmp_dir)/garbage.bin"

    let outcome = (try {
        ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/garbage.bin"
        "ok"
    } catch {|e| $e.msg })
    assert ($outcome | str contains "no bundle was written") $"expected a refusal, got: ($outcome)"
    # no bundle directory, no frozen copy, no proof — the rejected bytes are
    # a loose file, never something a verifier would read as a bundle
    let left = (ls --all $tmp_dir | get name | each { path basename } | sort)
    assert equal ($left | where {|f| not ($f | str contains ".rejected-") }) ["doc.txt" "garbage.bin"]
}

# The digest was already submitted and the nonce that binds it to this file
# lives only in the failing run, so refusing to write anything at all loses the
# submission exactly as the unreadable .ots did. The assembled bytes are kept
# instead — they carry the nonce, and the reference `ots` CLI reads constructs
# this parser refuses.
@test
def "a rejected calendar response is kept, nonce and all" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    # A fork: legal OpenTimestamps, refused by this parser — the case where
    # dropping the bytes would lose a submission the ots CLI could still read.
    0x[ff] | save --raw --force $"($tmp_dir)/forked.bin"

    try { ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/forked.bin" }

    let rejected = (ls --all $tmp_dir | get name | where {|f| $f | str contains ".rejected-" })
    assert equal ($rejected | length) 1
    let bytes = (open --raw ($rejected | first) | into binary)
    # header(31) version(1) sha256-op(1) hash(32) append-op(1) len(1) nonce(16)
    # sha256-op(1) response(1) — the nonce is what makes these bytes worth
    # keeping, so pin where it sits.
    assert equal ($bytes | bytes at 33..<65) (open --raw $file | hash sha256 | decode hex)
    assert equal ($bytes | bytes at 65..<67) 0x[f010]
    assert equal ($bytes | bytes length) 85
}

# Validation runs before the archival rename, so a bad response cannot cost the
# proof that is already there.
@test
def "a rejected stamp leaves the previous proof in place" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    build-calendar-response | save --raw --force $"($tmp_dir)/response.bin"
    "x" | save --raw --force $"($tmp_dir)/garbage.bin"

    let first = (ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/response.bin")
    let before = (open --raw $first.ots | into binary)

    try { ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/garbage.bin" }

    assert equal (open --raw $first.ots | into binary) $before
    assert equal (ls --all $first.dir | get name | each { path basename } | sort) ["doc.ots" "doc.txt"]
}

# Re-stamping the same content reuses the bundle dir and archives the incumbent
# proof. The archive name was only <stem>.<YYYYmmdd-HHMMSS>.ots and `mv`
# overwrites, so two stamps inside one second collided: three proofs, two files,
# every run exit 0 and no "Archived previous" line for the one that vanished.
@test
def "rapid re-stamps each keep their own proof" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    build-calendar-response | save --raw --force $"($tmp_dir)/response.bin"

    let made = 1..3 | each {
        let result = (ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/response.bin")
        {dir: $result.dir hash: (open --raw $result.ots | hash sha256)}
    }
    # Each run draws a fresh nonce, so these are three independent proofs
    assert equal ($made | get hash | uniq | length) 3

    let bundle = $made.0.dir
    let on_disk = (ls --all $bundle | get name | where {|f| $f | str ends-with ".ots"})
    assert equal ($on_disk | length) 3 "an archived proof was overwritten"
    assert equal ($on_disk | each { open --raw $in | hash sha256 } | sort) ($made | get hash | sort)

    # Why assert the naming rule and not just the count: three stamps could
    # straddle a second boundary, and then distinct timestamps would carry the
    # test on their own. The archive name binds to the archived proof's own
    # bytes, which is what makes a same-second collision impossible rather than
    # unlikely.
    for archived in ($on_disk | where {|f| ($f | path basename) != "doc.ots"}) {
        let tag = (open --raw $archived | hash sha256 | str substring 0..<8)
        assert ($archived | path basename | str ends-with $"-($tag).ots") $"archive name is not bound to its bytes: ($archived)"
    }
}
