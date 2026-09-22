use std/assert
use std/testing *

use ../nu-multiproof/ots.nu
use ../nu-multiproof/_ots-helpers.nu [ copy-path-for bundle-dir-for freeze-bundle write-frozen-copy check-block-header check-fetched-header ]
use _ots-fixtures.nu [ build-pending-ots build-bitcoin-ots build-calendar-response OTS_HEADER ZERO_HASH ATT_BITCOIN_TAG ]

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
    assert equal ($result.hash | str lowercase) "0000000000000000000000000000000000000000000000000000000000000000"
}

@test
def "info pending with ops" [] {
    let ots_bytes = build-pending-ots --with-ops
    $ots_bytes | save --raw --force /tmp/test_ots_ops.ots
    let result = ots info "/tmp/test_ots_ops.ots"
    assert equal ($result.ops | where type == "append" | get data.0 | str upcase) "DEADBEEF"
    assert ($result.ops | any {|o| $o.type == "sha256" })
    assert equal $result.attestation.type "pending"
}

@test
def "info bitcoin attestation" [] {
    let ots_bytes = build-bitcoin-ots
    $ots_bytes | save --raw --force /tmp/test_ots_btc.ots
    let result = ots info "/tmp/test_ots_btc.ots"
    assert equal ($result.ops | where type == "prepend" | get data.0 | str upcase) "AABB"
    assert ($result.ops | any {|o| $o.type == "sha256" })
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

# A short all-ASCII .ots is read back by `open --raw` as a *string*, not binary.
# Before the `into binary` at the read sites this died with a bare `Type
# mismatch`, hiding the real reason the file is not a proof.
@test
def "ascii file rejected as bad header, not type mismatch" [] {
    let tmp_dir = $in.tmp_dir
    let ots_path = $"($tmp_dir)/ascii.ots"
    "not a proof" | save --raw --force $ots_path
    let result = try { ots info $ots_path; null } catch { $in }
    assert ($result != null)
    assert str contains $result.msg "bad header magic"
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

    let outcome = (
        try {
            ots upgrade $ots_path --response-file $response
            "ok"
        } catch {|e| $"err:($e.msg)" }
    )

    # Why both checks: error surfaces the failure, and the file content
    # check proves the atomic-rename design held — no partial write.
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    let after = open --raw $ots_path
    assert equal $after $original "original ots was modified despite validation failure"
}

# Pure-function regression checks on the copy-path construction. Why split
# from stamp: the trailing-dot bug lived in string transformation, not in the
# network call — testing it directly needs no network at all.
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
    assert equal $r.merkle_root ($BLOCK_939896_ROOT | encode hex | str lowercase)
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
def "check-block-header does not bound the work behind a header" [] {
    # Hand-built, not mined, and not from any chain: version 1, zero prev-hash,
    # an arbitrary merkle root, regtest bits 0x207fffff and nonce 4. This is
    # the honest statement of the contract: `check-block-header` binds a header
    # to a merkle root and to its own double-SHA256, and claims nothing about
    # the work behind it. What stops a forged header is `ots verify`'s
    # requirement that independent explorers agree on the height -> hash
    # mapping; a powLimit floor would buy only ~2^32 hashes.
    # Pinned so a future reader does not mistake acceptance for a work check.
    let root = "forged" | hash sha256 --binary
    let header = 0x[01000000]
        | bytes add --end (0..<32 | each { 0x[00] } | bytes collect)
        | bytes add --end $root
        | bytes add --end 0x[00000000]
        | bytes add --end 0x[ffff7f20]
        | bytes add --end 0x[04000000]
    assert equal ($header | bytes length) 80
    let block_hash = $header | hash sha256 | decode hex | hash sha256 | decode hex
        | bytes reverse | encode hex | str lowercase

    let r = check-block-header $header $root $block_hash
    assert equal $r.block_hash $block_hash
    assert equal $r.merkle_root ($root | encode hex | str lowercase)
}

# The explorer serving the header would otherwise hold a one-request veto: a
# header with one flipped byte, inside verify's `try`, reads as "this proof does
# not match Bitcoin" — `valid: false`, `--fail` exit non-zero — for a proof that
# verifies fine with the source order swapped. The block hash was cross-checked
# by --min-sources explorers before the header fetch, so a header-vs-hash
# mismatch can only be the explorer's fault: an outage, not a verdict.
@test
def "a corrupted header blames the explorer, not the proof" [] {
    let flipped = 0x[ff] | bytes add --end ($BLOCK_939896_HEADER | bytes at 1..79)
    let outcome = try {
        check-fetched-header "https://explorer.example/api" $BLOCK_939896_HASH ($flipped | encode hex)
        "accepted"
    } catch {|e| $e.msg }
    assert ($outcome | str contains "explorer https://explorer.example/api") $"expected the explorer blamed, got: ($outcome)"
    assert ($outcome | str contains "cannot verify") $"expected an operational refusal, got: ($outcome)"
}

@test
def "check-fetched-header hands back the bytes of a genuine header" [] {
    let bytes = check-fetched-header "https://explorer.example/api" $BLOCK_939896_HASH ($BLOCK_939896_HEADER | encode hex)
    assert equal $bytes $BLOCK_939896_HEADER
}

# --- Bitcoin-anchored bundle, without the network ---
#
# Tests that need a live network live in tests-network/, which nutest does not
# discover.

@test
def "verify reports content mismatch without touching the network" [] {
    # A wrong --file is caught before any explorer lookup: verify computes the
    # file hash, sees it differs from the proof commitment, and returns
    # valid:false early. So this exercises the real command's parse ->
    # content-check -> early-return path against a committed bitcoin bundle
    # with zero network dependence.
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

# --- format conformance: bytes a lenient parser reads past ---
#
# Every proof below is built by hand, not by this repo's writer. Round-tripping
# the writer proves self-consistency; these pin conformance, which is what
# "the reference client can read what we wrote" actually means.

@test
def "a proof with bytes after the attestation is refused" [] {
    let tmp_dir = $in.tmp_dir
    let path = $"($tmp_dir)/trailing.ots"
    # 4 junk bytes after a well-formed bitcoin attestation. parse-timestamp
    # returns at the first attestation, so without an end-of-buffer assert this
    # parsed clean here and was TrailingGarbageError to the reference
    # deserializer — and `stamp`/`upgrade` validate by calling this parser, so
    # the validate-before-write guard passed it too.
    build-bitcoin-ots | bytes add --end 0x[deadbeef] | save --raw --force $path

    let outcome = try { ots info $path; "accepted" } catch {|e| $e.msg }
    assert ($outcome | str contains "the proof ends at") $"expected a refusal, got: ($outcome)"
}

@test
def "an attestation payload with trailing bytes is refused" [] {
    let tmp_dir = $in.tmp_dir
    let path = $"($tmp_dir)/fat-payload.ots"
    # Payload length 5: the 3-byte height varint for 123456, then 2 junk bytes
    # inside the attestation's own length-prefixed field. The reference wraps
    # each payload in its own context and ends it with assert_eof.
    $OTS_HEADER
    | bytes add --end 0x[01 08]
    | bytes add --end $ZERO_HASH
    | bytes add --end 0x[08]
    | bytes add --end 0x[00]
    | bytes add --end $ATT_BITCOIN_TAG
    | bytes add --end 0x[05 C0C407 ffff]
    | save --raw --force $path

    let outcome = try { ots info $path; "accepted" } catch {|e| $e.msg }
    assert ($outcome | str contains "trailing bytes inside") $"expected a refusal, got: ($outcome)"
}

@test
def "a pending attestation payload with trailing bytes is refused" [] {
    let tmp_dir = $in.tmp_dir
    let path = $"($tmp_dir)/fat-pending.ots"
    # The pending branch of the same rule. Two separate asserts in the parser,
    # so two tests: mutating the pending one off left the bitcoin test green.
    let uri = "https://a.calendar.opentimestamps.org" | into binary
    let uri_len = $uri | bytes length
    $OTS_HEADER
    | bytes add --end 0x[01 08]
    | bytes add --end $ZERO_HASH
    | bytes add --end 0x[08]
    | bytes add --end 0x[00]
    | bytes add --end 0x[83dfe30d2ef90c8e]
    | bytes add --end ($uri_len + 3 | into binary --endian little | bytes at 0..0)
    | bytes add --end ($uri_len | into binary --endian little | bytes at 0..0)
    | bytes add --end $uri
    | bytes add --end 0x[ffff]
    | save --raw --force $path

    let outcome = try { ots info $path; "accepted" } catch {|e| $e.msg }
    assert ($outcome | str contains "trailing bytes inside the pending") $"expected a refusal, got: ($outcome)"
}

@test
def "a pending URI holding characters the format forbids is refused" [] {
    let tmp_dir = $in.tmp_dir
    let path = $"($tmp_dir)/bad-uri.ots"
    # A URI carrying bytes outside the reference's ALLOWED_URI_CHARS. Decoding
    # it with `decode utf-8` first would have normalized them away, so `info`
    # printed a URL that was not what the file held — and that string is what
    # `upgrade` contacts.
    let uri = 0x[68747470733a2f2f61 2e 63616c656e6461722e6f70656e74696d657374616d70732e6f7267 3f 78]
    let uri_len = $uri | bytes length
    $OTS_HEADER
    | bytes add --end 0x[01 08]
    | bytes add --end $ZERO_HASH
    | bytes add --end 0x[08]
    | bytes add --end 0x[00]
    | bytes add --end 0x[83dfe30d2ef90c8e]
    | bytes add --end ($uri_len + 1 | into binary --endian little | bytes at 0..0)
    | bytes add --end ($uri_len | into binary --endian little | bytes at 0..0)
    | bytes add --end $uri
    | save --raw --force $path

    let outcome = try { ots info $path; "accepted" } catch {|e| $e.msg }
    assert ($outcome | str contains "characters the format does not allow") $"expected a refusal, got: ($outcome)"
}

# The reference client caps a pending URI at MAX_URI_LENGTH=1000 bytes
# (opentimestamps-client notary.py). Deleting the length clause kept the suite
# green: the fixtures' builder writes one-byte varint lengths, so it cannot
# even express a URI this long. The two-byte LEB128 lengths are hand-built —
# 1001 is E9 07 under a 1003-byte payload EB 07; 1000 is E8 07 under EA 07.
@test
def "the pending URI length cap is the reference client 1000 bytes" [] {
    let tmp_dir = $in.tmp_dir
    # Refused: 1001 bytes, every one of them in the allowed charset, so only
    # the length clause can be what refuses this.
    let over = $"($tmp_dir)/uri-1001.ots"
    $OTS_HEADER
    | bytes add --end 0x[01 08]
    | bytes add --end $ZERO_HASH
    | bytes add --end 0x[08]
    | bytes add --end 0x[00]
    | bytes add --end 0x[83dfe30d2ef90c8e]
    | bytes add --end 0x[EB 07]
    | bytes add --end 0x[E9 07]
    | bytes add --end ("" | fill --character "a" --width 1001 | into binary)
    | save --raw --force $over
    let outcome = try { ots info $over; "accepted" } catch {|e| $e.msg }
    assert ($outcome | str contains "exceeds 1000 bytes") $"expected the length refusal, got: ($outcome)"

    # Accepted: exactly 1000 — the reference cap is >, not >=.
    let at_cap = $"($tmp_dir)/uri-1000.ots"
    $OTS_HEADER
    | bytes add --end 0x[01 08]
    | bytes add --end $ZERO_HASH
    | bytes add --end 0x[08]
    | bytes add --end 0x[00]
    | bytes add --end 0x[83dfe30d2ef90c8e]
    | bytes add --end 0x[EA 07]
    | bytes add --end 0x[E8 07]
    | bytes add --end ("" | fill --character "a" --width 1000 | into binary)
    | save --raw --force $at_cap
    assert equal (ots info $at_cap | get attestation.url) ("" | fill --character "a" --width 1000)
}

# --- upgrade: the URL in the file is attacker input ---

@test
def "upgrade refuses a calendar URL the proof chose" [] {
    let tmp_dir = $in.tmp_dir
    let path = $"($tmp_dir)/evil.ots"
    # The reproduction from the audit: this made the repo GET
    # /SECRET-EXFIL-PATH/timestamp/<digest> on a host of the proof's choosing,
    # while telling the user only "not yet confirmed by Bitcoin". The host
    # learns the digest of private content, out of band and unlogged.
    build-pending-ots --url "http://127.0.0.1:18777/SECRET-EXFIL-PATH" | save --raw --force $path

    let outcome = try { ots upgrade $path; "fetched" } catch {|e| $e.msg }
    assert ($outcome | str contains "refusing to contact") $"expected a refusal, got: ($outcome)"
}

# One hostile URL only exercises one clause of the gate. `127.0.0.1` fails on
# the scheme alone, so with just that vector the host, port, userinfo, path,
# query and fragment checks could all be deleted and the suite stayed green.
# Each row below is refused by exactly one clause.
@test
def "every clause of the calendar gate refuses on its own" [] {
    let tmp_dir = $in.tmp_dir
    let hostile = [
        [url clause refused_by];
        ["https://evil.com" "host" "refusing to contact"]
        ["https://calendar.opentimestamps.org.attacker.net" "suffix" "refusing to contact"]
        ["https://calendar.opentimestamps.org" "label" "refusing to contact"]
        ["http://a.calendar.opentimestamps.org" "scheme" "refusing to contact"]
        ["https://a.calendar.opentimestamps.org:8443" "port" "refusing to contact"]
        ["https://a.calendar.opentimestamps.org/timestamp" "path" "refusing to contact"]
        # Userinfo cannot survive the URI charset, so it is refused a step
        # earlier and never reaches the trust gate. The gate keeps its own
        # userinfo clause anyway: it states the whole UrlWhitelist rule, and a
        # trust boundary that only holds because a *format* validator ran first
        # is one refactor away from not holding.
        ["https://u:p@a.calendar.opentimestamps.org" "userinfo" "characters the format does not allow"]
    ]
    for row in $hostile {
        let path = $"($tmp_dir)/(random uuid).ots"
        build-pending-ots --url $row.url | save --raw --force $path
        let outcome = try { ots upgrade $path; "fetched" } catch {|e| $e.msg }
        assert ($outcome | str contains $row.refused_by) $"($row.clause): ($row.url) was not refused as expected, got: ($outcome)"
    }
}

# --calendar is the operator's deliberate override of that gate, and it is the
# one path that sends a digest off the machine. Unreachable localhost, so the
# assertion is about which failure comes out: anything but the allowlist.
# Name does not start with "--": nutest builds a call from the test name, and
# a leading "--" parses there as a flag, breaking the whole suite file.
@test
def "the calendar flag overrides the allowlist" [] {
    let tmp_dir = $in.tmp_dir
    let path = $"($tmp_dir)/pending.ots"
    build-pending-ots --url "https://evil.com" | save --raw --force $path

    let refused = try { ots upgrade $path; "fetched" } catch {|e| $e.msg }
    assert ($refused | str contains "refusing to contact")

    let overridden = try { ots upgrade $path --calendar "http://127.0.0.1:1"; "fetched" } catch {|e| $e.msg }
    assert (not ($overridden | str contains "refusing to contact")) $"--calendar did not bypass the gate: ($overridden)"
}

# The charset check claims to be the reference client's ALLOWED_URI_CHARS
# (notary.py). Nothing in this repo carries that file, so pin the set itself:
# a comment naming an absent source is not a check.
@test
def "the accepted URI charset is exactly the reference set" [] {
    let tmp_dir = $in.tmp_dir
    let reference = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:"
    # Accepted: every reference character, in one URI.
    let ok_path = $"($tmp_dir)/charset-ok.ots"
    build-pending-ots --url $reference | save --raw --force $ok_path
    assert equal (ots info $ok_path | get attestation.url) $reference

    # Refused: everything else that a URL could plausibly carry.
    for c in ["%" "@" "#" "?" "\\" " " "~" "+" "=" "&" "[" "]" "," ";"] {
        let path = $"($tmp_dir)/(random uuid).ots"
        build-pending-ots --url $"https://a.calendar.opentimestamps.org($c)x" | save --raw --force $path
        let outcome = try { ots info $path; "accepted" } catch {|e| $e.msg }
        assert ($outcome | str contains "characters the format does not allow") $"($c) was accepted, got: ($outcome)"
    }
}

# --min-sources 0 would mean "assert validity with no explorer agreeing at
# all", which is not a weaker check but no check. The floor is refused before
# anything is read, so this is the one part of --min-sources that pins offline;
# the rest needs live explorers and lives in tests-network/.
@test
def "a min-sources floor below one is refused" [] {
    let tmp_dir = $in.tmp_dir
    let path = $"($tmp_dir)/btc.ots"
    build-bitcoin-ots | save --raw --force $path
    for n in [0 -1] {
        let outcome = try { ots verify $path --min-sources $n; "verified" } catch {|e| $e.msg }
        assert ($outcome | str contains "at least 1") $"--min-sources ($n) was accepted, got: ($outcome)"
    }
}

# The other half — that the allowlist still admits the calendar the live pool
# actually names — cannot be asserted offline without making the fetch it
# guards. It is pinned in tests-network/test_ots_network.nu instead.

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

# A bundle has to answer "signer X endorsed content C" out of its own directory
# (the anchor dates C, not the endorsement — see README, "Bundle contract"), so
# it snapshots EVERY signature sitting beside the stamped file,
# not one and not only the seal's own. Planted stub sigs on purpose: what is
# being pinned is discovery and copying, and `stamp` neither reads nor verifies
# these — a valid signature here would test ssh-keygen, not this.
#
# The bare `<file>.sig` form is in because `sig-files-for` is the shared
# discovery and knows both spellings; a bundle missing it is a bundle whose
# signature only exists outside itself.
@test
def "stamp snapshots every signature beside the file it stamps" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    build-calendar-response | save --raw --force $"($tmp_dir)/response.bin"
    "alice-sig" | save --force $"($file).alice.sig"
    "bob-sig" | save --force $"($file).bob.sig"
    "bare-sig" | save --force $"($file).sig"

    let result = (ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/response.bin")

    assert equal ($result.sigs | each {|s| $s | path basename } | sort) [
        "doc.txt.alice.sig"
        "doc.txt.bob.sig"
        "doc.txt.sig"
    ]
    assert equal (open --raw $"($result.dir)/doc.txt.alice.sig" | str trim) "alice-sig"
}

# Pins the README's "Dating the endorsement": a signature is dated by stamping
# the signature, and `ots stamp` is already general enough to take one — no
# mechanism is needed for it. What has to hold is that the resulting proof
# commits to the SIGNATURE's bytes and not to the signed file's, because that
# is the whole difference between dating an endorsement and dating content.
#
# The sig here is a stub: `stamp` hashes the bytes it is handed and never reads
# them as a signature, so a real ssh-keygen sig would pin ssh-keygen, not this.
@test
def "a stamp over a signature commits to the signature bytes, not to the signed file" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    let sig = $"($file).alice.sig"
    "hello world" | save --force $file
    "alice-sig" | save --force $sig
    build-calendar-response | save --raw --force $"($tmp_dir)/response.bin"

    let result = (ots stamp $sig --out-dir $tmp_dir --response-file $"($tmp_dir)/response.bin")

    let stamped = (ots info $result.ots | get hash)
    assert equal $stamped (open --raw $sig | hash sha256)
    assert ($stamped != (open --raw $file | hash sha256)) "the stamp dated the signed file, not the signature"
}

# --- --into: one seal moment, one bundle ---

# The point of --into. Derived naming filed a signature's proof in a bundle of
# its own, keyed by a name already carrying a 64-hex fingerprint, so one seal
# moment produced two directories and neither could make the full bundle claim:
# the content bundle held an endorsement it could not date, the signature bundle
# held a date for content it did not carry. Asserted on the whole directory
# listing rather than on `$result.ots` alone, because the failure mode is a
# second directory appearing — a stamp that ignored --into and derived its own
# name would still return a plausible path.
@test
def "stamp --into joins the named bundle instead of deriving one" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    let sig = $"($file).alice.sig"
    "hello world" | save --force $file
    "alice-sig" | save --force $sig
    build-calendar-response | save --raw --force $"($tmp_dir)/response.bin"

    let content = (ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/response.bin")
    let endorsement = (ots stamp $sig --into $content.dir --response-file $"($tmp_dir)/response.bin")

    assert equal $endorsement.dir $content.dir "the signature's proof got a bundle of its own"
    assert equal (ls --all $tmp_dir | where type == dir | get name | each {|d| $d | path basename }) [
        ($content.dir | path basename)
    ] "a second bundle directory appeared beside the first"

    # All four files together, and each proof committing to the file beside it —
    # that is what makes the one directory answer both halves of the claim. The
    # two proofs cannot collide: a stem keeps the `.sig`'s full name, so the
    # endorsement's proof is `doc.txt.alice.ots` beside the content's `doc.ots`,
    # and the same "strip .ots, take the sibling it proves" reading covers both.
    assert equal (ls --all $content.dir | get name | each {|f| $f | path basename } | sort) [
        "doc.ots"
        "doc.txt"
        "doc.txt.alice.ots"
        "doc.txt.alice.sig"
    ]
    assert equal (ots info $content.ots | get hash) (open --raw $file | hash sha256)
    assert equal (ots info $endorsement.ots | get hash) (open --raw $sig | hash sha256)
}

# --out-dir and --into say different things about where the proof goes, so a
# silent precedence would file it somewhere the caller did not ask for. It has
# to fail before the calendar post: that post is a permanent public write, and
# a --response-file is deliberately NOT passed here so that reaching the network
# is what a regression looks like.
@test
def "stamp refuses --out-dir together with --into" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file

    let failed = try {
        ots stamp $file --out-dir $tmp_dir --into $"($tmp_dir)/some.BUNDLE"
        false
    } catch {|e| $e.msg | str contains "alternatives" }
    assert $failed "an ambiguous destination was accepted"
    assert equal (ls --all $tmp_dir | get name | each {|f| $f | path basename }) ["doc.txt"] "the refusal still wrote something"
}

# The frozen-copy guard under --into. With derived naming a name clash inside a
# bundle is a ~2^-32 hash coincidence; under --into the caller chose the
# directory, so a clash is ordinary and the guard is what stops a stamp from
# overwriting another file's snapshot while archiving the wrong .ots. Hostile
# shape on purpose: the bundle is hand-built, not one `stamp` produced.
@test
def "stamp --into refuses a bundle holding different content under the same name" [] {
    let tmp_dir = $in.tmp_dir
    let bundle = $"($tmp_dir)/planted.BUNDLE"
    mkdir $bundle
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    "some other content entirely" | save --force $"($bundle)/doc.txt"
    build-calendar-response | save --raw --force $"($tmp_dir)/response.bin"

    let failed = try {
        ots stamp $file --into $bundle --response-file $"($tmp_dir)/response.bin"
        false
    } catch {|e| $e.msg | str contains "collision" }
    assert $failed "the stamp overwrote a frozen copy of different content"
    assert equal (open --raw $"($bundle)/doc.txt" | str trim) "some other content entirely"
}

# `cp` prints a failed copy on stderr and exits 0, so every writer that used it
# reported success for a file that was never written. This one pins the frozen
# copy: a write-frozen-copy that swallows its failure has to fail here. The
# other writer, `_fs.nu copy-file`, is pinned in tests/test_fs.nu.
#
# Why the bundle directory is pre-created and then made read-only: `mkdir` on an
# existing directory is a no-op, so the first write that can fail is the frozen
# copy itself, and the throw is about the copy rather than about the directory.
# Needs a non-root uid — root ignores the mode, and then this test fails loudly
# instead of passing for the wrong reason.
@test
def "a frozen copy that cannot be written throws instead of returning the bundle" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    let out_dir = $"($tmp_dir)/bundles"
    let prefix = open --raw $file | hash sha256 | decode hex | encode hex | str substring 0..<8
    let dir = bundle-dir-for $file $prefix $out_dir
    mkdir $dir
    ^chmod 500 $dir

    let failed = try { freeze-bundle $file $out_dir; false } catch { true }
    ^chmod 700 $dir

    assert $failed "freeze-bundle returned a bundle whose frozen copy was never written"
    assert equal (ls --all $dir | get name) [] "the copy landed after all, so this test proves nothing"
}

# The copy is read from disk a second time, after the hash the proof commits to
# was taken — under `stamp` with a calendar round-trip in between. A file edited
# in that window would put content in the bundle that the proof does not
# describe, and nothing downstream would say so: `check-frozen-copy` only looks
# at a copy that is already there.
@test
def "a frozen copy is refused when the file no longer matches the proof" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    let copy = $"($tmp_dir)/bundle-doc.txt"
    let stale_hash = "something else entirely" | hash sha256 | decode hex

    let failed = try { write-frozen-copy $file $stale_hash $copy; false } catch { true }
    assert $failed "a file that does not hash to the proof was frozen into the bundle anyway"
    assert equal ($copy | path exists) false "the mismatched content was written before the check"
}

# A bundle names the proof `<stem>.ots` and the frozen copy `<stem>.<ext>`, so a
# file already ending in `.ots` wants one path for two different bytes. It was
# the `.ots` write that won: the frozen copy saw the path taken and skipped,
# leaving a bundle holding a proof of content it did not contain, exit 0.
@test
def "a file already named .ots is refused rather than taking its own proof name" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.ots"
    "hello world" | save --force $file
    "x" | save --raw --force $"($tmp_dir)/garbage.bin"

    let outcome = (
        try {
            ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/garbage.bin"
            "ok"
        } catch {|e| $e.msg }
    )
    assert ($outcome | str contains "would take the name its own proof gets") $"expected a refusal, got: ($outcome)"
    # Refused before anything was assembled or parked: no rejected bytes either,
    # which is what marks this as a check that ran ahead of the calendar post.
    let left = (ls --all $tmp_dir | get name | path basename | sort)
    assert equal $left ["doc.ots" "garbage.bin"] "the refusal left something behind"
}

# Rejected bytes are deliberately not a proof (README, "rejected"), and a bundle
# is the one place they must not be mistaken for one — every file in a bundle is
# read as part of its claim. So under --into they go to the bundle's PARENT,
# which is where derived naming already put them.
@test
def "a rejected response under --into lands outside the bundle" [] {
    let tmp_dir = $in.tmp_dir
    let bundle = $"($tmp_dir)/existing.BUNDLE"
    mkdir $bundle
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    "x" | save --raw --force $"($tmp_dir)/garbage.bin"

    let failed = try {
        ots stamp $file --into $bundle --response-file $"($tmp_dir)/garbage.bin"
        false
    } catch {|e| $e.msg | str contains "no proof was written into a bundle" }
    assert $failed "a garbage calendar body was accepted"

    assert equal (ls --all $bundle | get name) [] "rejected bytes were written inside the bundle"
    let rejected = (ls --all $tmp_dir | get name | where ($it | str contains ".rejected-"))
    assert equal ($rejected | length) 1 "the assembled bytes were dropped instead of parked beside the bundle"
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

    let outcome = (
        try {
            ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/garbage.bin"
            "ok"
        } catch {|e| $e.msg }
    )
    assert ($outcome | str contains "no proof was written into a bundle") $"expected a refusal, got: ($outcome)"
    # no bundle directory, no frozen copy, no proof — the rejected bytes are
    # a loose file, never something a verifier would read as a bundle
    let left = (ls --all $tmp_dir | get name | path basename | sort)
    assert equal ($left | where not ($it | str contains ".rejected-")) ["doc.txt" "garbage.bin"]
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

    let rejected = (ls --all $tmp_dir | get name | where ($it | str contains ".rejected-"))
    assert equal ($rejected | length) 1
    let bytes = (open --raw ($rejected | first) | into binary)
    # header(31) version(1) sha256-op(1) hash(32) append-op(1) len(1) nonce(16)
    # sha256-op(1) response(1) — the nonce is what makes these bytes worth
    # keeping, so pin where it sits.
    assert equal ($bytes | bytes at 33..<65) (open --raw $file | hash sha256 | decode hex)
    assert equal ($bytes | bytes at 65..<67) 0x[f010]
    assert equal ($bytes | bytes length) 85
}

# The rejected name was <stem>.<prefix>.rejected-<YYYYmmdd-HHMMSS>.ots written
# with --force, so two failing stamps inside one second collided: the second
# silently replaced the first, and the first's nonce — the only thing binding
# its already-submitted digest to this file — was gone. The comment above the
# write claimed "a retry never overwrites one" while the code did exactly that.
@test
def "rejected stamps in the same second each keep their nonce" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "hello world" | save --force $file
    0x[ff] | save --raw --force $"($tmp_dir)/forked.bin"

    for _ in 1..3 {
        try { ots stamp $file --out-dir $tmp_dir --response-file $"($tmp_dir)/forked.bin" }
    }

    let rejected = (ls --all $tmp_dir | get name | where ($it | str contains ".rejected-"))
    assert equal ($rejected | length) 3 "a rejected proof was overwritten"
    # Each run draws a fresh nonce, so these are three distinct payloads.
    assert equal ($rejected | each { open --raw $in | hash sha256 } | uniq | length) 3
    # Why assert the naming rule and not just the count: the three runs could
    # straddle a second boundary, and distinct timestamps would then carry the
    # test on their own. Binding the name to the bytes is what makes a
    # same-second collision impossible rather than unlikely.
    for f in $rejected {
        let tag = (open --raw $f | hash sha256 | str substring 0..<8)
        assert ($f | path basename | str ends-with $"-($tag).ots") $"rejected name is not bound to its bytes: ($f)"
    }
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
    assert equal (ls --all $first.dir | get name | path basename | sort) ["doc.ots" "doc.txt"]
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
    let on_disk = (ls --all $bundle | get name | where ($it | str ends-with ".ots"))
    assert equal ($on_disk | length) 3 "an archived proof was overwritten"
    assert equal ($on_disk | each { open --raw $in | hash sha256 } | sort) ($made | get hash | sort)

    # Why assert the naming rule and not just the count: three stamps could
    # straddle a second boundary, and then distinct timestamps would carry the
    # test on their own. The archive name binds to the archived proof's own
    # bytes, which is what makes a same-second collision impossible rather than
    # unlikely.
    for archived in ($on_disk | where ($it | path basename) != "doc.ots") {
        let tag = (open --raw $archived | hash sha256 | str substring 0..<8)
        assert ($archived | path basename | str ends-with $"-($tag).ots") $"archive name is not bound to its bytes: ($archived)"
    }
}

# --into with no directory separator. `"mybundle" | path dirname` is the empty
# string, so the rejected-response file was aimed at `/<name>`: the write failed
# with a bare I/O error before the `error make` that names the parked path, and
# the assembled proof went nowhere — with a live calendar the digest has already
# been posted by then and the nonce only exists in that run. The earlier test of
# this path passed an absolute --into and so never saw it.
#
# `cd` into the temp dir on purpose: a relative --into is only relative to
# something, and that is what the bug needed.
@test
def "a rejected response under a relative --into is still parked, not lost" [] {
    let tmp_dir = $in.tmp_dir
    cd $tmp_dir
    mkdir "mybundle"
    "hello world" | save --force "doc.txt"
    "x" | save --raw --force "garbage.bin"

    let err = try {
        ots stamp "doc.txt" --into "mybundle" --response-file "garbage.bin"
        null
    } catch {|e| $e.msg }
    assert ($err != null) "a garbage calendar body was accepted"
    assert ($err | str contains "no proof was written into a bundle") $"the failure did not reach the recovery message: ($err)"

    assert equal (ls --all "mybundle" | get name) [] "rejected bytes were written inside the bundle"
    let rejected = ls --all $tmp_dir | get name | where ($it | str contains ".rejected-")
    assert equal ($rejected | length) 1 "the assembled proof and its nonce were lost"
}

# Two files sharing a stem in one bundle. `<stem>.ots` is named from the stem
# alone, so stamping `tree-root.md` into `tree-root.txt`'s bundle took
# `tree-root.ots` and filed the .txt proof under the archival name, whose README
# meaning is "a previous proof of the SAME content". What was left was a
# `tree-root.ots` that does not prove the `tree-root.txt` beside it. The
# frozen-copy guard cannot see this: the two files have different names.
@test
def "stamp --into refuses to take the .ots name that another file proof holds" [] {
    let tmp_dir = $in.tmp_dir
    let response = $"($tmp_dir)/response.bin"
    build-calendar-response | save --raw --force $response
    "content of txt" | save --force $"($tmp_dir)/doc.txt"
    "content of md" | save --force $"($tmp_dir)/doc.md"

    let first = ots stamp $"($tmp_dir)/doc.txt" --out-dir $tmp_dir --response-file $response
    let before = open --raw $first.ots | into binary

    let err = try {
        ots stamp $"($tmp_dir)/doc.md" --into $first.dir --response-file $response
        null
    } catch {|e| $e.msg }
    assert ($err != null) "a second stem took the first file's proof name"
    assert ($err | str contains "is the proof of doc.txt") $"the refusal did not name the file it protects: ($err)"

    # The incumbent is untouched: not archived, not overwritten.
    assert equal (open --raw $first.ots | into binary) $before "the refused stamp still moved the proof it clashed with"
    assert equal (
        ls --all $first.dir | get name | each {|f| $f | path basename } | sort
    ) ["doc.ots" "doc.txt"] "the refused stamp left files behind"
}

# --into means join THIS bundle. Creating one on a typo produces a directory
# outside the `<stem>.<HASH8>` grammar, holding a proof no name-based reader can
# place, which `seal status` then reports as a bundle. Checked before the calendar
# post, so no --response-file: reaching the network is what a regression looks
# like.
@test
def "stamp refuses an --into bundle that does not exist" [] {
    let tmp_dir = $in.tmp_dir
    "hello world" | save --force $"($tmp_dir)/doc.txt"

    let err = try {
        ots stamp $"($tmp_dir)/doc.txt" --into $"($tmp_dir)/typo-bundle"
        null
    } catch {|e| $e.msg }
    assert ($err != null) "a non-existent --into bundle was created"
    assert ($err | str contains "needs an existing bundle directory") $"unexpected refusal: ($err)"
    assert not ($"($tmp_dir)/typo-bundle" | path exists) "the refusal still created the directory"
}

# The two shapes `path exists` lets through, both of which lose the proof after
# the calendar post — so the check is `path type == "dir"`. No --response-file:
# reaching the network is what a regression looks like.
#
#   a regular file — `mkdir` throws a bare "Already exists" naming nothing, past
#     the point where the rejected-recovery branch could run
#   a symlink to a directory — the bundle would be written through the link, where
#     `seal status` cannot see it (it walks real directories only), and a rejected
#     response would park in the link's parent rather than beside the bundle
@test
def "stamp refuses an --into that exists but is not a real directory" [] {
    let tmp_dir = $in.tmp_dir
    "hello world" | save --force $"($tmp_dir)/doc.txt"
    "not a directory" | save --force $"($tmp_dir)/afile"
    mkdir $"($tmp_dir)/realdir"
    ^ln -s $"($tmp_dir)/realdir" $"($tmp_dir)/linkdir"

    for target in ["afile" "linkdir"] {
        let err = try {
            ots stamp $"($tmp_dir)/doc.txt" --into $"($tmp_dir)/($target)"
            null
        } catch {|e| $e.msg }
        assert ($err != null) $"--into ($target) was accepted"
        assert ($err | str contains "needs an existing bundle directory") $"unexpected refusal for ($target): ($err)"
    }
    assert equal (ls --all $"($tmp_dir)/realdir" | get name) [] "the symlinked target was written through"
    assert equal (open --raw $"($tmp_dir)/afile" | str trim) "not a directory" "the regular file was overwritten"
}

# An unreadable incumbent `<stem>.ots` cannot be placed, so it cannot be shown
# safe to rename either — and the archival name it would get asserts "a previous
# proof of the same content". Let through, the corrupt file would be archived
# and the new stamp would take `<stem>.ots`, leaving the `doc.txt` beside it
# paired with a proof of different content, which is the exact state the guard
# exists to prevent.
@test
def "stamp --into refuses when the incumbent proof cannot be read" [] {
    let tmp_dir = $in.tmp_dir
    let bundle = $"($tmp_dir)/doc.DEADBEEF"
    mkdir $bundle
    "content of txt" | save --force $"($bundle)/doc.txt"
    "not an OTS file at all" | save --raw --force $"($bundle)/doc.ots"
    "content of md" | save --force $"($tmp_dir)/doc.md"
    build-calendar-response | save --raw --force $"($tmp_dir)/response.bin"

    let err = try {
        ots stamp $"($tmp_dir)/doc.md" --into $bundle --response-file $"($tmp_dir)/response.bin"
        null
    } catch {|e| $e.msg }
    assert ($err != null) "an unreadable incumbent was archived and its name taken"
    assert ($err | str contains "not a readable proof") $"unexpected refusal: ($err)"
    assert equal (open --raw $"($bundle)/doc.ots" | str trim) "not an OTS file at all" "the unreadable proof was moved anyway"
    assert equal (
        ls --all $bundle | get name | each {|f| $f | path basename } | sort
    ) ["doc.ots" "doc.txt"] "the refused stamp left files behind"
}
