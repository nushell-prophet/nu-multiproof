use std/assert
use std/testing *

use ../nu-multiproof/ots.nu

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
    assert ($result | str contains "PendingAttestation")
    assert ($result | str contains "https://a.pool.opentimestamps.org")
    assert ($result | str contains "0000000000000000000000000000000000000000000000000000000000000000")
}

@test
def "info pending with ops" [] {
    let ots_bytes = build-pending-ots --with-ops
    $ots_bytes | save --raw --force /tmp/test_ots_ops.ots
    let result = ots info "/tmp/test_ots_ops.ots"
    assert ($result | str contains "append DEADBEEF")
    assert ($result | str contains "sha256")
    assert ($result | str contains "PendingAttestation")
}

@test
def "info bitcoin attestation" [] {
    let ots_bytes = build-bitcoin-ots
    $ots_bytes | save --raw --force /tmp/test_ots_btc.ots
    let result = ots info "/tmp/test_ots_btc.ots"
    assert ($result | str contains "prepend AABB")
    assert ($result | str contains "sha256")
    assert ($result | str contains "BitcoinBlockHeaderAttestation(123456)")
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

# --- promote tests (offline) ---

@test
def "promote refuses still-pending" [] {
    let tmp = mktemp --directory
    let bundle = $tmp | path join "ots-pending" "x.00000000"
    mkdir $bundle
    let ots_path = $bundle | path join "x.ots"
    build-pending-ots | save --raw --force $ots_path
    let result = try { ots promote $ots_path; null } catch { $in }
    assert ($result != null)
    rm --recursive --force $tmp
}

@test
def "promote moves bundle and applies default rename" [] {
    let tmp = mktemp --directory
    let bundle = $tmp | path join "ots-pending" "foo-bar.AABBCCDD"
    mkdir $bundle
    let ots_path = $bundle | path join "foo-bar.ots"
    "csv-content" | save --raw --force ($bundle | path join "foo-bar.csv")
    build-bitcoin-ots | save --raw --force $ots_path
    ots promote $ots_path
    let target = $tmp | path join "ots-verified" "tree-hashes.AABBCCDD"
    assert (($target | path join "tree-hashes.ots") | path exists)
    assert (($target | path join "tree-hashes.csv") | path exists)
    assert (not ($bundle | path exists))
    rm --recursive --force $tmp
}

@test
def "promote honors --rename override" [] {
    let tmp = mktemp --directory
    let bundle = $tmp | path join "ots-pending" "foo-bar.AABBCCDD"
    mkdir $bundle
    let ots_path = $bundle | path join "foo-bar.ots"
    build-bitcoin-ots | save --raw --force $ots_path
    ots promote $ots_path --rename "bar"
    let target = $tmp | path join "ots-verified" "bar.AABBCCDD"
    assert (($target | path join "bar.ots") | path exists)
    rm --recursive --force $tmp
}

@test
def "promote refuses non-pending location" [] {
    let tmp = mktemp --directory
    let bundle = $tmp | path join "elsewhere" "x.00000000"
    mkdir $bundle
    let ots_path = $bundle | path join "x.ots"
    build-bitcoin-ots | save --raw --force $ots_path
    let result = try { ots promote $ots_path; null } catch { $in }
    assert ($result != null)
    rm --recursive --force $tmp
}

# --- Network-dependent tests ---

@test
def "stamp and info round-trip" [] {
    if ($env.OTS_NETWORK_TEST? | default "false") != "true" { return }

    let test_file = "/tmp/test_ots_stamp_input.txt"
    "hello opentimestamps" | save --raw --force $test_file
    ots stamp $test_file

    let result = ots info $"($test_file).ots"
    let expected_hash = open --raw $test_file | hash sha256
    assert ($result | str contains $expected_hash)
    assert ($result | str contains "PendingAttestation")
}
