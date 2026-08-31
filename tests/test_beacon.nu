use std/assert
use std/testing *

use ../nu-multiproof/beacon.nu
use ../nu-multiproof/_beacon-helpers.nu [ BEACON_NONE BEACON_TOKEN_PATTERN validate-beacon parse-beacon beacon-token ]
use ../nu-multiproof/_explorer.nu [ header-time check-min-sources ]
use ../nu-multiproof/_ots-helpers.nu check-fetched-header
use ../nu-multiproof/_merkle-helpers.nu root-statement

# The Bitcoin genesis block, as published in Bitcoin Core and reproduced in
# every reference on the format. This is the outside vector this repo's rules
# require: every other beacon test in here folds bytes this codebase produced,
# so a header parser that read the wrong offsets — or a hash convention flipped
# end to end — would agree with itself and pass. These three values come from
# outside, and all three have to hold at once.
const GENESIS_HEADER = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
const GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
const GENESIS_TIME = 2009-01-03T18:15:05Z

@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

@test
def "the genesis block header hashes and dates as Bitcoin says it does" [] {
    # check-fetched-header is what admits an explorer's answer, so running the
    # published header through it exercises the same double-SHA256 and the same
    # display-order reversal a live beacon check rests on.
    let bytes = check-fetched-header "fixture" $GENESIS_HASH $GENESIS_HEADER
    assert equal ($bytes | bytes length) 80
    assert equal (header-time $bytes) $GENESIS_TIME
}

@test
def "a header of any length but eighty is refused a time" [] {
    # The offsets header-time reads are fixed, so a short buffer would otherwise
    # yield a plausible datetime out of whatever bytes happened to be there.
    for bad in [0x[] ($GENESIS_HEADER | decode hex | bytes at 0..78) (($GENESIS_HEADER | decode hex) ++ 0x[00])] {
        assert error {|| header-time $bad } $"accepted ($bad | bytes length) bytes"
    }
}

@test
def "the beacon token round-trips through its own grammar" [] {
    let token = beacon-token 964771 $GENESIS_HASH
    assert equal $token $"bitcoin:964771:($GENESIS_HASH)"
    assert equal (parse-beacon $token) {height: 964771 hash: $GENESIS_HASH}
    assert equal (parse-beacon $BEACON_NONE) null
}

@test
def "a beacon token that is not exactly the grammar is refused" [] {
    for bad in [
        ""
        "None" # the sentinel is lowercase, like every other token in the format
        "none " # trailing space: the statement is signed byte for byte
        $"bitcoin:964771:($GENESIS_HASH | str upcase)" # uppercase hex
        "bitcoin:964771" # a height naming no block
        $"bitcoin:($GENESIS_HASH)" # a hash naming no height
        $"bitcoin:0964771:($GENESIS_HASH)" # leading zero — two spellings of one height
        $"bitcoin:-1:($GENESIS_HASH)" # a height before the genesis block
        $"ethereum:964771:($GENESIS_HASH)" # a chain this format does not define
        $"bitcoin:964771:($GENESIS_HASH)extra"
        $"bitcoin:964771:(0..<63 | each { 'a' } | str join)" # 63 hex chars
    ] {
        assert error {|| validate-beacon $bad } $"accepted: ($bad | to json)"
    }
}

@test
def "minting a token validates what it is about to write" [] {
    # beacon-token is the one place a beacon enters bytes that get signed, so a
    # value that cannot be read back has to fail here rather than in the next
    # reader of an already-signed file.
    assert error {|| beacon-token 1 ($GENESIS_HASH | str upcase) }
    assert error {|| beacon-token -1 $GENESIS_HASH }
}

@test
def "a statement carrying no beacon has no bound to check" [] {
    let file = $"($in.tmp_dir)/tree-root.txt"
    root-statement ("root" | hash sha256) 0 "genesis" $BEACON_NONE | save --raw --force $file
    # Throws rather than answering `valid: false`: an offline seal made no claim,
    # and "no claim" is not a false one.
    let err = try { beacon verify $file --min-sources 1; null } catch {|e| $e.msg }
    assert ($err | str contains "no beacon") $"got: ($err)"
}

@test
def "a beacon check with no cross-check available is refused before the network" [] {
    # --min-sources 0 would mean "report a lower bound with no explorer agreeing
    # at all". Checked before anything is read, so it holds offline — the same
    # floor and the same reason as `ots verify`.
    for n in [0 -1] {
        assert error {|| beacon latest --min-sources $n } $"--min-sources ($n) was accepted by latest"
        assert error {|| beacon verify "/nonexistent" --min-sources $n } $"--min-sources ($n) was accepted by verify"
    }
}

@test
def "a negative reorg depth is refused" [] {
    # Depth above the tip is not a beacon: it names a block nobody has mined.
    assert error {|| beacon latest --depth -1 }
}

@test
def "the token grammar has one spelling" [] {
    # The statement parser splices BEACON_TOKEN_PATTERN into its own regex rather
    # than repeating it. If that fragment ever grows an anchor or a capturing
    # group, the statement's named groups shift and the parse breaks somewhere
    # else entirely — so pin the shape here, where the message is about it.
    assert not ($BEACON_TOKEN_PATTERN | str contains '\A')
    assert not ($BEACON_TOKEN_PATTERN | str contains '\z')
    assert equal ($BEACON_TOKEN_PATTERN | parse --regex '\((?<open>[^?])' | length) 0
}
