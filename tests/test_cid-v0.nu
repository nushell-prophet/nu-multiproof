use std/assert
use std/testing *

use ../nu-multiproof/cid-v0.nu
use ../nu-multiproof/_cid-helpers.nu [file-node dir-node node-cid encode-base58 decode-base58]
use ../nu-multiproof/_temp-helpers.nu with-temp-dir

# Every expected value below was recorded from the reference client, not from
# this code — that is the whole point of the file. Single files:
#   printf '<input>' | ipfs add --only-hash --quieter --cid-version=0 --raw-leaves=false --hash=sha2-256 --chunker=size-262144
# Directories add --recursive --hidden over a staged tree. The chunked and
# directory vectors were recorded with ipfs 0.42.0.

# 16 bytes doubled 14 times: exactly one chunk, and the building block for the
# multi-chunk vectors below.
def chunk-bytes []: nothing -> binary {
    mut buf = 0x[000102030405060708090a0b0c0d0e0f]
    for _ in 1..14 { $buf = $buf | bytes add --end $buf }
    $buf
}

@test
def "empty content" [] {
    assert equal (0x[] | cid-v0) "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH"
}

@test
def "single null byte" [] {
    assert equal (0x[00] | cid-v0) "QmS9JArPwa55ePgDnyg6TzX24mYTS1b1vLqWNebyVotKxQ"
}

@test
def "single 0xFF byte" [] {
    assert equal (0x[FF] | cid-v0) "QmarNgpyJHwcrLfjPzFsLiPmLukU3uYqqofHoYHbnUfErn"
}

@test
def "hello world string" [] {
    assert equal ("hello world" | into binary | cid-v0) "Qmf412jQZiuVUtdgnB36FXFX7xg5V6KEbSJ4dpQuhkLyfD"
}

# `open --raw` on a UTF-8 file yields a string, not binary — the same bytes
# through the type nushell actually hands back must give the same CID.
@test
def "utf-8 file read with open --raw" [] {
    with-temp-dir "cid-utf8" {|dir|
        let file = $dir | path join "hello.txt"
        "hello world" | save --raw --force $file
        assert equal (open --raw $file | cid-v0) "Qmf412jQZiuVUtdgnB36FXFX7xg5V6KEbSJ4dpQuhkLyfD"
    }
}

@test
def "max single chunk 262144 bytes" [] {
    # 262144 zero bytes, built by doubling
    mut buf = 0x[00]
    for _ in 1..18 { $buf = $buf | bytes add --end $buf }
    assert equal ($buf | cid-v0) "QmRk1rduJvo5DfEYAaLobS2za9tDszk35hzaNSDCJ74DA7"
}

# Over one chunk the CID stops being a hash of the bytes and becomes a hash of a
# DAG: two full leaves and a short one, linked from a root node carrying the
# total filesize and each leaf's size.
@test
def "multi-chunk file: two full chunks and a 1000-byte tail" [] {
    let chunk = chunk-bytes
    let content = $chunk | bytes add --end $chunk | bytes add --end ($chunk | bytes at 0..<1000)
    assert equal ($content | bytes length) 525288
    assert equal ($content | cid-v0) "QmWRgwTqCcE11Fs9rKviA8uxnACY5VWAyEJsCU44gD33ue"
}

# 175 chunks: one branch node fills at LINKS_PER_NODE (174) and the 175th chunk
# forces a second level. Nothing else in the suite reaches depth 2, and a
# wrong fold there is invisible at depth 1 — hence 45 MB of test data.
@test
def "two-level file: 175 chunks" [] {
    mut content = chunk-bytes
    for _ in 1..8 { $content = $content | bytes add --end $content }
    let content = $content | bytes at 0..<(262144 * 175)
    assert equal ($content | bytes length) 45875200
    assert equal ($content | cid-v0) "QmazZG2Fp65Los6G7GUjNgtSiJ9xxixYKNop6frmWR1QkK"
}

# The published CID of the empty UnixFS directory — the one vector here that is
# not merely recorded but publicly known.
@test
def "empty directory" [] {
    assert equal (dir-node [] | node-cid) "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn"
}

@test
def "directory tree with dotfile and nested dir" [] {
    let hidden = "hidden\n" | into binary | file-node
    let file = "hello\n" | into binary | file-node
    let inner = "world\n" | into binary | file-node

    assert equal ($hidden | node-cid) "QmUti2Md6FcRyt5XquQkvPFUgwxUra9p5b2iHXaPRWnhE9"
    assert equal ($file | node-cid) "QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN"
    assert equal ($inner | node-cid) "QmaRGe7bVmVaLmxbrMiVNXqW4pRNNp3xq7hFtyRKA3mtJL"

    let sub = dir-node [{name: "inner.txt" node: $inner}]
    assert equal ($sub | node-cid) "QmQV8kBgwwShkLLLvEej44qvbwTncKJmbwfz5E8e4ApNkj"

    let root = dir-node [
        {name: ".hidden" node: $hidden}
        {name: "file.txt" node: $file}
        {name: "sub" node: $sub}
    ]
    assert equal ($root | node-cid) "Qme53cg5u81Hh13JAU57drw7Rpm391Pwi2PkbAhF7k3pMS"
}

# The name order of directory links is part of the CID. This pins that the
# byte-wise sort in tree-hashes.nu is load-bearing, not decoration: build the
# same entries in the wrong order and the client's CID is no longer reproduced.
@test
def "directory link order changes the CID" [] {
    let file = "hello\n" | into binary | file-node
    let inner = "world\n" | into binary | file-node
    let sub = dir-node [{name: "inner.txt" node: $inner}]
    let unsorted = dir-node [
        {name: "sub" node: $sub}
        {name: "file.txt" node: $file}
    ]
    let sorted = dir-node [
        {name: "file.txt" node: $file}
        {name: "sub" node: $sub}
    ]
    assert not (($unsorted | node-cid) == ($sorted | node-cid))
}

# A directory link carries the child's multihash, which this code recovers from
# the child's base58 CID string — so the decode must invert the encode exactly.
@test
def "base58 round-trips" [] {
    let cid_bytes = 0x[1220] | bytes add --end ("hello" | into binary | hash sha256 | decode hex)
    assert equal ($cid_bytes | encode-base58 | decode-base58) $cid_bytes
    # Leading zero bytes are the case a naive big-integer conversion drops
    assert equal (0x[0000ff] | encode-base58 | decode-base58) 0x[0000ff]
}

@test
def "base58 rejects a character outside the alphabet" [] {
    # 0, O, I and l are excluded from base58btc precisely to avoid confusion
    let result = try { "QmO0Il" | decode-base58; null } catch {|e| $e.msg }
    assert ($result != null) "non-base58 input was accepted"
    assert ($result | str contains "base58")
}
