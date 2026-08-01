use std/assert
use std/testing *

use ../nu-multiproof/cid-v0.nu
use ../nu-multiproof/_cid-helpers.nu [ file-node dir-node node-cid encode-base58 ]
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

# Above a size threshold kubo stops writing a basic directory and shards it into
# a HAMT, which has a different CID for the same entries. Nothing here builds
# shards, so the boundary is a hard edge of what this code may claim.
#
# Both numbers come from the client, measured at the exact boundary: entries of
# (name bytes + 34) summing to 262144 still hash as a basic directory, and the
# CID below is what `ipfs add -r` reports for that directory.
@test
def "directory at the sharding threshold still matches the client" [] {
    let links = threshold-links 4096
    assert equal ($links | each {|l| ($l.name | into binary | bytes length) + 34 } | math sum) 262144
    assert equal (dir-node $links | node-cid) "QmYkVrEh726Xuib4nyYSpvN8UxquVr28umQjt8hP4KgvVp"
}

@test
def "directory past the sharding threshold is refused, not guessed" [] {
    # One more entry and kubo answers QmWaXkfnAfj2HmmWxXKaUgYxkc4nZHcGznGGhzfeRXytGq,
    # while a basic directory built over the same entries answers something else.
    let links = threshold-links 4097
    let result = try { dir-node $links --path "assets"; null } catch {|e| $e.msg }
    assert ($result != null) "an over-threshold directory was given a basic-directory CID"
    assert ($result | str contains "HAMT")
    assert ($result | str contains "assets") $"error does not name the directory: ($result)"
}

# 30-byte names, so each entry contributes exactly 64 bytes to kubo's estimate
def threshold-links [count: int]: nothing -> list {
    let node = "x" | into binary | file-node
    let pad = 0..<30 | each { "a" } | str join
    0..<$count
    | each {|i| $"($i)($pad)" | str substring 0..<30 }
    | sort # links reach dir-node in name order, as the client walks them
    | each {|name| {name: $name node: $node} }
}

@test
def "base58 of all-zero bytes is leading ones only" [] {
    # Bitcoin base58: each leading zero byte is one '1', and the remaining value
    # (zero) contributes no digits at all
    assert equal (0x[00] | encode-base58) "1"
    assert equal (0x[0000] | encode-base58) "11"
    assert equal (0x[0000ff] | encode-base58) "115Q"
}
