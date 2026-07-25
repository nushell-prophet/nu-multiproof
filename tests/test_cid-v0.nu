use std/assert
use std/testing *

use ../nu-multiproof/cid-v0.nu
use ../nu-multiproof/_temp-helpers.nu with-temp-dir

# Test vectors precomputed with:
# printf '<input>' | ipfs add --only-hash --quieter --cid-version=0 --raw-leaves=false --hash=sha2-256 --chunker=size-262144

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
    # Build 262144 zero bytes via doubling
    mut buf = 0x[00]
    for _ in 1..18 {
        $buf = $buf | bytes add --end $buf
    }
    assert equal ($buf | cid-v0) "QmRk1rduJvo5DfEYAaLobS2za9tDszk35hzaNSDCJ74DA7"
}

@test
def "exceeds max single chunk" [] {
    mut buf = 0x[00]
    for _ in 1..18 {
        $buf = $buf | bytes add --end $buf
    }
    let oversized = $buf | bytes add --end 0x[00]
    let result = try { $oversized | cid-v0; null } catch { $in }
    assert ($result != null)
}
