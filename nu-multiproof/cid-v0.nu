# Pure Nushell CID v0 for file content of any size.
# Reproduces: ipfs add --only-hash --quieter --cid-version=0 --raw-leaves=false --hash=sha2-256

use _cid-helpers.nu [file-node node-cid]

# Compute the CID v0 of raw content in pure Nushell — no ipfs daemon or CLI.
#
# Content over 256 KiB is chunked and folded into a UnixFS DAG exactly as the
# reference client does, so the CID is the same one `ipfs add` reports.
#
# Why string input is accepted: `open --raw f` collects to a *string* whenever
# the file's bytes are valid UTF-8, so `open --raw README.md | cid-v0` — the
# main way to use this command — hit a bare `Type mismatch` on a binary-only
# signature. `into binary` on that string yields the same bytes back, so this
# widens the accepted type without changing what gets hashed.
@example "CID v0 of in-memory bytes" { "hello" | into binary | nu-multiproof cid-v0 } --result "QmWfVY9y3xjsixTgbd9AorQxH7VtMpzfx2HaWtsoUYecaX"
@example "same bytes arriving as a string, as `open --raw` returns them" { "hello" | nu-multiproof cid-v0 } --result "QmWfVY9y3xjsixTgbd9AorQxH7VtMpzfx2HaWtsoUYecaX"
export def main []: [binary -> string, string -> string] {
    $in | into binary | file-node | node-cid
}
