# Pure Nushell OpenTimestamps implementation — no `ots` CLI dependency.
# Handles linear proof chains only (single-path, no merkle tree forks).

use _ots-helpers.nu [copy-path-for check-block-header]
use _varint.nu encode-varint
use _repo.nu repo-root
use _layout.nu ots-dir
use _sig.nu sig-files-for

const HEADER_MAGIC = 0x[00 4f70656e54696d657374616d7073 0000 50726f6f66 00 bf89e2e884e89294]
# Only the ops this code names as values live here. The rest (0x03 RIPEMD-160,
# 0xf0 append, 0xf1 prepend) stay byte literals at their two use sites: `match`
# arms must be literal patterns, and `stamp` writes raw bytes (0x[f0]) where an
# int const would need converting first. A const nothing reads is drift bait.
const OP_SHA256 = 0x08
const TAG_ATTESTATION = 0x00
const TAG_FORK = 0xff
const ATT_PENDING = 0x[83dfe30d2ef90c8e]
const ATT_BITCOIN = 0x[0588960d73d71901]
const DEFAULT_CALENDAR = "https://a.pool.opentimestamps.org"
# Esplora-compatible block explorers, queried independently and cross-checked
# so verification never rests on a single source. Both expose the same routes:
#   /block-height/<h> -> block hash   and   /block/<hash>/header -> raw 80 bytes.
const DEFAULT_EXPLORERS = [
    "https://mempool.space/api"
    "https://blockstream.info/api"
]

# LEB128 varuint decode at offset
def parse-varuint [offset: int]: binary -> record<value: int, offset: int> {
    let buf = $in
    mut value = 0
    mut shift = 1
    mut pos = $offset
    loop {
        # Why: an out-of-range `bytes at` yields empty and `into int` reads it
        # as 0, so a truncated file would silently misparse. Fail with a clear
        # message instead.
        if $pos >= ($buf | bytes length) {
            error make {msg: "truncated OTS file: varint runs past end of buffer"}
        }
        let b = $buf | bytes at $pos..($pos) | into int
        $value = $value + ($b mod 128) * $shift
        $pos = $pos + 1
        if ($b | bits and 0x80) == 0 { break }
        $shift = $shift * 128
    }
    {value: $value offset: $pos}
}

# Parse length-prefixed bytes at offset
def parse-varbytes [offset: int]: binary -> record<bytes: binary, offset: int> {
    let buf = $in
    let len = $buf | parse-varuint $offset
    if $len.value == 0 { return {bytes: 0x[] offset: $len.offset} }
    let start = $len.offset
    let end = $start + $len.value - 1
    if $end >= ($buf | bytes length) {
        error make {msg: "truncated OTS file: length-prefixed field runs past end of buffer"}
    }
    {bytes: ($buf | bytes at $start..($end)) offset: ($end + 1)}
}

# Parse one operation given the tag byte already read
def parse-op [tag: int offset: int]: binary -> record<op: record, offset: int> {
    let buf = $in
    match $tag {
        0x08 => { {op: {type: "sha256"} offset: $offset} }
        0x03 => { error make {msg: "RIPEMD-160 replay not supported"} }
        0xf0 => {
            let vb = $buf | parse-varbytes $offset
            {op: {type: "append" data: $vb.bytes} offset: $vb.offset}
        }
        0xf1 => {
            let vb = $buf | parse-varbytes $offset
            {op: {type: "prepend" data: $vb.bytes} offset: $vb.offset}
        }
        _ => { error make {msg: $"unknown op tag: ($tag)"} }
    }
}

# Parse timestamp chain: sequence of ops ending with an attestation
def parse-timestamp [offset: int] {
    let buf = $in
    mut pos = $offset
    mut ops = []

    loop {
        if $pos >= ($buf | bytes length) {
            error make {msg: "truncated OTS file: expected an op or attestation tag"}
        }
        let tag = $buf | bytes at $pos..($pos) | into int
        $pos = $pos + 1

        if $tag == $TAG_FORK {
            error make {msg: "forked timestamps not supported — use the ots CLI for complex proofs"}
        } else if $tag == $TAG_ATTESTATION {
            let att_start = $pos - 1
            let att_tag = $buf | bytes at $pos..($pos + 7)
            $pos = $pos + 8
            let vb = $buf | parse-varbytes $pos
            $pos = $vb.offset

            let attestation = if $att_tag == $ATT_PENDING {
                let inner = $vb.bytes | parse-varbytes 0
                {type: "pending" url: ($inner.bytes | decode utf-8)}
            } else if $att_tag == $ATT_BITCOIN {
                let height = $vb.bytes | parse-varuint 0
                {type: "bitcoin" height: $height.value}
            } else {
                {type: "unknown" tag: ($att_tag | encode hex | str lowercase)}
            }

            return {ops: $ops attestation: $attestation att_offset: $att_start offset: $pos}
        } else {
            let parsed = $buf | parse-op $tag $pos
            $ops = $ops ++ [$parsed.op]
            $pos = $parsed.offset
        }
    }
}

# Parse a complete .ots file
def parse-ots []: binary -> record {
    let buf = $in

    let header = $buf | bytes at 0..30
    if $header != $HEADER_MAGIC {
        error make {msg: "not a valid OTS file: bad header magic"}
    }

    let ver = $buf | parse-varuint 31
    if $ver.value != 1 {
        error make {msg: $"unsupported OTS version: ($ver.value)"}
    }

    let hash_op_byte = $buf | bytes at ($ver.offset)..($ver.offset) | into int
    if $hash_op_byte != $OP_SHA256 {
        error make {msg: $"unsupported file hash algorithm: ($hash_op_byte)"}
    }

    let hash_start = $ver.offset + 1
    let hash_end = $hash_start + 31
    let file_hash = $buf | bytes at $hash_start..($hash_end)

    let ts = $buf | parse-timestamp ($hash_end + 1)

    {
        hash: $file_hash
        ops: $ts.ops
        attestation: $ts.attestation
        att_offset: $ts.att_offset
    }
}

# Replay operations on binary hash input
def replay-ops [ops: list]: binary -> binary {
    mut hash = $in
    for op in $ops {
        $hash = match $op.type {
            "sha256" => { $hash | hash sha256 | decode hex }
            "append" => { $hash | bytes add --end $op.data }
            "prepend" => { $op.data | bytes add --end $hash }
            _ => { error make {msg: $"cannot replay op: ($op.type)"} }
        }
    }
    $hash
}

# Parsed contents of an .ots proof file, as structured data so it composes:
# `ots info x.ots | get attestation.height`. ops is a table ({type, data?} with
# hex-encoded data); the default table rendering is already human-readable, so
# no string-building is needed.
@example "read the attestation from a proof" { ots info proof.ots | get attestation }
export def info [ots_file: path] {
    let parsed = open --raw $ots_file | parse-ots
    {
        # Why str lowercase: `encode hex` emits uppercase, but every persisted
        # hash in this project (tree-hashes.csv, git-proof manifests) is
        # lowercase — it comes from `hash sha256`/git. Lowercase is canonical.
        hash: ($parsed.hash | encode hex | str lowercase)
        ops: (
            $parsed.ops | each {|op|
                match $op.type {
                    "append" => {type: "append" data: ($op.data | encode hex | str lowercase)}
                    "prepend" => {type: "prepend" data: ($op.data | encode hex | str lowercase)}
                    _ => {type: $op.type}
                }
            }
        )
        attestation: $parsed.attestation
    }
}

# Create an OTS timestamp proof for a file
@example "timestamp the manifest against the OTS calendar" { ots stamp multiproofs/tree-hashes.csv }
export def stamp [file: path --out-dir: path] {
    let out_dir = if $out_dir != null { $out_dir } else {
        ots-dir (repo-root)
    }
    let file_hash = open --raw $file | hash sha256 | decode hex
    let nonce = random binary 16
    let merkle_tip = $file_hash | bytes add --end $nonce | hash sha256 | decode hex

    # Why http builtin (not curl): no external dep and no temp files. --full
    # exposes the status, --allow-errors returns a non-200 instead of throwing
    # raw, and /digest expects raw bytes (application/octet-stream).
    let response = (
        http post --full --allow-errors
        --content-type "application/octet-stream"
        $"($DEFAULT_CALENDAR)/digest"
        $merkle_tip
    )
    if $response.status != 200 {
        error make {msg: $"calendar returned status ($response.status)"}
    }
    let calendar_bytes = $response.body

    let nonce_len = ($nonce | bytes length) | encode-varint
    let ots = (
        $HEADER_MAGIC
        | bytes add --end 0x[01]
        | bytes add --end 0x[08]
        | bytes add --end $file_hash
        | bytes add --end 0x[f0]
        | bytes add --end $nonce_len
        | bytes add --end $nonce
        | bytes add --end 0x[08]
        | bytes add --end $calendar_bytes
    )

    # Why uppercase here while every other hex in this project is lowercase:
    # `encode hex` emits uppercase and this prefix is only a directory name.
    # The form is already baked into committed bundles (tree-root.050186F7)
    # and documented in README.md, so the two conventions coexist on purpose —
    # lowercase for hashes that are compared or sent, as-emitted for this name.
    let hash_prefix = $file_hash | encode hex | str substring 0..<8
    let stem = ($file | path parse | get stem)

    let bundle_dir = $"($out_dir)/($stem).($hash_prefix)"
    mkdir $bundle_dir
    let copy_path = (copy-path-for $file $bundle_dir)
    let ots_path = $"($bundle_dir)/($stem).ots"

    # Why: the bundle dir is keyed by stem + an 8-hex hash prefix, so different
    # content sharing that prefix would map to the same dir — silently
    # overwriting the frozen copy while archiving the wrong .ots, breaking
    # bundle self-consistency. Guard: an existing frozen copy must be the same
    # content (full-hash compare, not just the prefix). ~2^-32, one comparison.
    if ($copy_path | path exists) {
        let existing_hash = open --raw $copy_path | hash sha256 | decode hex
        if $existing_hash != $file_hash {
            error make {msg: $"hash-prefix collision in ($bundle_dir): the frozen copy there is different content that shares the 8-hex prefix ($hash_prefix)"}
        }
    }

    # Why: bundle dir is keyed by file hash, so re-stamping unchanged content
    # reuses the directory. The new .ots has a different nonce + calendar
    # response — both are independent attestations worth keeping. Rename the
    # existing one to <stem>.<timestamp>.ots so the prior proof survives.
    if ($ots_path | path exists) {
        let stamp = (date now | format date "%Y%m%d-%H%M%S")
        let archived = $"($bundle_dir)/($stem).($stamp).ots"
        mv $ots_path $archived
        print $"Archived previous: ($archived)"
    }

    cp $file $copy_path
    $ots | save --raw --force $ots_path
    print $"Frozen copy: ($copy_path)"
    print $"Timestamped: ($ots_path)"

    # Why: a self-contained bundle must answer "signer X endorsed content C at
    # time T, anchored to Bitcoin block B" using only files in the bundle dir.
    # Snapshot any sibling sig next to the frozen copy so the binding
    # survives the next `seal` (which overwrites the live sig). Shared
    # discovery, so the bare `<file>.sig` form is bundled too.
    let sigs = sig-files-for $file
    let bundled_sigs = $sigs | each {|sig|
        let sig_name = $sig | path basename
        let dest = $"($bundle_dir)/($sig_name)"
        cp $sig $dest
        print $"Bundled sig: ($dest)"
        $dest
    }

    {dir: $bundle_dir copy: $copy_path ots: $ots_path sigs: $bundled_sigs}
}

# Upgrade a pending OTS attestation to a Bitcoin block header attestation.
# Returns {status: "upgraded" | "already-verified", path}.
# --response-file: read the calendar response from a local file instead of
# fetching it. Why: enables offline tests of the splice/validate/write logic
# without a real calendar; also lets callers pre-fetch responses.
@example "upgrade a pending proof once Bitcoin confirms it" { ots upgrade proof.ots }
export def upgrade [ots_file: path --response-file: path] {
    let buf = open --raw $ots_file
    let parsed = $buf | parse-ots

    if $parsed.attestation.type != "pending" {
        return {status: "already-verified" path: $ots_file}
    }

    let new_bytes = if $response_file != null {
        open --raw $response_file
    } else {
        let current_hash = $parsed.hash | replay-ops $parsed.ops
        # Why str lowercase: same canonical-hex rule as `info` above. The
        # reference calendar unhexlifies server-side and accepts either case,
        # but this is the one hash this project sends off the machine — it
        # should not ride on another server's undocumented tolerance.
        let hash_hex = $current_hash | encode hex | str lowercase
        let url = $"($parsed.attestation.url)/timestamp/($hash_hex)"
        let response = (
            http get --full --allow-errors
            --headers {Accept: "application/vnd.opentimestamps.v1"}
            $url
        )
        if $response.status == 404 {
            error make {msg: "timestamp not yet confirmed by Bitcoin — try again later"}
        }
        if $response.status != 200 {
            error make {msg: $"calendar returned status ($response.status)"}
        }
        $response.body
    }

    let prefix = $buf | bytes at 0..($parsed.att_offset - 1)
    let upgraded = $prefix | bytes add --end $new_bytes

    # Why: validate the upgraded buffer parses to a Bitcoin attestation before
    # touching the file. A malformed calendar response would otherwise destroy
    # the pending bundle. Validate-then-atomic-rename keeps the original
    # intact on any failure.
    let validation = try {
        let reparsed = $upgraded | parse-ots
        if $reparsed.attestation.type != "bitcoin" {
            {ok: false reason: $"upgraded attestation type is ($reparsed.attestation.type), expected bitcoin"}
        } else {
            {ok: true}
        }
    } catch {|e|
        {ok: false reason: $e.msg}
    }
    if not $validation.ok {
        error make {msg: $"upgrade aborted, original untouched: ($validation.reason)"}
    }

    let tmp_out = $"($ots_file).new"
    $upgraded | save --raw --force $tmp_out
    mv $tmp_out $ots_file
    {status: "upgraded" path: $ots_file}
}

# Print a human summary of a verify result and, under --fail, turn an invalid
# proof into a non-zero exit (matching git-proof/ssh-sign verify).
def emit-verify [result: record, fail: bool]: nothing -> record {
    if $result.valid {
        print $"✓ Bitcoin block ($result.height) verified independently"
        print $"  block hash:    ($result.block_hash)"
        print $"  block time:    ($result.block_time | format date '%Y-%m-%d %H:%M:%S UTC')"
        print $"  merkle root:   ($result.merkle_root)"
        # Why the label branches: one responder means no cross-check happened —
        # the height->hash mapping rests on that single explorer. Printing
        # "cross-checked" there would claim agreement that was never tested.
        if ($result.sources_confirmed | length) > 1 {
            print $"  cross-checked: ($result.sources_confirmed | str join ', ')"
        } else {
            print $"  single source: ($result.sources_confirmed | str join ', ') \(no cross-check — only one explorer answered\)"
        }
        if $result.content_verified == true { print "  content:       matches the proof commitment" }
    } else {
        print $"✗ verification failed: ($result.error)"
    }
    if $fail and (not $result.valid) {
        error make {msg: $"proof invalid: ($result.error)"}
    }
    $result
}

# GET an Esplora endpoint, returning its trimmed text body or null on any
# non-200 / transport error (so a single flaky mirror doesn't abort the run).
def esplora-get [url: string]: nothing -> any {
    let r = try { http get --full --allow-errors $url } catch { return null }
    if $r.status != 200 { return null }
    $r.body | into string | str trim
}

# Independently verify a Bitcoin-anchored OTS proof against real block headers.
# Why: `info`/`upgrade` only echo the block height the calendar reported —
# nothing checks it against Bitcoin. This does. It looks the height up on
# independent explorers, requires every explorer that answers to agree on the
# block hash, then fetches the raw 80-byte header and self-verifies the
# merkle-root binding, the block hash, and the proof-of-work. The explorers are
# trusted only for the height->hash mapping; every cryptographic claim is
# recomputed locally. If only one explorer answers there is no cross-check at
# all — `sources_confirmed` names the single source relied on, and the printed
# output labels it as such rather than claiming agreement.
#
# Returns a uniform record {valid, height, block_hash, block_time, merkle_root,
# file_hash, content_verified, sources_confirmed, error}. A well-formed proof
# that does not match Bitcoin (or a --file that the proof does not commit to)
# is a `valid: false` result, not an error. Operational failures — a pending
# proof, no reachable explorer, explorers disagreeing — throw, since validity
# cannot be asserted. --fail turns a `valid: false` into a non-zero exit (CI).
#   --file:    also confirm the proof commits to this content (closes the loop)
#   --sources: Esplora-compatible API bases to cross-check
@example "verify an anchor, failing on invalid (for CI)" { ots verify proof.ots --fail }
export def verify [
    ots_file: path
    --file: path
    --sources: list<string> = $DEFAULT_EXPLORERS
    --fail # Exit non-zero on an invalid proof (for CI)
] {
    let parsed = open --raw $ots_file | parse-ots

    match $parsed.attestation.type {
        "pending" => { error make {msg: $"proof is still pending on calendar ($parsed.attestation.url) — run `ots upgrade` after Bitcoin confirms it, then verify"} }
        "bitcoin" => {}
        $other => { error make {msg: $"unsupported attestation type: ($other)"} }
    }

    let height = $parsed.attestation.height
    # Replaying the ops yields the value the attestation binds to: the block's
    # merkle root (internal byte order).
    let expected_root = $parsed.hash | replay-ops $parsed.ops
    let base = {
        valid: false height: $height file_hash: ($parsed.hash | encode hex | str lowercase)
        block_hash: null block_time: null merkle_root: null
        content_verified: null sources_confirmed: [] error: null
    }

    # Content binding (if requested): a mismatch means the proof does not cover
    # this file — an invalid result, not an error.
    let content_verified = if $file != null {
        (open --raw $file | hash sha256 | decode hex) == $parsed.hash
    } else { null }
    if $content_verified == false {
        return (emit-verify ($base | merge {content_verified: false error: $"content mismatch: ($file) is not what the proof commits to"}) $fail)
    }

    # Cross-check height -> block hash across independent explorers.
    # Why a for loop, not `each`: a `try`/`catch` wrapping `http get` inside an
    # `each` closure trips a Nushell runtime error across iterations; the plain
    # loop is unaffected. See todo/ note.
    mut lookups = []
    for src in $sources {
        $lookups = ($lookups | append {source: $src hash: (esplora-get $"($src)/block-height/($height)")})
    }
    let ok_lookups = $lookups | where hash != null
    if ($ok_lookups | is-empty) {
        error make {msg: $"no explorer returned block ($height) — cannot verify"}
    }
    let distinct = $ok_lookups | get hash | each { str lowercase } | uniq
    if ($distinct | length) > 1 {
        error make {msg: $"explorers disagree on block ($height): ($distinct | str join ', ')"}
    }
    let block_hash = $distinct | first

    let src = $ok_lookups | first | get source
    let header_hex = esplora-get $"($src)/block/($block_hash)/header"
    if $header_hex == null {
        error make {msg: $"could not fetch the header for block ($block_hash)"}
    }

    # Self-verify the header. A failure here means the proof does not match the
    # real block -> invalid proof, not an operational error.
    let checked = try { check-block-header ($header_hex | decode hex) $expected_root $block_hash } catch {|e| {error: $e.msg} }
    let confirmed = $ok_lookups | get source
    if ($checked.error? != null) {
        return (emit-verify ($base | merge {block_hash: $block_hash sources_confirmed: $confirmed error: $checked.error}) $fail)
    }

    emit-verify ($base | merge {
        valid: true
        block_hash: $checked.block_hash
        block_time: $checked.time
        merkle_root: $checked.merkle_root
        content_verified: $content_verified
        sources_confirmed: $confirmed
    }) $fail
}
