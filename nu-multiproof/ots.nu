# Pure Nushell OpenTimestamps implementation — no `ots` CLI dependency.
# Handles linear proof chains only (single-path, no merkle tree forks).

use _ots-helpers.nu copy-path-for
use _varint.nu encode-varint
use _repo.nu repo-root
use _layout.nu ots-dir

const HEADER_MAGIC = 0x[00 4f70656e54696d657374616d7073 0000 50726f6f66 00 bf89e2e884e89294]
const OP_SHA256 = 0x08
const OP_RIPEMD160 = 0x03
const OP_APPEND = 0xf0
const OP_PREPEND = 0xf1
const TAG_ATTESTATION = 0x00
const TAG_FORK = 0xff
const ATT_PENDING = 0x[83dfe30d2ef90c8e]
const ATT_BITCOIN = 0x[0588960d73d71901]
const DEFAULT_CALENDAR = "https://a.pool.opentimestamps.org"

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
                {type: "unknown" tag: ($att_tag | encode hex)}
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
        hash: ($parsed.hash | encode hex)
        ops: (
            $parsed.ops | each {|op|
                match $op.type {
                    "append" => {type: "append" data: ($op.data | encode hex)}
                    "prepend" => {type: "prepend" data: ($op.data | encode hex)}
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
    # Snapshot any sibling `<file>.<signer>.sig` next to the frozen copy so
    # the binding survives the next `seal` (which overwrites the live sig).
    let sigs = glob $"($file).*.sig"
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
        let hash_hex = $current_hash | encode hex
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
