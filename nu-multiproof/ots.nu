# Pure Nushell OpenTimestamps implementation — no `ots` CLI dependency.
# Handles linear proof chains only (single-path, no merkle tree forks).

use _ots-helpers.nu copy-path-for

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

# LEB128 varuint encode
def encode-varuint []: int -> binary {
    mut n = $in
    mut out = 0x[]
    while $n >= 128 {
        let byte = ($n mod 128) | bits or 128
        $out = ($out | bytes add --end ($byte | into binary | bytes at 0..0))
        $n = $n // 128
    }
    $out | bytes add --end ($n | into binary | bytes at 0..0)
}

# LEB128 varuint decode at offset
def parse-varuint [offset: int]: binary -> record<value: int, offset: int> {
    let buf = $in
    mut value = 0
    mut shift = 1
    mut pos = $offset
    loop {
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

# Display info about an .ots proof file
export def info [ots_file: path] {
    let parsed = open --raw $ots_file | parse-ots

    mut lines = [
        $"File sha256 hash: ($parsed.hash | encode hex)"
        "Timestamp:"
    ]

    for op in $parsed.ops {
        $lines = $lines ++ [
            (
                match $op.type {
                    "sha256" => "  sha256"
                    "append" => $"  append ($op.data | encode hex)"
                    "prepend" => $"  prepend ($op.data | encode hex)"
                    _ => $"  ($op.type)"
                }
            )
        ]
    }

    let att = $parsed.attestation
    $lines = $lines ++ [
        (
            match $att.type {
                "pending" => $"  verify PendingAttestation\(\"($att.url)\"\)"
                "bitcoin" => $"  verify BitcoinBlockHeaderAttestation\(($att.height)\)"
                _ => $"  verify UnknownAttestation\(($att.tag)\)"
            }
        )
    ]

    $lines | str join "\n"
}

# Create an OTS timestamp proof for a file
export def stamp [file: path --out-dir: path] {
    let out_dir = if $out_dir != null { $out_dir } else {
        let git_root = ^git rev-parse --show-toplevel | str trim
        $git_root | path join "multiproofs/ots-timestamps"
    }
    let file_hash = open --raw $file | hash sha256 | decode hex
    let nonce = random binary 16
    let merkle_tip = $file_hash | bytes add --end $nonce | hash sha256 | decode hex

    let tmp = mktemp
    $merkle_tip | save --raw --force $tmp
    # Why: /digest expects raw bytes; application/x-www-form-urlencoded was
    # misleading and could break with stricter calendar servers.
    let status = (
        ^curl --silent --show-error
        --write-out "%{http_code}"
        --output $"($tmp).resp"
        --data-binary $"@($tmp)"
        --header "Content-Type: application/octet-stream"
        $"($DEFAULT_CALENDAR)/digest"
    )
    rm $tmp
    if $status != "200" {
        rm --force $"($tmp).resp"
        error make {msg: $"calendar returned status ($status)"}
    }
    let calendar_bytes = open --raw $"($tmp).resp"
    rm $"($tmp).resp"

    let nonce_len = ($nonce | bytes length) | encode-varuint
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
# --response-file: read the calendar response from a local file instead of
# fetching it. Why: enables offline tests of the splice/validate/write logic
# without a real calendar; also lets callers pre-fetch responses.
export def upgrade [ots_file: path --response-file: path] {
    let buf = open --raw $ots_file
    let parsed = $buf | parse-ots

    if $parsed.attestation.type != "pending" {
        print $"Already verified: ($parsed.attestation.type)"
        return
    }

    let new_bytes = if $response_file != null {
        open --raw $response_file
    } else {
        let current_hash = $parsed.hash | replay-ops $parsed.ops
        let hash_hex = $current_hash | encode hex
        let url = $"($parsed.attestation.url)/timestamp/($hash_hex)"
        let tmp = mktemp
        let status = (
            ^curl --silent --show-error
            --write-out "%{http_code}"
            --output $tmp
            --header "Accept: application/vnd.opentimestamps.v1"
            $url
        )
        if $status == "404" {
            rm $tmp
            error make {msg: "timestamp not yet confirmed by Bitcoin — try again later"}
        }
        if $status != "200" {
            rm $tmp
            error make {msg: $"calendar returned status ($status)"}
        }
        let bytes = open --raw $tmp
        rm $tmp
        $bytes
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
    print $"Upgraded: ($ots_file)"
}
