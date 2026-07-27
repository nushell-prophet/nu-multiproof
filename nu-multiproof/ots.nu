# Pure Nushell OpenTimestamps implementation — no `ots` CLI dependency.
# Handles linear proof chains only (single-path, no merkle tree forks).

use _ots-helpers.nu [copy-path-for check-block-header check-fetched-header]
use _varint.nu encode-varint
use _repo.nu repo-root
use _layout.nu ots-dir
use _sig.nu sig-files-for

const HEADER_MAGIC = 0x[00 4f70656e54696d657374616d7073 0000 50726f6f66 00 bf89e2e884e89294]
# Op tags stay byte literals throughout (0x08 sha256, 0x03 RIPEMD-160, 0xf0
# append, 0xf1 prepend): `match` arms must be literal patterns, and `stamp`
# writes raw bytes (0x[f0]) where an int const would need converting first.
# OP_SHA256 used to be a const here and was bypassed at three of its four
# sites — a name spelled one way and meant another is worse than the byte.
const TAG_ATTESTATION = 0x00
const TAG_FORK = 0xff
const ATT_PENDING = 0x[83dfe30d2ef90c8e]
const ATT_BITCOIN = 0x[0588960d73d71901]
const DEFAULT_CALENDAR = "https://a.pool.opentimestamps.org"
# Parent domains of the calendars `upgrade` may contact. The URL it fetches is
# read out of the .ots file, which is attacker-controlled input: a proof
# carrying `http://127.0.0.1:18777/EXFIL` made this repo GET that path and tell
# the user only "not yet confirmed by Bitcoin", handing the host the digest of
# private content out of band. The reference client gates the same URL through
# UrlWhitelist (otsclient/cmds.py:284); this list is its DEFAULT_CALENDAR_WHITELIST
# (python-opentimestamps calendar.py:150-154) with the `*.` written as a
# suffix rather than a glob. `--calendar` is the override for anything else.
const CALENDAR_ALLOWLIST = [
    "calendar.opentimestamps.org"
    "calendar.eternitywall.com"
    "calendar.catallaxy.com"
]
# Every outbound call is bounded. Without it a black-holed connection hangs
# `stamp`, `upgrade` and `verify` with no output and no way back but Ctrl-C —
# and `seal` runs `upgrade` over every archived stamp in a loop. 30s is well
# past the calendars' and explorers' normal response time.
const NETWORK_TIMEOUT = 30sec
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

# The URI of a pending attestation, as bytes read out of the .ots file.
#
# Why the length is measured on the bytes and the charset on the decoded
# string: `decode utf-8` is lossy — invalid bytes become U+FFFD — so `ots info`
# would otherwise print a URL that is not what the file holds, and that
# silently normalized string is what `upgrade` would contact. Checking after
# the decode is safe only because every allowed character is ASCII: U+FFFD is
# outside the set, and so is every character a multi-byte sequence can decode
# to, so no byte sequence survives normalization into something accepted.
# The length must be measured before, though — 1000 bytes is not 1000 chars.
# Reject, never normalize. The limit and the character set are the reference
# client's (notary.py:165-186); pinned by tests/test_ots.nu — the set by "the
# accepted URI charset is exactly the reference set", the cap by "the pending
# URI length cap is the reference client 1000 bytes" — since nothing in this
# repo carries that file and a comment naming an absent source is not a check.
def check-uri [raw: binary]: nothing -> string {
    if ($raw | bytes length) > 1000 {
        error make {msg: "malformed OTS file: pending attestation URI exceeds 1000 bytes"}
    }
    let uri = $raw | decode utf-8
    if not ($uri =~ '^[A-Za-z0-9\-._/:]*$') {
        error make {msg: "malformed OTS file: pending attestation URI holds characters the format does not allow"}
    }
    $uri
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

            # Why the payload must be fully consumed: the reference
            # deserializer wraps each attestation payload in its own context and
            # ends it with assert_eof (notary.py:92). Without that, trailing
            # bytes inside the payload parse here and are rejected everywhere
            # else — and `stamp`/`upgrade` validate by calling this parser, so a
            # looser parser makes the validate-before-write guard pass bytes the
            # format refuses. Pinned by test_ots.nu "attestation payload with
            # trailing bytes is refused".
            let payload_len = $vb.bytes | bytes length
            let attestation = if $att_tag == $ATT_PENDING {
                let inner = $vb.bytes | parse-varbytes 0
                if $inner.offset != $payload_len {
                    error make {msg: "malformed OTS file: trailing bytes inside the pending attestation payload"}
                }
                {type: "pending" url: (check-uri $inner.bytes)}
            } else if $att_tag == $ATT_BITCOIN {
                let height = $vb.bytes | parse-varuint 0
                if $height.offset != $payload_len {
                    error make {msg: "malformed OTS file: trailing bytes inside the bitcoin attestation payload"}
                }
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
    if $hash_op_byte != 0x08 {
        error make {msg: $"unsupported file hash algorithm: ($hash_op_byte)"}
    }

    let hash_start = $ver.offset + 1
    let hash_end = $hash_start + 31
    let file_hash = $buf | bytes at $hash_start..($hash_end)

    let ts = $buf | parse-timestamp ($hash_end + 1)

    # Why: parse-timestamp returns at the first attestation, so without this a
    # file carrying anything after it parses clean here and is
    # TrailingGarbageError to the reference deserializer (timestamp.py:339
    # ctx.assert_eof). `stamp` and `upgrade` validate what they are about to
    # write by calling this parser — a parser looser than the format turns that
    # guard into a rubber stamp, and a calendar answering with 4 junk bytes
    # appended produced an unreadable .ots and exit 0. Pinned by test_ots.nu
    # "a proof with bytes after the attestation is refused".
    if $ts.offset != ($buf | bytes length) {
        error make {msg: $"malformed OTS file: ($buf | bytes length) bytes, but the proof ends at ($ts.offset)"}
    }

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
    let parsed = open --raw $ots_file | into binary | parse-ots
    {
        # Why str lowercase: `encode hex` emits uppercase, but every persisted
        # hash in this project (tree-hashes.csv, proof files) is lowercase —
        # it comes from `hash sha256`/git. Lowercase is canonical.
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
#
# --response-file: read the calendar's answer from a local file instead of
# posting the digest. Same seam as `upgrade --response-file`, and for the same
# reason: without it the assemble/validate/write path can only be exercised
# against a live calendar, so it was not exercised at all.
#
# The live form is `ots stamp multiproofs/tree-hashes.csv` with no flags — it
# posts the file's digest to the public calendar, a permanent public write, so
# it is named here in prose rather than in the @example: an example must be
# safe to paste. A fully runnable offline example is impossible for this
# command — a valid calendar answer only ever comes from a calendar — so the
# example shows the offline seam and fails locally when the file is absent.
@example "assemble a proof from a saved calendar answer, offline" { ots stamp multiproofs/tree-hashes.csv --response-file calendar-answer.bin }
export def stamp [file: path --out-dir: path --response-file: path] {
    let out_dir = if $out_dir != null { $out_dir } else {
        ots-dir (repo-root)
    }
    let file_hash = open --raw $file | hash sha256 | decode hex
    let nonce = random binary 16
    let merkle_tip = $file_hash | bytes add --end $nonce | hash sha256 | decode hex

    let calendar_bytes = if $response_file != null {
        open --raw $response_file | into binary
    } else {
        # Why http builtin (not curl): no external dep and no temp files. --full
        # exposes the status, --allow-errors returns a non-200 instead of throwing
        # raw, and /digest expects raw bytes (application/octet-stream).
        let response = (
            http post --full --allow-errors --raw --max-time $NETWORK_TIMEOUT
            --content-type "application/octet-stream"
            $"($DEFAULT_CALENDAR)/digest"
            $merkle_tip
        )
        if $response.status != 200 {
            error make {msg: $"calendar returned status ($response.status)"}
        }
        # Why --raw + into binary: the body's shape used to depend on the
        # Content-Type the calendar chose. An application/json body arrived as
        # a record, so `bytes add` threw a type error naming neither the
        # calendar nor the cause; an all-ASCII body arrived as a string. --raw
        # stops the content-type parsing; into binary covers the string case.
        # Measured limit (0.114.1, no flag turns it off): a text/* body with a
        # non-UTF-8 charset is transcoded to UTF-8 at the HTTP layer, before
        # either of these — such a body still arrives corrupted, and the
        # rejected-recovery file then keeps the transcoding, not what the
        # calendar sent. Not pinned by a test: triggering any of this needs a
        # live server choosing the header, and the suite has no local one.
        $response.body | into binary
    }

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

    # Why parse what we just built, before anything is written: only the HTTP
    # status was checked, so a calendar answering 200 with `b"x"` produced a
    # full success record, exit 0, and an .ots that `info` rejects with
    # "unknown op tag: 60". `upgrade` has validated before writing since
    # 2844626; `stamp` never did.
    let validation = try {
        let reparsed = $ots | parse-ots
        if $reparsed.hash != $file_hash {
            {ok: false reason: "the assembled proof does not commit to this file's hash"}
        } else if $reparsed.attestation.type == "unknown" {
            {ok: false reason: $"unknown attestation type ($reparsed.attestation.tag)"}
        } else {
            {ok: true}
        }
    } catch {|e|
        {ok: false reason: $e.msg}
    }
    if not $validation.ok {
        # Why the rejected bytes are still written: the digest already reached
        # the calendar, and the nonce that binds it to this file exists only in
        # this run — dropping both is the same unrecoverable loss the guard
        # above exists to prevent, just moved to the failure path. The bundle
        # is untouched, so nothing here is mistaken for a proof; these bytes
        # are the only material a later recovery (or the reference `ots` CLI,
        # which reads constructs this parser refuses, such as forks) can work
        # from. Named for the moment AND for its own bytes: the timestamp
        # alone repeats within one second, and --force then let a second
        # failing stamp silently swallow the first one's nonce — three failing
        # stamps in a second left one file. Bound to the proof's hash (like
        # the parked-file branch below), a name collision can only be the same
        # bytes. Pinned by tests/test_ots.nu "rejected stamps in the same
        # second each keep their nonce".
        mkdir $out_dir
        let rejected = $"($out_dir)/($stem).($hash_prefix).rejected-(date now | format date '%Y%m%d-%H%M%S')-($ots | hash sha256 | str substring 0..<8).ots"
        $ots | save --raw $rejected
        error make {msg: ([
            $"calendar response does not make a readable proof: ($validation.reason)"
            $"no bundle was written; the assembled bytes \(nonce included\) are at ($rejected)"
        ] | str join "\n")}
    }

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
    # existing one to <stem>.<timestamp>-<proof-hash-prefix>.ots so the prior
    # proof survives.
    #
    # Why the name also carries the archived proof's own hash: `mv` overwrites
    # its destination (measured on 0.114.1, no flag needed) and
    # %Y%m%d-%H%M%S repeats for two stamps in the same second — three stamps
    # inside one second left two files, one proof gone with every run exiting 0.
    # Binding the name to the bytes means a collision can only be the same
    # proof, so it costs nothing. Pinned by tests/test_ots.nu "rapid re-stamps
    # each keep their own proof".
    let now = date now | format date "%Y%m%d-%H%M%S"
    if ($ots_path | path exists) {
        let previous_tag = open --raw $ots_path | into binary | hash sha256 | str substring 0..<8
        let archived = $"($bundle_dir)/($stem).($now)-($previous_tag).ots"
        mv $ots_path $archived
        print $"Archived previous: ($archived)"
    }

    cp $file $copy_path
    # Why save without --force: the `path exists` test above and this write are
    # two steps, so two stamps racing on one bundle both saw no incumbent, both
    # wrote through --force, and one proof was gone with both runs exiting 0.
    # Refusing an occupied destination keeps what is there, and this run's bytes
    # go beside it rather than nowhere — the nonce binding them to this file
    # exists only in this run (same reasoning as the rejected-response path
    # above), and a proof under the archival name is what `merkle verify`
    # already discovers by content. Measured limit: nushell's `save` tests for
    # the file and then creates it, so this narrows the race, it does not close
    # it.
    try {
        $ots | save --raw $ots_path
    } catch {|e|
        let parked = $"($bundle_dir)/($stem).($now)-($ots | hash sha256 | str substring 0..<8).ots"
        $ots | save --raw --force $parked
        error make {msg: ([
            $"could not write ($ots_path): ($e.msg)"
            $"this run's assembled proof \(nonce included\) is at ($parked)"
        ] | str join "\n")}
    }
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

# Refuse to contact a calendar URL the proof named unless it is one of ours.
#
# Matches the reference's UrlWhitelist rules (calendar.py:131-145): scheme and
# path must equal the pattern's, the host is matched against `*.<domain>`, and
# a URL carrying params, a query or a fragment never matches. The extra port /
# userinfo rejections are the same rule stated directly — the reference globs
# the whole netloc, so `evil.com:8080` and `x@evil.com` fail there too.
#
# Not a glob here: `str ends-with` on a value that came from a file. This repo
# has already been bitten by feeding data-derived text to glob.
def check-calendar-url [url: string] {
    let u = try { $url | url parse } catch {
        error make {msg: $"refusing to contact the calendar named in the proof: ($url) is not a URL"}
    }
    let allowed = (
        $u.scheme == "https"
        and ($CALENDAR_ALLOWLIST | any {|d| $u.host | str ends-with $".($d)" })
        and $u.port == "" and $u.username == "" and $u.password == ""
        and $u.path in ["" "/"] and $u.query == "" and $u.fragment == ""
    )
    if not $allowed {
        error make {
            msg: $"refusing to contact the calendar named in the proof: ($url)"
            help: $"the URL comes from the .ots file itself. Allowed: https://*.($CALENDAR_ALLOWLIST | str join ', https://*.'). Pass --calendar <url> to contact another one deliberately."
        }
    }
}

# Upgrade a pending OTS attestation to a Bitcoin block header attestation.
# Returns {status: "upgraded" | "already-verified", path}.
# --response-file: read the calendar response from a local file instead of
# fetching it. Why: enables offline tests of the splice/validate/write logic
# without a real calendar; also lets callers pre-fetch responses.
# --calendar: contact this calendar instead of the one named in the proof.
# Why an override and not a wider allowlist: the URL in the file is attacker
# input, the URL on the command line is the operator's decision.
@example "upgrade a pending proof once Bitcoin confirms it" { ots upgrade proof.ots }
export def upgrade [ots_file: path --response-file: path --calendar: string] {
    let buf = open --raw $ots_file | into binary
    let parsed = $buf | parse-ots

    if $parsed.attestation.type != "pending" {
        return {status: "already-verified" path: $ots_file}
    }

    let new_bytes = if $response_file != null {
        open --raw $response_file | into binary
    } else {
        let current_hash = $parsed.hash | replay-ops $parsed.ops
        # Why str lowercase: same canonical-hex rule as `info` above. The
        # reference calendar unhexlifies server-side and accepts either case,
        # but this is the one hash this project sends off the machine — it
        # should not ride on another server's undocumented tolerance.
        let hash_hex = $current_hash | encode hex | str lowercase
        let base_url = if $calendar != null { $calendar } else {
            check-calendar-url $parsed.attestation.url
            $parsed.attestation.url
        }
        let url = $"($base_url)/timestamp/($hash_hex)"
        let response = (
            http get --full --allow-errors --raw --max-time $NETWORK_TIMEOUT
            --headers {Accept: "application/vnd.opentimestamps.v1"}
            $url
        )
        if $response.status == 404 {
            error make {msg: "timestamp not yet confirmed by Bitcoin — try again later"}
        }
        if $response.status != 200 {
            error make {msg: $"calendar returned status ($response.status)"}
        }
        # Why --raw + into binary: same as the calendar POST in `stamp` —
        # without them the body's shape depends on the Content-Type the server
        # chose. The charset-transcoding limit measured there applies here too.
        $response.body | into binary
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
# proof into a non-zero exit (matching merkle/ssh-sign verify).
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
    let r = try { http get --full --allow-errors --max-time $NETWORK_TIMEOUT $url } catch { return null }
    if $r.status != 200 { return null }
    $r.body | into string | str trim
}

# Fetch a block header from one explorer and hand back its 80 bytes.
#
# Why the answer is checked here (check-fetched-header) and not in the `try`
# around check-block-header: everything about the fetched answer — did an
# explorer respond, is it hex, is it header-sized, does it hash to the
# cross-checked block hash at all — is operational and must throw. Folded into
# that `try` it became `valid: false`, which handed the one explorer serving
# the header a one-request veto over any valid proof: a 200 carrying an HTML
# error page — or a header with a single flipped byte — read as "this proof
# does not match Bitcoin", and `--fail` exited non-zero on it. The block hash
# was already cross-checked by --min-sources explorers before this fetch, so a
# header that does not hash to it can only be this explorer's fault — the
# "outage, not a verdict" class. check-block-header keeps its own 80-byte and
# claimed-hash guards as preconditions for its other callers; from this path
# they can no longer fire.
def fetch-header [src: string, block_hash: string]: nothing -> binary {
    let header_hex = esplora-get $"($src)/block/($block_hash)/header"
    if $header_hex == null {
        error make {msg: $"could not fetch the header for block ($block_hash) from ($src)"}
    }
    check-fetched-header $src $block_hash $header_hex
}

# Independently verify a Bitcoin-anchored OTS proof against real block headers.
# Why: `info`/`upgrade` only echo the block height the calendar reported —
# nothing checks it against Bitcoin. This does. It looks the height up on
# independent explorers, requires every explorer that answers to agree on the
# block hash, then fetches the raw 80-byte header and self-verifies the
# merkle-root binding and the block hash. The explorers are trusted only for
# the height->hash mapping; both cryptographic claims are recomputed locally.
# Nothing here bounds the work behind the header — see _ots-helpers.nu
# check-block-header and README "Verifying a timestamp". So the cross-check is
# the whole defence, and --min-sources is what makes it mandatory: below it
# this refuses to answer rather than resting on a single explorer, which would
# be choosing the block hash and the reported time at once.
#
# Returns a uniform record {valid, height, block_hash, block_time, merkle_root,
# file_hash, content_verified, sources_confirmed, error}. A well-formed proof
# that does not match Bitcoin (or a --file that the proof does not commit to)
# is a `valid: false` result, not an error. Operational failures — a pending
# proof, too few reachable explorers, explorers disagreeing — throw, since
# validity cannot be asserted. --fail turns a `valid: false` into a non-zero
# exit (CI).
#   --file:        also confirm the proof commits to this content (closes the loop)
#   --sources:     Esplora-compatible API bases to cross-check
#   --min-sources: how many must answer and agree before a result is asserted
@example "verify an anchor, failing on invalid (for CI)" { ots verify proof.ots --fail }
export def verify [
    ots_file: path
    --file: path
    --sources: list<string> = $DEFAULT_EXPLORERS
    --min-sources: int = 2 # Explorers that must agree before a result is asserted
    --fail # Exit non-zero on an invalid proof (for CI)
] {
    if $min_sources < 1 {
        error make {msg: "--min-sources must be at least 1"}
    }
    let parsed = open --raw $ots_file | into binary | parse-ots

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
    let lookups = $sources | each {|src|
        {source: $src hash: (esplora-get $"($src)/block-height/($height)")}
    }
    let ok_lookups = $lookups | where hash != null
    if ($ok_lookups | is-empty) {
        error make {msg: $"no explorer returned block ($height) — cannot verify"}
    }
    # Why this throws instead of returning valid: false — and why it exists at
    # all. Nothing below bounds the work behind the header, so the cross-check
    # IS the defence. With one responder there is none: whoever answers serves
    # the height -> hash mapping and a header they made, and the header supplies
    # block_time, which this command reports as the timestamp. The attacker
    # would set the date — the one claim the whole system exists to make. One
    # explorer timing out was enough to arrange that, and the old code answered
    # valid: true with no field a consumer could key on to notice.
    # Throwing, not valid: false, because this is the same class as "no
    # explorer answered": validity could not be asserted, and calling a good
    # proof invalid is its own false statement.
    if ($ok_lookups | length) < $min_sources {
        error make {
            msg: $"only ($ok_lookups | length) of ($sources | length) explorers answered for block ($height), below --min-sources ($min_sources) — cannot verify"
            help: "a single responder is not a cross-check: it would choose both the block hash and the time this reports. Retry, add --sources, or pass --min-sources 1 to accept one source deliberately."
        }
    }
    let distinct = $ok_lookups | get hash | each { str lowercase } | uniq
    if ($distinct | length) > 1 {
        error make {msg: $"explorers disagree on block ($height): ($distinct | str join ', ')"}
    }
    let block_hash = $distinct | first

    let src = $ok_lookups | first | get source
    let header_bytes = fetch-header $src $block_hash

    # Self-verify the header. A failure here means the proof does not match the
    # real block -> invalid proof, not an operational error. Everything about
    # the explorer's answer itself — its shape, and whether it is the
    # cross-checked block's header at all — was settled in fetch-header, above;
    # inside this try it would read as "invalid proof". Only the merkle-root
    # binding is left to fail here, and that mismatch is about the proof.
    let checked = try { check-block-header $header_bytes $expected_root $block_hash } catch {|e| {error: $e.msg} }
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
