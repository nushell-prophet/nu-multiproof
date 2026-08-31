# The Esplora-compatible block explorer layer, shared by `ots verify` and `beacon`.
#
# Why one module and not a copy per caller: nothing in this repo bounds the work
# behind a block header (see _ots-helpers.nu check-block-header), so the
# height -> hash cross-check across independent explorers IS the whole defence
# for every claim built on Bitcoin here. A second implementation of it is a
# second place for that defence to be weakened by accident, and the two callers
# ask the same question in opposite directions: `ots verify` checks a height a
# proof names, `beacon latest` picks a height to name.

use _ots-helpers.nu check-fetched-header

# Every outbound call is bounded. Without it a black-holed connection hangs
# `stamp`, `upgrade`, `verify` and `beacon latest` with no output and no way
# back but Ctrl-C — and `seal` runs `upgrade` over every archived stamp in a
# loop. 30s is well past the calendars' and explorers' normal response time.
export const NETWORK_TIMEOUT = 30sec

# Esplora-compatible block explorers, queried independently and cross-checked
# so no answer rests on a single source. Both expose the same routes:
#   /blocks/tip/height   -> the tip height
#   /block-height/<h>    -> block hash
#   /block/<hash>/header -> raw 80 bytes
export const DEFAULT_EXPLORERS = [
    "https://mempool.space/api"
    "https://blockstream.info/api"
]

# --min-sources 0 would mean "answer with no explorer agreeing at all", which is
# the one configuration none of this may offer. Checked by each command before
# anything is read or written, so it fails offline and costs nothing.
export def check-min-sources [min_sources: int]: nothing -> nothing {
    if $min_sources < 1 {
        error make {msg: "--min-sources must be at least 1"}
    }
}

# GET an Esplora endpoint, returning its trimmed text body or null on any
# non-200 / transport error (so a single flaky mirror doesn't abort the run).
export def esplora-get [url: string]: nothing -> any {
    let r = try { http get --full --allow-errors --max-time $NETWORK_TIMEOUT $url } catch { return null }
    if $r.status != 200 { return null }
    $r.body | into string | str trim
}

# The block hash at one height, agreed by independent explorers.
#
# Why this throws rather than returning a verdict, in all three failures: the
# explorers are trusted for exactly one thing — the height -> hash mapping —
# and with one responder there is no cross-check at all. Whoever answers then
# serves the hash and, through the header fetched by it, the time. Every caller
# builds a dated claim on that, so "could not be cross-checked" must not be
# reachable as a green answer, and it is not a verdict about the artifact
# either: a proof is not invalid because two explorers timed out.
export def block-hash-at [
    height: int
    sources: list<string>
    min_sources: int
]: nothing -> record<hash: string, sources_confirmed: list<string>> {
    let lookups = $sources | each {|src|
            {source: $src hash: (esplora-get $"($src)/block-height/($height)")}
        }
    let ok_lookups = $lookups | where hash != null
    if ($ok_lookups | is-empty) {
        error make {msg: $"no explorer returned block ($height) — cannot continue"}
    }
    if ($ok_lookups | length) < $min_sources {
        error make {
            msg: $"only ($ok_lookups | length) of ($sources | length) explorers answered for block ($height), below --min-sources ($min_sources) — cannot continue"
            help: "a single responder is not a cross-check: it would choose both the block hash and the time this reports. Retry, add --sources, or pass --min-sources 1 to accept one source deliberately."
        }
    }
    # Case-folded before comparison: two explorers serving the same hash in
    # different case are agreeing, and the fold is also what makes the returned
    # value canonical for the callers that write it into a signed statement.
    let distinct = $ok_lookups | get hash | str lowercase | uniq
    if ($distinct | length) > 1 {
        error make {msg: $"explorers disagree on block ($height): ($distinct | str join ', ')"}
    }
    {hash: ($distinct | first) sources_confirmed: ($ok_lookups | get source)}
}

# Fetch a block header from one explorer and hand back its 80 bytes.
#
# Why the answer is checked here (check-fetched-header) and not by the caller's
# `try` around a verdict: everything about the fetched answer — did an explorer
# respond, is it hex, is it header-sized, does it hash to the cross-checked
# block hash at all — is operational and must throw. Folded into a verdict it
# became `valid: false`, which handed the one explorer serving the header a
# one-request veto over any valid proof: a 200 carrying an HTML error page — or
# a header with a single flipped byte — read as "this proof does not match
# Bitcoin", and `--fail` exited non-zero on it. The block hash was already
# cross-checked by --min-sources explorers before this fetch, so a header that
# does not hash to it can only be this explorer's fault.
export def fetch-header [src: string block_hash: string]: nothing -> binary {
    let header_hex = esplora-get $"($src)/block/($block_hash)/header"
    if $header_hex == null {
        error make {msg: $"could not fetch the header for block ($block_hash) from ($src)"}
    }
    check-fetched-header $src $block_hash $header_hex
}

# The `time` field of a raw 80-byte header (bytes 68..71, little-endian).
#
# Read what this is worth. A block's timestamp is chosen by the miner, and
# consensus only requires it to exceed the median of the previous 11 blocks and
# to sit no more than two hours ahead of network-adjusted time — so it is an
# approximation, not a clock. The hard fact a beacon rests on is the block
# HEIGHT: its hash could not be known before that block was mined. This time is
# what makes the height readable to a human, and it is reported as the miner's
# claim, never as the bound itself.
export def header-time [header: binary]: nothing -> datetime {
    if ($header | bytes length) != 80 {
        error make {msg: $"expected an 80-byte header, got ($header | bytes length) bytes"}
    }
    # Those four bytes hold a Unix time in SECONDS. `into datetime` reads a bare
    # integer as nanoseconds, so scale first, then move the result to UTC.
    let unix_seconds = $header | bytes at 68..71 | into int --endian little
    $unix_seconds * 1_000_000_000 | into datetime | date to-timezone UTC
}

# The height every explorer that answered has already reached, minus a reorg
# margin — the block a beacon is minted from.
#
# Why the MINIMUM of the tips and not agreement: explorers legitimately sit at
# different heights, seconds apart, so requiring them to agree on the tip would
# fail constantly and say nothing. The minimum is the height all of them have.
#
# Why not the tip itself: a tip block can be orphaned. The explorers then serve
# a different hash at that height, and a beacon minted from it is unverifiable
# for the life of the seal — a permanent break bought for about an hour of
# tightness at the lower end. The depth is subtracted from the minimum, so the
# chosen block is at least that deep for every explorer asked.
export def tip-height [
    sources: list<string>
    min_sources: int
    depth: int
]: nothing -> int {
    let tips = $sources
        | each {|src| esplora-get $"($src)/blocks/tip/height" }
        | where $it != null
        # An explorer answering something that is not a height is not answering.
        | where $it =~ '^(0|[1-9][0-9]*)$'
        | each { into int }
    if ($tips | length) < $min_sources {
        error make {
            msg: $"only ($tips | length) of ($sources | length) explorers reported a chain tip, below --min-sources ($min_sources) — cannot continue"
            help: "a beacon minted from a single explorer's tip rests on that explorer alone. Retry, add --sources, or pass --min-sources 1 to accept one source deliberately."
        }
    }
    let height = ($tips | math min) - $depth
    if $height < 0 {
        error make {msg: $"chain tip ($tips | math min) is shallower than --depth ($depth) — no block at that depth exists"}
    }
    $height
}
