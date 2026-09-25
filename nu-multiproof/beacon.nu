# The seal's LOWER time bound.
#
# An OpenTimestamps proof bounds a seal from above: the calendar had this digest
# by block T, so the content existed no later than that. Nothing in it says the
# seal is not older, and a signature carries no time at all — so a statement
# written today fits a bundle from last year and nothing on disk contradicts it.
#
# A beacon closes that direction. It is a public value nobody could have known
# before a fixed moment; embedding one in the bytes the signer signs means the
# statement did not exist BEFORE that moment. The two anchors bracket the seal:
# the beacon blocks backdating, the OTS stamp blocks post-dating, and the claim
# is only as tight as the gap between the two blocks.
#
# What it does NOT prove: that the seal happened AT the beacon's time. A signer
# can hold a fresh beacon and sign a year later, and nothing here detects that;
# a signer can also pick an older block and weaken their own bound, which harms
# nobody else. Only backdating becomes impossible.
#
# The beacon is a Bitcoin block, named by height and hash — not because Bitcoin
# is the best beacon available, but because it is the only chain data this repo
# already trusts and already cross-checks. Any other source would add a second
# trust root, a second parser and a second outage story for a claim that is not
# stronger. The trust argument is `ots verify`'s, unchanged: independent
# explorers must agree on the height -> hash mapping, and nothing bounds the
# work behind a header (README "Verifying a timestamp").

use _explorer.nu [
    DEFAULT_EXPLORERS check-min-sources block-hash-at fetch-header tip-height sources-line
]
use _beacon-helpers.nu [BEACON_NONE beacon-token parse-beacon]
use _ots-helpers.nu header-time
use _merkle-helpers.nu parse-root-statement

# How deep below the chain tip a freshly minted beacon sits.
#
# Why not the tip itself: a tip block can be orphaned. The explorers then serve a
# different hash at that height, and a beacon minted from it is unverifiable for
# the life of the seal — a permanent break bought for about an hour of tightness
# at the lower end of a bound that is already a bound, not a clock. Six is the
# depth Bitcoin practice settled on for the same reason.
const DEFAULT_DEPTH = 6

# Mint a beacon: the cross-checked Bitcoin block `seal` embeds in the root
# statement. Reaches the network — two explorers by default.
#
# Cross-checking gates the mint too, though it buys something narrower here than
# at verification. What `--min-sources` rules out is an INVENTED block: the
# height picked below is resolved through the same agreed height -> hash lookup
# the verifier uses, so a hash no other explorer serves never reaches a signed
# statement, and a beacon nobody could ever check is never minted.
#
# What it does not rule out is a real but STALE tip. tip-height takes the
# minimum of the tips that answered, so one lagging explorer lowers the chosen
# height rather than breaking it. That is accepted, not overlooked: a beacon
# claims "not before", so an earlier block is a weaker claim and never a false
# one — the same reason a signer naming an old block deliberately harms nobody
# but itself.
@example "mint a beacon token for a seal (reaches the network)" { nu-multiproof beacon latest }
export def latest [
    --sources: list<string> = $DEFAULT_EXPLORERS # Esplora-compatible API bases to cross-check
    --min-sources: int = 2 # Explorers that must answer before a beacon is minted
    --depth: int = $DEFAULT_DEPTH # Blocks below the tip, for reorg safety
]: nothing -> record {
    check-min-sources $min_sources
    if $depth < 0 {
        error make {msg: "--depth must be zero or more blocks below the tip"}
    }
    let height = tip-height $sources $min_sources $depth
    let looked_up = block-hash-at $height $sources $min_sources
    # The header is fetched for its time alone, and the time is the miner's
    # claim, not the bound — see _ots-helpers.nu header-time. The height is the
    # fact: its hash could not have been named before that block was mined.
    let header = fetch-header ($looked_up.sources_confirmed | first) $looked_up.hash
    {
        token: (beacon-token $height $looked_up.hash)
        height: $height
        block_hash: $looked_up.hash
        block_time: (header-time $header)
        sources_confirmed: $looked_up.sources_confirmed
    }
}

# Print a human summary and, under --fail, turn a beacon that does not match
# Bitcoin into a non-zero exit (matching ots/merkle/ssh-sign verify).
def emit-verify [result: record fail: bool]: nothing -> record {
    if $result.valid {
        print $"✓ beacon block ($result.height) confirmed independently"
        print $"  block hash:    ($result.block_hash)"
        print $"  not before:    ($result.block_time | format date '%Y-%m-%d %H:%M:%S UTC') \(the miner's timestamp; the height is the fact\)"
        print (sources-line $result.sources_confirmed)
    } else {
        print $"✗ beacon check failed: ($result.error)"
    }
    if $fail and (not $result.valid) {
        error make {msg: $"beacon invalid: ($result.error)"}
    }
    $result
}

# Check a root statement's beacon against Bitcoin, and report the lower bound.
#
# A statement whose beacon names a height that does not carry that hash is
# `valid: false` — a verdict about the statement, not an outage. The ordinary
# cause is a reorg (which is what --depth exists to avoid), the other is a
# fabricated bound; neither is distinguishable from here, and both mean the same
# thing: this statement's lower bound cannot be relied on.
#
# Operational failures throw, as everywhere else in this repo: too few explorers
# answering, explorers disagreeing, a statement carrying no beacon at all. None
# of those is a fact about the statement, and calling a good beacon invalid is
# its own false statement.
@example "check the lower bound on a seal (reaches the network)" { nu-multiproof beacon verify multiproofs/tree-root.txt }
export def verify [
    statement: path # Root statement file (multiproofs/tree-root.txt, or a seal snapshot's copy)
    --sources: list<string> = $DEFAULT_EXPLORERS # Esplora-compatible API bases to cross-check
    --min-sources: int = 2 # Explorers that must answer and agree before a result is asserted
    --fail # Exit non-zero on a beacon that does not match Bitcoin (for CI)
]: nothing -> record {
    check-min-sources $min_sources
    let parsed = parse-root-statement $statement
    let beacon = parse-beacon $parsed.beacon
    if $beacon == null {
        error make {
            msg: $"($statement) carries no beacon \(($BEACON_NONE)\) — there is no lower bound to check"
            help: "an offline seal (`seal --no-stamp`) writes none. Re-seal with network access to mint one."
        }
    }

    let looked_up = block-hash-at $beacon.height $sources $min_sources
    # What the statement claims, before the verdict: the height and the hash are
    # its words, and sources_confirmed names who was asked. The branch below
    # merges only what the check itself decides, so both outcomes leave this
    # record in one shape.
    let stated = {
        valid: false
        height: $beacon.height
        block_hash: $beacon.hash
        block_time: null
        sources_confirmed: $looked_up.sources_confirmed
        error: null
    }
    let verdict = if $looked_up.hash == $beacon.hash {
        # Fetched inside this branch, after the hash matched, so it is only ever
        # the block the statement named. check-fetched-header (inside
        # fetch-header) throws if the explorer's bytes are not that block's
        # header — an outage, not a verdict.
        let header = fetch-header ($looked_up.sources_confirmed | first) $looked_up.hash
        {valid: true block_time: (header-time $header)}
    } else {
        {error: $"the statement's beacon names block ($beacon.height) as ($beacon.hash), but the explorers agree it is ($looked_up.hash) — a reorged or fabricated bound either way"}
    }
    emit-verify ($stated | merge $verdict) $fail
}
