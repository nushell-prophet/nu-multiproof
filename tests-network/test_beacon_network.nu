use std/assert
use std/testing *

use ../nu-multiproof/beacon.nu
use ../nu-multiproof/_merkle-helpers.nu root-statement
use ../nu-multiproof/_temp-helpers.nu with-temp-dir

# Tests that reach the public internet — see tests-network/test_ots_network.nu
# for why they are out of the default suite. Nothing here writes anywhere: a
# beacon is READ from the chain, so unlike the calendar post these are pure
# lookups against public explorers.
#
#   nu toolkit.nu test --network

const GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
const GENESIS_TIME = 2009-01-03T18:15:05Z

def statement-with [dir: path beacon: string]: nothing -> path {
    let file = $"($dir)/tree-root.txt"
    root-statement ("beacon test" | hash sha256) 0 "genesis" $beacon | save --raw --force $file
    $file
}

# The one end-to-end vector against real Bitcoin whose expected values can never
# drift: block 0 is the same block forever, and its timestamp is published in
# Bitcoin Core. Anything wrong with the height lookup, the header fetch or the
# time decode shows up as a mismatch against a constant, not against whatever
# the explorer happened to say.
@test
def "the genesis block verifies as a lower bound" [] {
    with-temp-dir "beacon-genesis" {|dir|
        let result = beacon verify (statement-with $dir $"bitcoin:0:($GENESIS_HASH)")
        assert $result.valid
        assert equal $result.height 0
        assert equal $result.block_hash $GENESIS_HASH
        assert equal $result.block_time $GENESIS_TIME
        # Not `>= 1`: below --min-sources verify throws rather than answering,
        # so reaching this line means the cross-check really happened.
        assert (($result.sources_confirmed | length) >= 2)
    }
}

# The reorg case and the fabricated case are indistinguishable from here, and
# both mean the same thing: the statement names a block Bitcoin does not have at
# that height, so its lower bound rests on nothing.
@test
def "a beacon naming the wrong block at its height is not valid" [] {
    with-temp-dir "beacon-wrong" {|dir|
        let wrong = "0000000000000000000000000000000000000000000000000000000000000001"
        let result = beacon verify (statement-with $dir $"bitcoin:0:($wrong)")
        assert not $result.valid
        assert ($result.error | str contains $GENESIS_HASH)
        # A verdict, not a throw: the explorers answered and agreed, and what
        # they agreed on contradicts the statement.
        assert equal $result.block_hash $wrong
    }
}

# What `seal` does on a live run, in two steps: mint, then check the same token
# back. The height is not asserted against a constant — it moves with the chain
# — but the round trip is what matters, and it fails if `latest` ever mints a
# block the verifier cannot find.
@test
def "a freshly minted beacon verifies" [] {
    with-temp-dir "beacon-minted" {|dir|
        let minted = beacon latest
        let result = beacon verify (statement-with $dir $minted.token)
        assert $result.valid
        assert equal $result.height $minted.height
        assert equal $result.block_hash $minted.block_hash
        assert equal $result.block_time $minted.block_time
        # Minted below the tip on purpose: a tip block can be orphaned, and a
        # beacon minted from one is unverifiable for the life of the seal.
        assert ($minted.height > 900000) $"suspicious mint height: ($minted.height)"
    }
}
