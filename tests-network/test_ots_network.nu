use std/assert
use std/testing *

use ../nu-multiproof/ots.nu
use ../nu-multiproof/_temp-helpers.nu with-temp-dir

# Tests that reach the public internet. nutest does not discover this directory
# — `nu toolkit.nu test` covers `tests/` only — so run it deliberately:
#
#   nu toolkit.nu test --network
#
# Why out of the main suite rather than gated by an env var: such a gate
# reports PASS with zero assertions executed on every default run, and there is
# no CI to set the variable. A test that cannot fail is worse than
# no test — it reads as coverage. Here they are absent from the count instead
# of falsely present in it.
#
# `stamp reaches the public calendar` also writes a real, permanent timestamp
# to a public calendar. That is a side effect on someone else's infrastructure,
# which is its own reason not to run it on every `toolkit test`.

# The module's only end-to-end vector against real Bitcoin: mainnet block
# 939896, committed in this repo as an origin proof.
@test
def "verify confirms a real Bitcoin-anchored bundle" [] {
    let bundle = "multiproofs/origin-proofs/tree-hashes.CCA016A8"
    let result = ots verify $"($bundle)/tree-hashes.ots" --file $"($bundle)/tree-hashes.csv"
    assert $result.valid
    assert equal $result.height 939896
    assert $result.content_verified
    # Not `>= 1`: below --min-sources verify throws rather than answering, so
    # reaching this line at all means the cross-check happened. Asserting the
    # count keeps that true if the default ever changes.
    assert (($result.sources_confirmed | length) >= 2)
}

# The cross-check is the whole defence — nothing bounds the work behind the
# header — so a result resting on one explorer is a result the single
# responder chose, block time and all. Only a live explorer can put exactly one
# responder on the wire, which is why this lives here and not in tests/.
@test
def "one explorer is not enough, unless it is asked for" [] {
    let proof = "multiproofs/origin-proofs/tree-hashes.CCA016A8/tree-hashes.ots"

    let outcome = try { ots verify $proof --sources ["https://mempool.space/api"] | get valid } catch {|e| $e.msg }
    assert ($outcome | describe | str starts-with "string") $"expected a refusal, got valid: ($outcome)"
    assert ($outcome | str contains "below --min-sources") $"expected the min-sources refusal, got: ($outcome)"

    # The deliberate override still answers.
    let forced = ots verify $proof --sources ["https://mempool.space/api"] --min-sources 1
    assert $forced.valid
    assert equal ($forced.sources_confirmed | length) 1
}

# What only a live calendar can tell us: that CALENDAR_ALLOWLIST still admits
# the calendar the public pool actually names. Offline fixtures carry whatever
# URL the fixture author typed, so they cannot catch the allowlist going stale
# — and a stale allowlist would refuse to upgrade every fresh stamp.
@test
def "stamp reaches the public calendar, and upgrade will talk to it" [] {
    with-temp-dir "network-stamp" {|dir|
        let file = $dir | path join "doc.txt"
        "hello opentimestamps" | save --raw --force $file
        # `stamp` returns the paths it wrote; it does NOT write <file>.ots
        # beside the input, it writes a bundle directory.
        let result = ots stamp $file --out-dir $dir

        let stamped = ots info $result.ots
        assert equal ($stamped.hash | str lowercase) (open --raw $file | hash sha256)
        assert equal $stamped.attestation.type "pending"

        # A fresh stamp is not yet in a block, so upgrade is expected to fail —
        # the point is *which* failure. "not yet confirmed" means the gate let
        # the fetch through; "refusing to contact" means the allowlist is stale.
        let outcome = try { ots upgrade $result.ots | get status } catch {|e| $e.msg }
        assert (not ($outcome | str contains "refusing to contact")) $"CALENDAR_ALLOWLIST does not admit ($stamped.attestation.url), the calendar the public pool named"
    }
}
