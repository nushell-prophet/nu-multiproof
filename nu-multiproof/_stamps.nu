# Finding the OTS proofs a repo holds, and picking the best one for a hash.
#
# Internal module: mod.nu does not re-export _*.nu files. merkle.nu, seal.nu and
# tests import the names they need explicitly.
#
# Why shared rather than a block in each caller: `merkle verify` and `seal
# status` ask the same two questions — which proof dates this content, and which
# dates this signature — and both answers turn on discovering proofs by content
# commitment rather than by file or bundle name. Two copies of that rule would
# drift, and the direction they drift in is a status command reporting "no
# stamp" for a bundle verify accepts, or the reverse.

use ots.nu
use _fs.nu [ list-files list-dirs ]

# Every parsable proof in the bundles under $ots_dir, as {file, type, hash}.
#
# One directory level by default, which is the bundle layout: proofs live in
# `<ots-dir>/<bundle>/`, never loose in $ots_dir (the one form written there is
# a rejected calendar answer, which is deliberately not a proof). --recursive
# walks the whole tree instead, for a caller describing everything a repo holds
# rather than consulting the operational set.
#
# Why unparsable files are skipped with a note rather than raised: a corrupt or
# truncated archival .ots must not block an answer about an unrelated proof, and
# `seal` is often the only thing that will ever look at one.
export def scan-stamps [ots_dir: path --recursive]: nothing -> list<record> {
    let files = if $recursive {
        list-files $ots_dir --recursive --suffix ".ots"
    } else {
        list-dirs $ots_dir | each {|d| list-files $d --suffix ".ots" } | flatten
    }
    # Rejected calendar answers are skipped rather than parsed: they are the one
    # `.ots` this repo writes that is deliberately NOT a proof (README,
    # "rejected"), so parsing each one only to print "skipping unparsable" is a
    # note about an expected file, and a --recursive caller sees it on every run.
    # Matched on the name because this code writes that name; nothing here reads a
    # name supplied by anyone else.
    $files | where not ($it | path basename | str contains ".rejected-") | each {|f|
        let info = try { ots info $f } catch {|e|
            print $"note: skipping unparsable OTS file ($f): ($e.msg)"
            null
        }
        # height: the Bitcoin block the attestation binds to, null while pending.
        # It is the only time this proof carries — a block's wall-clock time lives
        # in its header, which no .ots holds, so a date needs `ots verify` and the
        # network. Anything derived from the filesystem (an mtime, a name's
        # timestamp) would render in the same column and mean nothing: it is
        # whenever the file was last written, not when the content existed.
        if $info != null {
            {file: $f type: $info.attestation.type hash: $info.hash height: $info.attestation.height?}
        } else { null }
    }
}

# Best stamp from a set of candidates, as a status rather than a verdict.
# Prefers an anchored one: listing order can put an archived still-pending
# <stem>.<timestamp>.ots before the anchored <stem>.ots.
#
# Among several anchored proofs of the same content, the LOWEST block wins. The
# claim being made is "these bytes existed no later than T", so the earliest
# anchor is the strongest one available and every later anchor is implied by it.
# This used to be `$anchored | first`, i.e. `ls` order — invisible for as long as
# only the word "anchored" came out of here, and a wrong number as soon as the
# height was reported: a bundle holding anchors at 123456 and 100 answered 100 or
# 123456 depending on how the archival filename sorted.
export def pick-stamp [stamps: list]: nothing -> record<status: string, ots: any, height: any> {
    if ($stamps | is-empty) { return {status: "absent" ots: null height: null} }
    # No `height != null` filter: `parse-ots` always sets it for a bitcoin
    # attestation, so a null here would be a parser defect, and swallowing it
    # would report an anchored proof as `pending` — the fail-fast rule says pick
    # the real fix (the sort) and not a guard beside it.
    let anchored = $stamps | where type == "bitcoin"
    let pick = if ($anchored | is-not-empty) {
        $anchored | sort-by height | first
    } else {
        $stamps | first
    }
    {
        status: (if $pick.type == "bitcoin" { "anchored" } else { "pending" })
        ots: $pick.file
        height: $pick.height?
    }
}

# A stamp status as one readable cell: "anchored 912345", "pending", "absent".
#
# Why the height is joined into the status rather than given a column of its own:
# a bundle has one status per stamped file — content plus one per signature — so
# a parallel height column would have to repeat that structure and a reader would
# match them up by position. `where status =~ anchored` still selects.
export def format-stamp [stamp: record]: nothing -> string {
    if $stamp.height? == null { $stamp.status } else { $"($stamp.status) ($stamp.height)" }
}
