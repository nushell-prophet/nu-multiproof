# RFC 6962 (Certificate Transparency) merkle tree over tree-hashes.csv rows.
# Spec-critical primitives — the full pinned spec lives in README.md
# ("Merkle inclusion proofs"); an independent implementation of that section
# must reproduce the same root from the same CSV.
#
# Internal module: mod.nu does not re-export _*.nu files. merkle.nu and tests
# import the names they need explicitly.

use _beacon-helpers.nu [BEACON_TOKEN_PATTERN validate-beacon]

# The token moves with every change to the bytes it names, and pre-1.0 the older
# form is refused rather than migrated (see 32e613f, 6ff7096: the stale statement
# is deleted and the chain restarts at genesis).
# v3: the leaf gained a second git column, so a root computed over v2 leaf bytes
# describes a different serialization of the same manifest — a verifier must
# never fold v2 bytes against a v3 root.
# v4: the statement gained the beacon field, its lower time bound. The tree is
# untouched; the SIGNED BYTES are not, and they are what the token describes.
export const MERKLE_SCHEMA = "multiproof-merkle-v4"

const LEAF_COLUMNS = [filepath content_sha256 content_git_sha1 content_git_sha256 content_cid]

# Injectivity guard (forgery fix): git allows "\n" in filenames, so a name
# like "evil\n<64hex>\n<40hex>\n<64hex>\n<cid>" would serialize into leaf bytes that
# parse as a DIFFERENT record with attacker-chosen hashes. Constraining the
# charsets makes the "\n"-join injective. Both builder and verifier call this;
# reject (never normalize) violations — uppercase hex included.
export def validate-leaf [row: record]: nothing -> nothing {
    let cols = $row | columns
    if ($cols | sort) != ($LEAF_COLUMNS | sort) {
        error make {msg: $"leaf must have exactly columns ($LEAF_COLUMNS | str join ', ') — got ($cols | str join ', ')"}
    }
    if ($row.filepath | is-empty) {
        error make {msg: "leaf filepath is empty"}
    }
    if $row.filepath =~ '[\x00-\x1f]' {
        error make {msg: $"leaf filepath contains control bytes \(< 0x20\): ($row.filepath | to json)"}
    }
    # Containment guard: `verify` joins the filepath onto the target dir and
    # reads it, so an absolute path or a ".." component makes a proof verify
    # against a file OUTSIDE the directory carrying it — a bundle then proves a
    # file it does not contain, or one belonging to the verifier. git ls-files
    # emits neither form, so nothing legitimate is rejected. "." is legal on
    # purpose: it is the root-CID row (tree-hashes.nu).
    if ($row.filepath | str starts-with "/") or (".." in ($row.filepath | path split)) {
        error make {msg: $"leaf filepath must stay inside the repo — no leading / and no .. component: ($row.filepath | to json)"}
    }
    if $row.content_sha256 != "" and $row.content_sha256 !~ '^[0-9a-f]{64}$' {
        error make {msg: $"leaf content_sha256 must be empty or 64 lowercase hex chars: ($row.content_sha256)"}
    }
    # Each git column is pinned to its own digest length. The single column this
    # replaced accepted 40 or 64 because it carried whichever format the repo
    # ran; now the format is in the column name, so a length that disagrees with
    # the name is a manifest describing something other than what it claims.
    if $row.content_git_sha1 != "" and $row.content_git_sha1 !~ '^[0-9a-f]{40}$' {
        error make {msg: $"leaf content_git_sha1 must be empty or 40 lowercase hex chars: ($row.content_git_sha1)"}
    }
    if $row.content_git_sha256 != "" and $row.content_git_sha256 !~ '^[0-9a-f]{64}$' {
        error make {msg: $"leaf content_git_sha256 must be empty or 64 lowercase hex chars: ($row.content_git_sha256)"}
    }
    if $row.content_cid != "" and $row.content_cid !~ '^Qm[1-9A-HJ-NP-Za-km-z]{44}$' {
        error make {msg: $"leaf content_cid must be empty or a base58btc CIDv0: ($row.content_cid)"}
    }
}

# Leaf hash = sha256(0x00 ++ leaf_bytes), where leaf_bytes is the five PARSED
# field values (not the raw CSV line — quoting is not canonical) joined with
# "\n". The 0x00/0x01 prefixes are RFC 6962 domain separation: without them an
# inner node can be presented as a leaf (second-preimage attack).
export def leaf-hash [row: record]: nothing -> binary {
    let leaf_bytes = [$row.filepath $row.content_sha256 $row.content_git_sha1 $row.content_git_sha256 $row.content_cid]
        | str join (char nl)
        | into binary
    0x[00] | bytes add --end $leaf_bytes | hash sha256 --binary
}

# Largest power of two strictly below n (n >= 2) — the RFC 6962 split point.
export def largest-pow2-below [n: int]: nothing -> int {
    mut k = 1
    while $k * 2 < $n { $k = $k * 2 }
    $k
}

# RFC 6962 merkle tree hash over leaf hashes. Split at the largest power of
# two < n, recurse; inner node = sha256(0x01 ++ left ++ right) over raw
# 32-byte child hashes. No padding, no last-leaf duplication (Bitcoin-style
# duplication is malleable — CVE-2012-2459). n=1: the leaf hash itself.
# n=0: sha256 of empty input (e3b0c442…).
export def mth [hashes: list<binary>]: nothing -> binary {
    match ($hashes | length) {
        0 => (0x[] | hash sha256 --binary)
        1 => ($hashes | first)
        $n => {
            let k = largest-pow2-below $n
            let left = mth ($hashes | first $k)
            let right = mth ($hashes | skip $k)
            0x[01] | bytes add --end $left | bytes add --end $right | hash sha256 --binary
        }
    }
}

# Audit path (inclusion proof) for the leaf at index: sibling subtree hashes
# in leaf-to-root order. `side` names the SIBLING's position — see fold-path.
export def audit-path [hashes: list<binary> index: int]: nothing -> list {
    let n = $hashes | length
    if $index < 0 or $index >= $n {
        error make {msg: $"leaf index ($index) out of range for ($n) leaves"}
    }
    if $n == 1 { return [] }
    let k = largest-pow2-below $n
    if $index < $k {
        (audit-path ($hashes | first $k) $index) ++ [{side: "right" hash: (mth ($hashes | skip $k))}]
    } else {
        (audit-path ($hashes | skip $k) ($index - $k)) ++ [{side: "left" hash: (mth ($hashes | first $k))}]
    }
}

# Fold a leaf hash up an audit path (steps carry lowercase-hex sibling hashes,
# as stored in proof files). `side` is the SIBLING's position: side "right" →
# acc = sha256(0x01 ++ acc ++ sibling); side "left" → sibling goes first.
# This is the single most common interop bug in merkle verifiers — the rule is
# pinned here and in the README spec.
export def fold-path [leaf_hash: binary steps: list]: nothing -> binary {
    $steps | reduce --fold $leaf_hash {|step acc|
        if ($step.hash | describe) != "string" or $step.hash !~ '^[0-9a-f]{64}$' {
            error make {msg: $"proof step hash must be 64 lowercase hex chars: ($step.hash)"}
        }
        let sibling = $step.hash | decode hex
        match $step.side {
            "right" => (0x[01] | bytes add --end $acc | bytes add --end $sibling | hash sha256 --binary)
            "left" => (0x[01] | bytes add --end $sibling | bytes add --end $acc | hash sha256 --binary)
            _ => (error make {msg: $"proof step side must be left or right: ($step.side)"})
        }
    }
}

# Read the manifest into validated, byte-wise-sorted leaves. Duplicate
# filepaths are a hard error: two rows for one path would let two
# contradicting proofs verify against the same signed root (equivocation).
export def load-leaves [manifest: path]: nothing -> table {
    if not ($manifest | path exists) {
        error make {msg: $"manifest not found: ($manifest) — run tree-hashes first"}
    }
    # --no-infer: a numeric-looking filepath ("123") must stay a string.
    # Builder sorts itself (byte-wise, which nu's default string sort is)
    # rather than trusting file order, so the root is order-independent.
    let rows = open --raw $manifest | from csv --no-infer | sort-by filepath
    let dupes = $rows | get filepath | uniq --repeated
    if ($dupes | is-not-empty) {
        error make {msg: $"duplicate filepaths in manifest \(equivocation risk\): ($dupes | str join ', ')"}
    }
    for row in $rows { validate-leaf $row }
    $rows
}

# One-line root statement — the bytes a seal signs:
#   "multiproof-merkle-v4 <64 lowercase hex> <seq> <prev> <beacon>"
# plus exactly one trailing "\n". Statement form, not a bare hash — a signature
# over a bare hash under the generic "file" namespace could be replayed into any
# other context where the key signs hashes.
#
# `seq` counts seals from 0 and rises by exactly 1 per seal; `prev` is the root
# this seal supersedes, or the literal `genesis` for the first one. Why both sit
# in the signed bytes: a root says what a tree held, never which seal it was, and
# multiproofs/ keeps only the LIVE statement — so "does this seal follow that
# one" had no answer outside git history. Why a word and not 64 zeros for the
# first seal: a sentinel shaped like a hash gets read as a hash by any verifier
# that forgets the special case.
#
# `beacon` is the lower time bound: a token minted by `beacon latest`, or the
# literal `none` when the seal was made offline. Its grammar lives in
# _beacon-helpers.nu, the argument for having it at all in beacon.nu.
#
# What the number is worth: multiproofs/ is excluded from the manifest, so `seq`
# is not under the merkle root. It rests on the signature over these bytes and on
# their OTS anchor — a key holder can restate any number, what they cannot do is
# make two different statements share one signature and one anchor.
export def root-statement [
    root_hex: string
    seq: int # 0 for the first seal, then +1 per seal
    prev: string # root this seal supersedes, or "genesis"
    beacon: string # lower time bound: a beacon token, or "none" (_beacon-helpers.nu)
]: nothing -> string {
    # Validated here, at the one place a statement is formed: this field is the
    # only one whose value comes from off the machine, and an unparseable token
    # would otherwise be found by the next reader of a file already signed.
    validate-beacon $beacon
    $"($MERKLE_SCHEMA) ($root_hex) ($seq) ($prev) ($beacon)\n"
}

# Parse a root statement file, byte-exact. Editors love adding trailing
# newlines; the signature covers exact bytes, so drift must be loud.
#
# Returns the whole record, not the root alone: a caller handed a bare hash
# cannot check the chain that hash is a link in.
export def parse-root-statement [file: path]: nothing -> record<root: string, seq: int, prev: string, beacon: string> {
    let content = open --raw $file | into string
    # The schema token is captured and compared against MERKLE_SCHEMA rather
    # than spelled into the regex: hardcoding it made the parser keep accepting
    # the old schema after a bump, while root-statement already wrote the new
    # one — a silent version split in the one file that must be byte-exact.
    #
    # `0|[1-9][0-9]*`, not `\d+`: under `into int` both "7" and "007" become 7,
    # so two byte strings would state one seq — and the signature covers bytes,
    # not the parsed value.
    #
    # The beacon alternation is spliced in from _beacon-helpers.nu rather than
    # spelled again — the token grammar has one home, and a format whose
    # signature covers exact bytes must not have two readings of a field.
    #
    # One line per field, in the order the statement writes them, joined into a
    # single regex. `\A` and `\n\z` pin both ends: that is how "exactly one
    # trailing newline" becomes a parse failure instead of something a reader
    # would be tempted to trim.
    let pattern = [
        '\A'
        '(?<schema>\S+) '
        '(?<root>[0-9a-f]{64}) '
        '(?<seq>0|[1-9][0-9]*) '
        '(?<prev>[0-9a-f]{64}|genesis) '
        '(?<beacon>' $BEACON_TOKEN_PATTERN ')'
        '\n\z'
    ] | str join
    let matched = $content | parse --regex $pattern
    if ($matched | is-empty) or $matched.schema.0 != $MERKLE_SCHEMA {
        error make {msg: $"malformed root statement ($file): expected '($MERKLE_SCHEMA) <64 lowercase hex> <seq> <prev root hex or genesis> <beacon token or none>' with exactly one trailing newline"}
    }
    let rec = $matched | first
    let seq = $rec.seq | into int
    # genesis and seq 0 are one claim — "nothing came before this". Half of it
    # describes a chain nobody can walk: seq 0 with a predecessor hash points at
    # a seal its own count says does not exist, and genesis at seq 5 hides four.
    if ($rec.prev == "genesis") != ($seq == 0) {
        error make {msg: $"inconsistent root statement ($file): seq ($seq) with prev ($rec.prev) — genesis pairs with seq 0, and with nothing else"}
    }
    {root: $rec.root seq: $seq prev: $rec.prev beacon: $rec.beacon}
}
