# RFC 6962 (Certificate Transparency) merkle tree over tree-hashes.csv rows.
# Spec-critical primitives — the full pinned spec lives in README.md
# ("Merkle inclusion proofs"); an independent implementation of that section
# must reproduce the same root from the same CSV.
#
# Internal module: mod.nu does not re-export _*.nu files. merkle.nu and tests
# import the names they need explicitly.

export const MERKLE_SCHEMA = "multiproof-merkle-v1"

const LEAF_COLUMNS = [filepath content_sha256 content_git content_cid]

# Injectivity guard (forgery fix): git allows "\n" in filenames, so a name
# like "evil\n<64hex>\n<64hex>\n<cid>" would serialize into leaf bytes that
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
    if $row.content_sha256 != "" and $row.content_sha256 !~ '^[0-9a-f]{64}$' {
        error make {msg: $"leaf content_sha256 must be empty or 64 lowercase hex chars: ($row.content_sha256)"}
    }
    # 40 or 64: seal supports SHA-1 git repos (only git-proof requires SHA-256),
    # so a manifest's git object hash is legitimately either digest length.
    if $row.content_git != "" and $row.content_git !~ '^([0-9a-f]{40}|[0-9a-f]{64})$' {
        error make {msg: $"leaf content_git must be empty or 40/64 lowercase hex chars: ($row.content_git)"}
    }
    if $row.content_cid != "" and $row.content_cid !~ '^Qm[1-9A-HJ-NP-Za-km-z]{44}$' {
        error make {msg: $"leaf content_cid must be empty or a base58btc CIDv0: ($row.content_cid)"}
    }
}

# Leaf hash = sha256(0x00 ++ leaf_bytes), where leaf_bytes is the four PARSED
# field values (not the raw CSV line — quoting is not canonical) joined with
# "\n". The 0x00/0x01 prefixes are RFC 6962 domain separation: without them an
# inner node can be presented as a leaf (second-preimage attack).
export def leaf-hash [row: record]: nothing -> binary {
    let leaf_bytes = [$row.filepath $row.content_sha256 $row.content_git $row.content_cid]
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

# One-line root statement: "multiproof-merkle-v1 <64 lowercase hex>" + exactly
# one trailing "\n". Statement form, not a bare hash — a signature over a bare
# hash under the generic "file" namespace could be replayed into any other
# context where the key signs hashes.
export def root-statement [root_hex: string]: nothing -> string {
    $"($MERKLE_SCHEMA) ($root_hex)\n"
}

# Parse a root statement file, byte-exact. Editors love adding trailing
# newlines; the signature covers exact bytes, so drift must be loud.
export def parse-root-statement [file: path]: nothing -> string {
    let content = open --raw $file | into string
    # The schema token is captured and compared against MERKLE_SCHEMA rather
    # than spelled into the regex: hardcoding it made the parser keep accepting
    # the old schema after a bump, while root-statement already wrote the new
    # one — a silent version split in the one file that must be byte-exact.
    let matched = $content | parse --regex '\A(?<schema>\S+) (?<root>[0-9a-f]{64})\n\z'
    if ($matched | is-empty) or $matched.schema.0 != $MERKLE_SCHEMA {
        error make {msg: $"malformed root statement ($file): expected '($MERKLE_SCHEMA) <64 lowercase hex>' with exactly one trailing newline"}
    }
    $matched.root.0
}
