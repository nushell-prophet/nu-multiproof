# Internal helpers for ots.nu. Not part of the public nu-multiproof API
# (mod.nu does not re-export this file). Lives separately so the pure
# extensionless-input case can be tested without invoking `stamp` and the
# calendar network call.

# The bundle directory a proof over <file> is filed under: `<stem>.<HASH8>`,
# the grammar every name-based reader places a proof by (README, "OTS bundle").
#
# The prefix is passed in rather than hashed here: `stamp` derives it from the
# very bytes it stamped, and re-reading the file to build the name would let the
# name describe bytes the proof does not commit to.
export def bundle-dir-for [file: path hash_prefix: string out_dir: path]: nothing -> string {
    $"($out_dir)/($file | path parse | get stem).($hash_prefix)"
}

# A bundle directory holding the frozen copy and no proof — everything `ots
# stamp --into` needs to be there before it can join one.
#
# Why this exists apart from `stamp`: `--into` refuses a directory that is not
# already on disk, on purpose, so the directory has to be minted before the
# first proof lands in it. `stamp` mints it from the file it is stamping;
# `seal --no-content-anchor` stamps that file not at all and still owes the
# bundle its frozen copy — nu-cybergraph finds a bundle by matching the frozen
# `tree-root.txt` in it against the root hex, and `seal status` reads the same
# copy.
export def freeze-bundle [file: path out_dir: path]: nothing -> path {
    let file_hash = open --raw $file | hash sha256 | decode hex
    # Uppercase here while every compared hash in this project is lowercase, for
    # the same reason `stamp` does it: this is only a directory name, and the
    # form is already baked into committed bundles and into README. `encode hex`
    # is what emits it that way.
    let dir = bundle-dir-for $file ($file_hash | encode hex | str substring 0..<8) $out_dir
    let copy = copy-path-for $file $dir
    check-frozen-copy $copy $file_hash "the frozen copy there is different content that shares the 8-hex prefix"
    mkdir $dir
    write-frozen-copy $file $file_hash $copy
    $dir
}

# The one place a frozen copy is written. `stamp` and `freeze-bundle` both fill
# the same bundles, so the rule about how that file appears is enforced once —
# the same reason check-frozen-copy is one guard rather than one per writer.
#
# Not `cp`: a failed `cp` cannot be noticed (see `_fs.nu copy-file`).
#
# Nothing to write when the copy exists: check-frozen-copy has proved it
# byte-identical by the time this runs, which is the ordinary `seal` path (it
# stamps a signature into the bundle that already snapshotted it). Skipping is
# what keeps this `save` free of --force, the one flag able to destroy a bundle.
export def write-frozen-copy [
    file: path # the content the proof commits to
    file_hash: binary # what the caller hashed it as, before anything was written
    copy_path: path # where the bundle keeps it
]: nothing -> nothing {
    if ($copy_path | path exists) { return }
    # Re-read and re-hash rather than copy from bytes the caller kept in hand.
    # Keeping them closes the window completely but costs memory proportional to
    # the file — measured on a 100 MB input: 23 MB streamed against 213 MB held,
    # and `stamp` would hold it across the whole calendar round-trip. Two
    # streaming passes keep memory flat, and the compare still refuses a file
    # that changed underneath, which is the part that matters: a silent copy of
    # new content is a bundle whose proof commits to bytes it does not hold.
    # Measured limit, stated because it is not closed: the verify read and the
    # copy read are two passes, so this narrows the window, it does not remove
    # it.
    if (open --raw $file | hash sha256 | decode hex) != $file_hash {
        error make {
            msg: $"($file) changed while it was being timestamped"
            help: "the proof commits to the bytes read at the start of the run; a bundle must not hold anything else under that name"
        }
    }
    # No `into binary` before `save --raw`, though this repo's rule asks for one
    # ahead of a binary pipeline: `into binary` collects, which is the cost this
    # whole shape exists to avoid, and `save --raw` writes a byte stream through
    # unchanged. Verified byte-exact both ways — a body that is valid UTF-8 and
    # one that is not both round-trip to the same hash.
    open --raw $file | save --raw $copy_path
}

# A frozen copy already sitting in a bundle must be the same content: full-hash
# compare, never the 8 hex the directory name carries. It is the only thing
# between a prefix collision — or, under `--into`, a directory the caller named
# itself — and a bundle whose proofs commit to bytes it no longer holds.
#
# One guard and not one per writer, because `stamp` and `freeze-bundle` write
# that copy into the same directories: a bundle minted by one is filled by the
# other, so a rule enforced in two places is a rule that can hold in one.
export def check-frozen-copy [
    copy_path: path # where the frozen copy goes
    file_hash: binary # sha256 of the bytes about to be frozen
    why: string # what a mismatch means at this callsite
]: nothing -> nothing {
    if not ($copy_path | path exists) { return }
    if (open --raw $copy_path | hash sha256 | decode hex) != $file_hash {
        error make {msg: $"collision in ($copy_path | path dirname): ($why)"}
    }
}

# Bundle copy-path for an input file. Pure.
# Why no trailing dot: extensionless input ("README") was producing "README."
# because `($stem).($ext)` collapsed to "README." when `$ext` was empty.
export def copy-path-for [file: path bundle_dir: path]: nothing -> string {
    let parsed = $file | path parse
    if ($parsed.extension | is-empty) {
        $"($bundle_dir)/($parsed.stem)"
    } else {
        $"($bundle_dir)/($parsed.stem).($parsed.extension)"
    }
}

# A raw header's block hash: double-SHA256, byte-reversed into the display
# order explorers and block heights use.
export def block-hash-of [header: binary]: nothing -> string {
    $header | hash sha256 | decode hex | hash sha256 | decode hex | bytes reverse | encode hex | str lowercase
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

# The explorer's answer to /block/<hash>/header, admitted only if it really is
# that block's header. Everything here is about the source, not the proof: the
# block hash was already cross-checked across explorers before the header was
# fetched, so an answer that is not hex, not 80 bytes, or hashes to something
# else can only be this explorer's fault. Each check throws naming the
# explorer — none is a verdict about the proof. Pinned by tests/test_ots.nu
# "a corrupted header blames the explorer, not the proof".
export def check-fetched-header [
    src: string # explorer base URL, named in every refusal
    block_hash: string # cross-checked block hash (display hex)
    header_hex: string # the explorer's response body
]: nothing -> binary {
    let bytes = try { $header_hex | decode hex } catch {
        error make {msg: $"explorer ($src) answered with a block header that is not hex — cannot verify"}
    }
    if ($bytes | bytes length) != 80 {
        error make {msg: $"explorer ($src) answered with ($bytes | bytes length) bytes where a block header is 80 — cannot verify"}
    }
    let hashes_to = block-hash-of $bytes
    if $hashes_to != ($block_hash | str lowercase) {
        error make {msg: $"explorer ($src) answered with a header that hashes to ($hashes_to), not the cross-checked ($block_hash) — cannot verify"}
    }
    $bytes
}

# Self-verify a raw 80-byte Bitcoin block header with no network access:
#   1. double-SHA256(header), reversed, equals `claimed_hash` (display order)
#   2. the header's merkle-root field equals `expected_root` (internal order)
# Why no proof-of-work check: `bits` travels inside the header being checked,
# so "hash <= target(bits)" is self-referential. A floor at mainnet's powLimit
# would only buy ~2^32 hashes (minutes on a GPU) against an attacker who
# already controls every explorer that answered, and would cost 91 lines.
# A real bound needs the difficulty expected AT this height, or a pinned
# block hash, and neither the proof nor the explorer answer carries data we
# could check that against. The defence is the cross-check in `ots verify`:
# independent explorers must agree on the height -> hash mapping.
# Why fail-fast (error on any mismatch): a header that fails any check is not
# evidence of anything — the caller must not proceed on a partial match.
export def check-block-header [
    header: binary # raw 80-byte header
    expected_root: binary # merkle root the OTS commitment replays to (internal order)
    claimed_hash: string # block hash the height lookup returned (display hex)
]: nothing -> record {
    if ($header | bytes length) != 80 {
        error make {msg: $"expected an 80-byte header, got ($header | bytes length) bytes"}
    }
    let block_hash = block-hash-of $header
    if $block_hash != ($claimed_hash | str lowercase) {
        error make {msg: $"header hashes to ($block_hash), not the looked-up ($claimed_hash)"}
    }
    let header_root = $header | bytes at 36..67
    if $header_root != $expected_root {
        error make {msg: $"merkle root mismatch: header commits to ($header_root | encode hex | str lowercase), proof replays to ($expected_root | encode hex | str lowercase)"}
    }
    {
        block_hash: $block_hash
        merkle_root: ($header_root | encode hex | str lowercase)
        time: (header-time $header)
    }
}
