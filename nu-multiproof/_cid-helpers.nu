# UnixFS / dag-pb node construction for CID v0, in pure Nushell.
#
# Reproduces `ipfs add --cid-version=0 --raw-leaves=false --hash=sha2-256
# --chunker=size-262144` for files and directories. Vectors recorded from the
# reference client (tests/test_cid-v0.nu) pin the chunk boundaries (empty
# through one full 262144-byte chunk), a depth-1 file DAG (two full chunks
# and a tail), a depth-2 file DAG at 175 chunks, and directory shapes from
# empty up to the HAMT boundary. A file DAG deeper than 2 (175 full branches,
# ~7.9 GB) has no recorded vector — the fold past depth 2 is the same code,
# but nothing external pins it.
#
# A *node* here is {digest, dag_size} plus, for file nodes only, {file_size}:
#   digest    sha-256 of the serialized block (the multihash body of its CID)
#   dag_size  cumulative size of this block and every block under it (PBLink.Tsize)
#   file_size UnixFS filesize — the payload bytes, no framing. Only a file node
#             can be a child of a file node, so directory nodes have no use for it.

use _varint.nu encode-varint

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# How many base58 digits encode-base58 peels off per division pass. Not 1 —
# see the note there.
const B58_GROUP = 5
const B58_GROUP_DIVISOR = 656356768 # 58^5

# UnixFS splits file payloads at this size; each piece becomes one leaf block.
export const CHUNK_SIZE = 262144
# Links per intermediate node in the balanced layout go-unixfs builds
# (DefaultLinksPerBlock): an 8 KiB block target divided by ~47 bytes per link.
export const LINKS_PER_NODE = 174

# kubo estimates a directory's size as the sum over its entries of the name
# length plus the link's CID length, and switches to a HAMT shard once that
# passes 256 KiB (Import.UnixFSHAMTDirectorySizeThreshold). A shard has a
# different CID for the same entries, and this file builds no shards — see
# dir-node. Both numbers were measured against ipfs 0.42.0 at the exact
# boundary: 4096 entries of 30-byte names (262144) still hash as a basic
# directory, 4097 (262208) do not.
export const HAMT_THRESHOLD = 262144
export const LINK_SIZE_CIDV0 = 34

# Protobuf length-delimited field: <tag><length varint><bytes>
export def pb-field [tag: binary]: binary -> binary {
    let value = $in
    $tag | bytes add --end (($value | bytes length) | encode-varint) | bytes add --end $value
}

# Long division of the whole byte string, B58_GROUP digits at a time.
#
# Why not one digit per pass, which is the textbook shape and was the shape here
# until 2026-08-28: a 34-byte CID is a 272-bit number, so it holds ~46 base58
# digits, and one digit per pass means ~46 passes over the byte list — ~1560
# interpreter steps for one CID. Dividing by 58^5 instead peels five digits at
# once and takes ~10 passes: 3.5 ms -> 1.1 ms per call, measured over 200 random
# 34-byte inputs, and node-cid was 68% of a manifest build (2.2 s of 3.3 s over
# 521 rows on the monorepo root, same day).
#
# It is the same long division, not a different algorithm and not a cache: the
# step got bigger, nothing is stored, nothing is skipped. The two forms were
# checked digit-identical on 200 random inputs plus the all-zero, leading-zero,
# single-byte, empty and all-0xff edges before the old one was removed.
#
# Why 5 and not more: the intermediate is carry * 256 + byte with carry < 58^5,
# which is 1.7e11 and decades inside i64 — but the pass count is already down to
# ~10, so 58^6 buys little and eats the headroom. Packing the bytes into 32-bit
# limbs was also measured (0.97 ms) and rejected: 15% for a repacking step and
# twice the code.
export def encode-base58 []: binary -> string {
    let hex = $in | encode hex
    let pair_count = ($hex | str length) // 2
    let byte_list = (
        0..<$pair_count | each {|i|
            let s = $i * 2
            let hex_pair = $hex | str substring ($s)..<($s + 2)
            $"0x($hex_pair)" | into int
        }
    )
    let chars = $BASE58_ALPHABET | split chars
    let leading = $byte_list | take while { $in == 0 } | length
    # Why strip here and not only inside the loop: leading zero bytes are carried
    # by the '1' prefix below, and an all-zero input left the loop with one pass
    # to make — emitting a spurious '1' on top of the prefix.
    mut nums = ($byte_list | skip while { $in == 0 })
    mut digits = []
    while not ($nums | is-empty) {
        mut carry = 0
        mut quotient = []
        for b in $nums {
            let val = $carry * 256 + $b
            $quotient ++= [($val // $B58_GROUP_DIVISOR)]
            $carry = $val mod $B58_GROUP_DIVISOR
        }
        # The remainder is the next B58_GROUP digits, least significant first.
        mut group = []
        mut rest = $carry
        for _ in 0..<$B58_GROUP {
            $group = [($rest mod 58) ...$group]
            $rest = $rest // 58
        }
        $digits = [...$group ...$digits]
        $nums = ($quotient | skip while { $in == 0 })
    }
    let ones = (0..<$leading | each { '1' } | str join)
    # The final pass emits a full group whether the value filled it or not, so
    # the top of that group can hold zero digits the number does not have. One
    # digit per pass could not produce them, so this trim is new with the group.
    # It cannot eat a real digit: a leading zero digit is not part of any
    # base58 value, and the input's leading zero BYTES left before the loop.
    let encoded = ($digits | skip while { $in == 0 } | each {|d| $chars | get $d } | str join)
    $"($ones)($encoded)"
}

# CID v0 of a node: base58btc of the sha2-256 multihash (0x12 0x20 || digest).
export def node-cid []: record -> string {
    let node = $in
    0x[1220] | bytes add --end $node.digest | encode-base58
}

# Serialize one PBLink {Hash, Name, Tsize}. Chunk links inside a file carry an
# empty name — the position in the link list is the order of the bytes.
export def link-bytes [name: string node: record]: nothing -> binary {
    let cid_bytes = 0x[1220] | bytes add --end $node.digest
    let body = (
        ($cid_bytes | pb-field 0x[0a])
        | bytes add --end (($name | into binary) | pb-field 0x[12])
        | bytes add --end (0x[18] | bytes add --end ($node.dag_size | encode-varint))
    )
    $body | pb-field 0x[12]
}

export def block-node [block: binary file_size: int children: list]: nothing -> record {
    {
        digest: ($block | hash sha256 | decode hex)
        # append 0: a leaf and an empty directory both link nothing, and
        # `math sum` refuses an empty list
        dag_size: (($block | bytes length) + ($children | each {|c| $c.dag_size } | append 0 | math sum))
        file_size: $file_size
    }
}

# One chunk of file payload: PBNode{Data: UnixFS{Type: File, Data, filesize}}.
export def leaf-node []: binary -> record {
    let chunk = $in
    let n = $chunk | bytes length
    let nv = $n | encode-varint
    # An empty file omits the Data field entirely, it does not carry a zero-length one.
    let data_field = if $n > 0 { $chunk | pb-field 0x[12] } else { 0x[] }
    let unixfs = 0x[08 02] | bytes add --end $data_field | bytes add --end 0x[18] | bytes add --end $nv
    block-node ($unixfs | pb-field 0x[0a]) $n []
}

# Intermediate file node: links to child file nodes, and a UnixFS Data carrying
# the total filesize plus one blocksizes entry per child, in link order.
export def branch-node [children: list]: nothing -> record {
    let links = $children | each {|c| link-bytes "" $c } | bytes collect
    let total = $children | get file_size | math sum
    mut unixfs = 0x[08 02] | bytes add --end 0x[18] | bytes add --end ($total | encode-varint)
    for c in $children {
        $unixfs = $unixfs | bytes add --end 0x[20] | bytes add --end ($c.file_size | encode-varint)
    }
    block-node ($links | bytes add --end ($unixfs | pb-field 0x[0a])) $total $children
}

# UnixFS directory: PBNode{Links: entries, Data: UnixFS{Type: Directory}}.
# Links must arrive sorted by name — `ipfs add` walks directory entries in
# byte-wise name order, and the link order is part of what the CID commits to.
#
# Refuses a directory large enough that kubo would shard it, rather than
# returning a basic-directory CID no IPFS client reproduces: the manifest's job
# is to name content the way the network names it, and a silent divergence here
# lands in the "." row the merkle root signs. Reject, never normalize.
export def dir-node [
    links: list
    --path: string = "." # directory being built, for the sharding error only
]: nothing -> record {
    let estimate = $links | each {|l| ($l.name | into binary | bytes length) + $LINK_SIZE_CIDV0 } | append 0 | math sum
    if $estimate > $HAMT_THRESHOLD {
        error make {msg: $"directory ($path) holds ($links | length) entries \(estimated ($estimate) bytes\), over the ($HAMT_THRESHOLD)-byte threshold where IPFS switches to a HAMT-sharded directory. This builds basic directories only, so any CID it produced here would be one no IPFS client agrees with."}
    }
    let link_bytes = $links | each {|l| link-bytes $l.name $l.node } | bytes collect
    let nodes = $links | each {|l| $l.node }
    let block = $link_bytes | bytes add --end (0x[08 01] | pb-field 0x[0a])
    block-node $block 0 $nodes | reject file_size
}

# File node for a whole payload, chunked and folded like go-unixfs's balanced
# builder: split at CHUNK_SIZE, then group each level into fixed batches of
# LINKS_PER_NODE until one node is left. Not the recursive fill the reference
# implementation is written as, because: it fills every subtree to capacity
# before starting the next, which is the same tree this bottom-up grouping
# produces. Pinned by tests/test_cid-v0.nu "multi-chunk file: two full chunks
# and a 1000-byte tail" (one level) and "two-level file: 175 chunks", both
# recorded from the client.
export def file-node []: binary -> record {
    let content = $in
    let n = $content | bytes length
    mut level = if $n == 0 {
        [(0x[] | leaf-node)]
    } else {
        0..<(($n + $CHUNK_SIZE - 1) // $CHUNK_SIZE) | each {|i|
            let start = $i * $CHUNK_SIZE
            let end = [(($i + 1) * $CHUNK_SIZE) $n] | math min
            $content | bytes at $start..<$end | leaf-node
        }
    }
    while ($level | length) > 1 {
        $level = ($level | chunks $LINKS_PER_NODE | each {|group| branch-node $group })
    }
    $level | first
}
