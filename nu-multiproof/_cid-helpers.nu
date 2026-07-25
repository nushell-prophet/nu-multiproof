# UnixFS / dag-pb node construction for CID v0, in pure Nushell.
#
# Reproduces `ipfs add --cid-version=0 --raw-leaves=false --hash=sha2-256
# --chunker=size-262144` for files of any size and for directories. Vectors
# recorded from the reference client pin every shape this file can build:
# see tests/test_cid-v0.nu.
#
# A *node* here is {digest, dag_size} plus, for file nodes only, {file_size}:
#   digest    sha-256 of the serialized block (the multihash body of its CID)
#   dag_size  cumulative size of this block and every block under it (PBLink.Tsize)
#   file_size UnixFS filesize — the payload bytes, no framing. Only a file node
#             can be a child of a file node, so directory nodes have no use for it.

use _varint.nu encode-varint

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# UnixFS splits file payloads at this size; each piece becomes one leaf block.
export const CHUNK_SIZE = 262144
# Links per intermediate node in the balanced layout go-unixfs builds
# (DefaultLinksPerBlock): an 8 KiB block target divided by ~47 bytes per link.
export const LINKS_PER_NODE = 174

# Protobuf length-delimited field: <tag><length varint><bytes>
export def pb-field [tag: binary]: binary -> binary {
    let value = $in
    $tag | bytes add --end (($value | bytes length) | encode-varint) | bytes add --end $value
}

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
    mut nums = $byte_list
    mut digits = []
    while not ($nums | is-empty) {
        mut carry = 0
        mut quotient = []
        for b in $nums {
            let val = $carry * 256 + $b
            $quotient ++= [($val // 58)]
            $carry = $val mod 58
        }
        $digits = [$carry ...$digits]
        $nums = ($quotient | skip while { $in == 0 })
    }
    let ones = (0..<$leading | each { '1' } | str join)
    let encoded = ($digits | each {|d| $chars | get $d } | str join)
    $"($ones)($encoded)"
}

# Why decode at all: a directory link carries the child's raw multihash, and the
# only form of a child CID that crosses a command boundary here is its base58
# string. Round-tripping it back to bytes keeps the node API in terms of CIDs.
export def decode-base58 []: string -> binary {
    let chars = $BASE58_ALPHABET | split chars
    let input = $in | split chars
    # Why the check is here and not inside the map below: an error thrown inside
    # `each` reaches the caller wrapped, as a bare "Eval block failed".
    let outside = $input | where {|c| $c not-in $chars }
    if ($outside | is-not-empty) {
        error make {msg: $"not base58btc: ($outside | uniq | str join '')"}
    }
    let values = $input | each {|c| $chars | enumerate | where item == $c | get index.0 }
    let leading = $values | take while { $in == 0 } | length
    mut nums = $values
    mut out = []
    while not ($nums | is-empty) {
        mut carry = 0
        mut quotient = []
        for d in $nums {
            let val = $carry * 58 + $d
            $quotient ++= [($val // 256)]
            $carry = $val mod 256
        }
        $out = [$carry ...$out]
        $nums = ($quotient | skip while { $in == 0 })
    }
    let zeros = 0..<$leading | each { 0 }
    [...$zeros ...$out]
    | each {|b| $b | format number | get lowerhex | str substring 2.. | fill --alignment right --character '0' --width 2 }
    | str join
    | decode hex
}

# CID v0 of a node: base58btc of the sha2-256 multihash (0x12 0x20 || digest).
export def node-cid []: record -> string {
    let node = $in
    0x[1220] | bytes add --end $node.digest | encode-base58
}

# Serialize one PBLink {Hash, Name, Tsize}. Chunk links inside a file carry an
# empty name — the position in the link list is the order of the bytes.
export def link-bytes [name: string, node: record]: nothing -> binary {
    let cid_bytes = 0x[1220] | bytes add --end $node.digest
    let body = (
        ($cid_bytes | pb-field 0x[0a])
        | bytes add --end (($name | into binary) | pb-field 0x[12])
        | bytes add --end (0x[18] | bytes add --end ($node.dag_size | encode-varint))
    )
    $body | pb-field 0x[12]
}

def block-node [block: binary, file_size: int, children: list]: nothing -> record {
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
export def dir-node [links: list]: nothing -> record {
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
# produces — checked against the client at 4 chunks and at 192 (two levels).
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
