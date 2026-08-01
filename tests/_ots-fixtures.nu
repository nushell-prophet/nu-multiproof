# Synthetic OTS proof builders shared by test suites — offline, no calendar.
# Byte layout mirrors ots.nu parse-ots: header magic, version 1, sha256 op,
# 32-byte file hash, ops, attestation. The `_` name keeps nutest from picking
# this up as a suite (discovery matches test_*.nu); import names explicitly.

use ../nu-multiproof/_varint.nu encode-varint

export const OTS_HEADER = 0x[00 4f70656e54696d657374616d7073 0000 50726f6f66 00 bf89e2e884e89294]
export const ZERO_HASH = 0x[0000000000000000000000000000000000000000000000000000000000000000]
export const ATT_PENDING_TAG = 0x[83dfe30d2ef90c8e]
export const ATT_BITCOIN_TAG = 0x[0588960d73d71901]

# Pending attestation over --hash, pointing at --url.
# --url exists so a test can build the hostile case: the URL is bytes read out
# of the proof, so it is attacker input, and `upgrade` fetches it.
export def build-pending-ots [
    --hash: binary = $ZERO_HASH
    --url: string = "https://a.pool.opentimestamps.org"
    --with-ops
] {
    let url_bytes = $url | into binary
    mut ots = ($OTS_HEADER | bytes add --end 0x[01 08] | bytes add --end $hash)
    if $with_ops {
        $ots = (
            $ots
            | bytes add --end 0x[f0 04 deadbeef]
            | bytes add --end 0x[08]
        )
    }
    let url_len = $url_bytes | bytes length
    let inner_len = ($url_len | into binary --endian little | bytes at 0..0)
    let outer_len = ($url_len + 1 | into binary --endian little | bytes at 0..0)
    $ots
    | bytes add --end 0x[00]
    | bytes add --end $ATT_PENDING_TAG
    | bytes add --end $outer_len
    | bytes add --end $inner_len
    | bytes add --end $url_bytes
}

# Bitcoin attestation over --hash at --height (default 123456).
#
# --height exists so a test can put two anchors of the SAME content in one
# bundle: "existed no later than T" makes the lowest block the strongest claim,
# and picking between them was `ls` order until an assertion could see the
# difference.
export def build-bitcoin-ots [--hash: binary = $ZERO_HASH --height: int = 123456] {
    let h = $height | encode-varint
    let payload = (($h | bytes length) | encode-varint) | bytes add --end $h
    $OTS_HEADER
    | bytes add --end 0x[01 08]
    | bytes add --end $hash
    | bytes add --end 0x[f1 02 aabb]
    | bytes add --end 0x[08]
    | bytes add --end 0x[00]
    | bytes add --end $ATT_BITCOIN_TAG
    | bytes add --end $payload
}

# What the calendar returns from POST /digest: the tail of the timestamp chain
# that `stamp` appends after the nonce's sha256 op — here a bare pending
# attestation naming the public calendar.
export def build-calendar-response [] {
    let url_bytes = "https://a.pool.opentimestamps.org" | into binary
    let url_len = $url_bytes | bytes length
    0x[00]
    | bytes add --end $ATT_PENDING_TAG
    | bytes add --end ($url_len + 1 | into binary --endian little | bytes at 0..0)
    | bytes add --end ($url_len | into binary --endian little | bytes at 0..0)
    | bytes add --end $url_bytes
}
