# The beacon token — the fourth field of a root statement.
#
# A beacon is a public value nobody could have known before a fixed moment, so
# embedding one in the bytes a signer signs bounds the seal from BELOW: this
# statement did not exist before that block was mined. OTS bounds it from above.
# The two together bracket a seal; neither gives the other's direction.
#
# The value is a Bitcoin block, named by height and hash. Not because Bitcoin is
# the best beacon available, but because it is the only chain data this repo
# already trusts and already cross-checks (_explorer.nu, README "Verifying a
# timestamp") — a second source would be a second trust root, a second parser
# and a second outage story for a claim that is not stronger.

# The token's grammar, as a regex fragment with no anchors and no capturing
# groups, so `parse-root-statement` can drop it inside its own named group
# without shifting the others. One spelling, used by the writer, the parser and
# the reader: a format whose signature covers exact bytes must not have two.
#
# The height admits no leading zeros, for the reason `seq` does not: under
# `into int` both "7" and "007" become 7, so two byte strings would state one
# height while the signature covers only one of them. The hash is lowercase
# only — reject, never normalize.
export const BEACON_TOKEN_PATTERN = 'none|bitcoin:(?:0|[1-9][0-9]*):[0-9a-f]{64}'

# The token meaning "this statement carries no beacon", playing the role
# `genesis` plays for `prev`. A statement is legal without a beacon: `seal
# --no-stamp` is the offline seal, every @example in this repo runs offline, and
# a bound nobody could mint is better said than faked.
export const BEACON_NONE = "none"

# Reject anything that is not exactly a beacon token. Called by the statement
# writer before the bytes are formed, and by every command that accepts a token
# from a caller.
export def validate-beacon [token: string]: nothing -> nothing {
    if $token !~ (['\A(?:' $BEACON_TOKEN_PATTERN ')\z'] | str join) {
        error make {msg: $"malformed beacon token: ($token | to json) — expected ($BEACON_NONE) or bitcoin:<height>:<64 lowercase hex block hash>"}
    }
}

# A validated token as data: null for `none`, else {height, hash}.
export def parse-beacon [token: string]: nothing -> any {
    validate-beacon $token
    if $token == $BEACON_NONE { return null }
    let parts = $token | split column ":" chain height hash | first
    {height: ($parts.height | into int) hash: $parts.hash}
}

# Build a token from a cross-checked block. Validated on the way out: this is
# the one place a beacon enters the signed bytes, and an unparseable one would
# be discovered by the next reader of a file that is already signed.
export def beacon-token [height: int hash: string]: nothing -> string {
    let token = $"bitcoin:($height):($hash)"
    validate-beacon $token
    $token
}
