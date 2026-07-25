# Golden behavior of `pubkey canonical`: the stored pubkey bytes are the
# identity downstream (CID of the file), so the canonical encoding is
# spec-critical — pin it. The fixtures are real `ssh-keygen` output, not
# truncated blobs: the checks here parse the key material, so a made-up base64
# string would only prove that the rejection path works.
use std/assert
use std/testing *

use ../nu-multiproof/pubkey.nu

const ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOi7LinplEQewM3/l8Ol9rE85+YwhvLPKf+ZUUf36Xuf"
const RSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDExnwUVhsIh66w1OIGHFyr0prionxHoHEmkSdgDvMo86vDarHwO88H5yQ4ZhRcUTBS4pLYMbGMeGQfHQBbJI4P8Xarsgys7TfMZ9oJq7/tvSnt85xfkXixhSSTMml3D80FAvhS4hPjnSbqaaVeBcW6d3uCDGpibXZ9eted9nY1PsVtsvET57ooJ8qGh4e3lqkwCXJaCKGAY4zqtTZKAEjsm0PcCueFDuN9zWTTzYy9XZucqcGaBDslrylix5AW81QwOzWlkE7nukWGCguSLUezms8yr1NU9Z2HBlwt3hVC5BLqPOrDWR55jhEQuGV8RVZBT6LaVfVdPqhNA1lJTn9j"
# A hardware-backed key, assembled field by field (type, key, application) —
# `ssh-keygen -t ed25519-sk` needs a security key present.
const SK = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIDfEkyImHgI7LfesBcs1Q1OQlod52hqMaAYxpRExv2OqAAAABHNzaDo="

@test
def "canonical is `<type> <base64>` + newline: comment and extra whitespace dropped" [] {
    assert equal ($"($ED25519) alice@host\n" | pubkey canonical) $"($ED25519)\n"
    assert equal ($"($ED25519 | str replace ' ' '  ')  " | pubkey canonical) $"($ED25519)\n"
    # already-canonical input is a fixed point — verifiers rely on this
    assert equal ($"($ED25519)\n" | pubkey canonical) $"($ED25519)\n"
    assert equal ($"($RSA) bob@example\n" | pubkey canonical) $"($RSA)\n"
    # sk-* types, as ssh-keygen writes them (trailing space, no comment)
    assert equal ($"($SK) \n" | pubkey canonical) $"($SK)\n"
}

@test
def "canonical rejects anything that is not a single pubkey line" [] {
    assert error {|| "-----BEGIN OPENSSH PRIVATE KEY-----" | pubkey canonical }
    assert error {|| "hello world" | pubkey canonical }
    assert error {|| "ssh-ed25519" | pubkey canonical }
    assert error {|| "ssh-ed25519 not*base64" | pubkey canonical }
    assert error {|| $"($ED25519)\n($RSA)" | pubkey canonical }
}

# Why these five: each one passed the earlier shape check (`<known prefix>
# <base64-looking>`), and pubkeys/ is the trust list every verifier reads.
@test
def "canonical rejects key material that is not a key" [] {
    # base64 that decodes, but to nothing a key could be
    assert error {|| "ssh-rsa A" | pubkey canonical }
    assert error {|| "ssh-rsa Zm9v" | pubkey canonical }
    # the type field is not one OpenSSH writes — and it names a path
    assert error {|| "ssh-../../../../tmp/pwn Zm9v" | pubkey canonical }
    assert error {|| "ecdsa-anything Zm9v" | pubkey canonical }
    # a real ed25519 blob presented under another type: OpenSSH reads the
    # inner type, so the line lies about what the key is
    assert error {|| $"ssh-rsa ($ED25519 | split row ' ' | get 1)" | pubkey canonical }
}

@test
def "canonical rejects a truncated or padded blob" [] {
    # first field only: the type, with no key after it
    assert error {|| "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5" | pubkey canonical }
    # length prefix runs past the end of the blob
    assert error {|| "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNr" | pubkey canonical }
    # a whole extra byte after the last field
    let padded = ($ED25519 | split row " " | get 1 | decode base64 | bytes add --end 0x[00] | encode base64)
    assert error {|| $"ssh-ed25519 ($padded)" | pubkey canonical }
}

# The outside oracle. Every check above is this codebase reading its own
# fixtures, so the `side` of each rule could be wrong in the code and in the
# test at once. `ssh-keygen -lf` is the parser that actually decides whether a
# key in pubkeys/ can verify anything, so the two must accept the same set —
# a key this accepts and OpenSSH refuses is a trust-list entry that silently
# verifies nothing.
#
# Not in the list, and deliberately: certificates
# (`ssh-ed25519-cert-v01@openssh.com`) and authorized_keys option prefixes,
# which ssh-keygen reads and this module refuses on purpose.
@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

def ssh-keygen-accepts [dir: path line: string]: nothing -> bool {
    let file = $"($dir)/candidate.pub"
    $line | save --force $file
    (do { ^ssh-keygen -lf $file } | complete | get exit_code) == 0
}

def canonical-accepts [line: string]: nothing -> bool {
    try { $line | pubkey canonical; true } catch { false }
}

@test
def "canonical and ssh-keygen accept the same keys" [] {
    let tmp_dir = $in.tmp_dir
    let ed_blob = ($ED25519 | split row " " | get 1 | decode base64)
    let ed_type = ($ed_blob | bytes at 0..<15)

    # Real keys of every type ssh-keygen here can still generate.
    let generated = [["ed25519"] ["rsa"] ["ecdsa" "-b" "256"] ["ecdsa" "-b" "384"] ["ecdsa" "-b" "521"]]
        | each {|args|
            let path = $"($tmp_dir)/gen-($args | str join '-')"
            ^ssh-keygen -t $args.0 ...($args | skip 1) -f $path -N "" -q -C "someone@host"
            open --raw $"($path).pub" | str trim
        }

    let candidates = $generated ++ [
        $ED25519
        $RSA
        $SK
        # An ed25519 point that is not 32 bytes — the field walk alone took it.
        $"ssh-ed25519 (($ed_type | bytes add --end 0x[00000010] | bytes add --end 0x[41414141414141414141414141414141]) | encode base64)"
        # ...and one with no point at all.
        $"ssh-ed25519 (($ed_type | bytes add --end 0x[00000000]) | encode base64)"
        # A valid key with one extra length-prefixed field appended.
        $"ssh-ed25519 (($ed_blob | bytes add --end 0x[00000001] | bytes add --end 0x[41]) | encode base64)"
        # ssh-rsa carrying only its exponent, no modulus.
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB"
        # The type says nistp256, the blob says nistp384.
        ($generated | where {|k| $k | str starts-with "ecdsa-sha2-nistp384" } | first
            | str replace "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp256")
        # A structurally sound ssh-dss line — 5 length-prefixed fields, the
        # shape OpenSSH wrote before it dropped DSA. Refused for the type
        # alone, on both sides: a key ssh-keygen will not read is a trust-list
        # entry that verifies nothing.
        $"ssh-dss ((0x[00000007] | bytes add --end ("ssh-dss" | into binary) | bytes add --end 0x[00000001 01 00000001 02 00000001 03 00000001 04]) | encode base64)"
        "ssh-rsa A"
        "ssh-rsa Zm9v"
        "ssh-../../../../tmp/pwn Zm9v"
        "ecdsa-anything Zm9v"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"
        "hello world"
    ]

    let disagreements = $candidates | each {|line|
        {
            line: ($line | str substring 0..48)
            canonical: (canonical-accepts $line)
            ssh_keygen: (ssh-keygen-accepts $tmp_dir $line)
        }
    # A closure, not `where canonical != ssh_keygen`: the bare word on the
    # right of a `where` shorthand is a string literal, so that form compares
    # every row against "ssh_keygen" and reports all of them as disagreeing.
    } | where {|r| $r.canonical != $r.ssh_keygen }

    assert equal $disagreements []
}
