# Golden behavior of `pubkey canonical`: the stored pubkey bytes are the
# identity downstream (CID of the file), so the canonical encoding is
# spec-critical — pin it. The fixtures are real `ssh-keygen` output, not
# truncated blobs: the checks here parse the key material, so a made-up base64
# string would only prove that the rejection path works.
use std/assert
use std/testing *

use ../nu-multiproof/pubkey.nu

# Why a const: one test asks what the operator sees under a fixed umask, which
# only a separate process can answer.
const MODULE_DIR = path self ../nu-multiproof

const ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOi7LinplEQewM3/l8Ol9rE85+YwhvLPKf+ZUUf36Xuf"
const RSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDExnwUVhsIh66w1OIGHFyr0prionxHoHEmkSdgDvMo86vDarHwO88H5yQ4ZhRcUTBS4pLYMbGMeGQfHQBbJI4P8Xarsgys7TfMZ9oJq7/tvSnt85xfkXixhSSTMml3D80FAvhS4hPjnSbqaaVeBcW6d3uCDGpibXZ9eted9nY1PsVtsvET57ooJ8qGh4e3lqkwCXJaCKGAY4zqtTZKAEjsm0PcCueFDuN9zWTTzYy9XZucqcGaBDslrylix5AW81QwOzWlkE7nukWGCguSLUezms8yr1NU9Z2HBlwt3hVC5BLqPOrDWR55jhEQuGV8RVZBT6LaVfVdPqhNA1lJTn9j"
# A hardware-backed key, assembled field by field (type, key, application) —
# `ssh-keygen -t ed25519-sk` needs a security key present.
const SK = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIDfEkyImHgI7LfesBcs1Q1OQlod52hqMaAYxpRExv2OqAAAABHNzaDo="
# The seventh accepted type, assembled the same way (type, curve, point,
# application) around a real nistp256 point — `ssh-keygen -t ecdsa-sk` needs a
# security key present, so without this the type had no vector at all and the
# fixed-point claim covered six of seven.
const SK_ECDSA = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBE/Y3fEWc3l4tPCRaXjcZ+s6DEyWxEpTpgFGyyoDGyE996NZmu1UYuzksgXTOyTx+tGMHOzsBx5xlUKzh7FgTIcAAAAEc3NoOg=="
# RSA above with one redundant 0x00 byte in front of its modulus. RFC 4251
# allows a leading zero only when the next byte's high bit is set, but OpenSSH
# trims leading zeros while parsing instead of refusing them — `ssh-keygen -lf`
# takes this line, exits 0 and prints the *same* SHA256 fingerprint as RSA.
# That is the fork: one key, two canonical lines, two file-byte CIDs, two
# identities. Built by hand from the constant above, not by this repo's code.
const RSA_PADDED_MODULUS = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAgAAxMZ8FFYbCIeusNTiBhxcq9Ka4qJ8R6BxJpEnYA7zKPOrw2qx8DvPB+ckOGYUXFEwUuKS2DGxjHhkHx0AWySOD/F2q7IMrO03zGfaCau/7b0p7fOcX5F4sYUkkzJpdw/NBQL4UuIT450m6mmlXgXFund7ggxqYm12fXrXnfZ2NT7FbbLxE+e6KCfKhoeHt5apMAlyWgihgGOM6rU2SgBI7JtD3ArnhQ7jfc1k082MvV2bnKnBmgQ7Ja8pYseQFvNUMDs1pZBO57pFhgoLki1Hs5rPMq9TVPWdhwZcLd4VQuQS6jzqw1keeY4RELhlfEVWQU+i2lX1XT6oTQNZSU5/Yw=="

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

# The identity fork, and the reason `ssh-keygen -lf` is not the oracle here:
# it loads this line, exits 0 and prints RSA's own fingerprint. Whoever holds
# alice's public key can therefore file a second canonical line for it, and
# `init`'s duplicate check — which compares canonical bytes — does not fire.
# `ssh-sign verify` then names that second registration as the signer of
# alice's signature.
@test
def "canonical refuses a second encoding of a key it already accepts" [] {
    let tmp_dir = $in.tmp_dir
    assert (ssh-keygen-accepts $tmp_dir $RSA_PADDED_MODULUS) "the vector no longer loads — it must be a key OpenSSH takes, or it proves nothing"
    assert equal (fingerprint-of $tmp_dir $RSA_PADDED_MODULUS) (fingerprint-of $tmp_dir $RSA) "the vector must be the same key to be a fork"

    assert equal ($RSA | pubkey canonical) $"($RSA)\n"
    let outcome = try { $RSA_PADDED_MODULUS | pubkey canonical; "accepted" } catch {|e| $e.msg }
    assert ($outcome | str contains "not the encoding OpenSSH writes") $"the padded copy was accepted: ($outcome)"
}

# The other half of the same rule: re-encoding must leave a real key alone. If
# the round trip moved any accepted key's bytes, `canonical` would refuse
# ordinary keys — and every stored identity would depend on the OpenSSH build
# that wrote it.
@test
def "canonical is a fixed point for real keys of every accepted type" [] {
    let tmp_dir = $in.tmp_dir
    let generated = [["ed25519"] ["rsa"] ["ecdsa" "-b" "256"] ["ecdsa" "-b" "384"] ["ecdsa" "-b" "521"]]
        | each {|args|
            let path = $"($tmp_dir)/fixed-($args | str join '-')"
            ^ssh-keygen -t $args.0 ...($args | skip 1) -f $path -N "" -q -C "someone@host"
            open --raw $"($path).pub" | str trim
        }

    for key in ($generated ++ [$ED25519 $RSA $SK $SK_ECDSA]) {
        let line = $key | split row --regex '\s+' | first 2 | str join " "
        assert equal ($key | pubkey canonical) $"($line)\n"
        # and applying it twice changes nothing more
        assert equal ($key | pubkey canonical | pubkey canonical) $"($line)\n"
    }
}

# What the type allowlist is for, and the only thing that is: two shapes
# ssh-keygen reads happily — it loads a certificate and re-serializes it
# unchanged, and it takes an authorized_keys line with an options prefix. Both
# are refused here on the type field alone. A certificate carries its own
# principals and validity window, so storing one in pubkeys/ would put a second
# authority beside the file name this repo treats as the identity; an options
# prefix would make the stored bytes carry an instruction.
#
# Mutation-checked: deleting the allowlist leaves every other test in this file
# green, because the round trip's accept-set is ssh-keygen's own.
@test
def "canonical refuses the key shapes ssh-keygen reads but pubkeys/ must not hold" [] {
    let tmp_dir = $in.tmp_dir
    let ca = $"($tmp_dir)/ca"
    let user = $"($tmp_dir)/user"
    ^ssh-keygen -t ed25519 -f $ca -N "" -q
    ^ssh-keygen -t ed25519 -f $user -N "" -q -C "alice@host"
    ^ssh-keygen -s $ca -I alice-id -n alice -V +52w $"($user).pub"

    let cert = open --raw $"($user)-cert.pub" | str trim
    let options_prefix = $"command=\"rm -rf /\" (open --raw $"($user).pub" | str trim)"

    for line in [$cert $options_prefix] {
        assert (ssh-keygen-accepts $tmp_dir $line) $"vector no longer loads in ssh-keygen, so it proves nothing: ($line | str substring 0..40)"
        assert (not (canonical-accepts $line)) $"accepted into pubkeys/: ($line | str substring 0..40)"
    }
}

# The refusal an operator actually has to act on, and the one branch where the
# reason comes from another program. `ssh-keygen -e` retries a public key it
# cannot read as a *private* key, so at a common umask the temp file trips the
# UNPROTECTED PRIVATE KEY FILE banner and the reported cause became a
# permissions complaint about a path that no longer exists — a message that
# changed with the operator's umask. Run under a fixed umask 0022 for that
# reason: at 0077 the bug is invisible.
@test
def "an unreadable key reports the parser reason, not a umask artifact" [] {
    let tmp_dir = $in.tmp_dir
    let script = $"($tmp_dir)/probe.nu"
    # Valid base64 of the right shape, but not a key: it gets past the type
    # allowlist and dies inside ssh-keygen, which is the branch under test.
    let broken = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICQSxzg3nX7AN3jgd3UK5yRoZgY/SX5cuFFiFwpjKuj="
    [
        $"use ($MODULE_DIR)/pubkey.nu"
        $"const BROKEN = \"($broken)\""
        # A plain "…" string, not $"…": the `$e` inside must reach the probe as
        # source text, not be resolved here.
        "try { $BROKEN | pubkey canonical } catch {|e| print $e.msg }"
    ] | str join "\n" | save --force $script

    let out = ^bash -c $"umask 0022; exec nu ($script)" | complete
    assert ($out.stdout | str contains "invalid format") $"expected ssh-keygen's parse error, got: ($out.stdout)"
    assert (not ($out.stdout | str contains "UNPROTECTED")) $"the reason is a umask artifact: ($out.stdout)"
    assert (not ($out.stdout | str contains $nu.temp-dir)) $"the reason names a temp path the operator cannot look at: ($out.stdout)"
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

# The outside oracle, and it pins one direction only: nothing `canonical`
# accepts may be a line `ssh-keygen -lf` cannot load. A key that fails that way
# is a trust-list entry which silently verifies nothing.
#
# Not the converse, and that is deliberate — `canonical` is strictly the
# narrower of the two. `-lf` loads a certificate, an authorized_keys options
# prefix and a padded copy of a registered key; each is refused here, and each
# has its own test above. Asserting set *equality* would either fail or, worse,
# pass by leaving those vectors out of the candidate list, which is what an
# earlier version of this test did.
#
# The check is one-sided, so it would also pass if `canonical` refused
# everything. The real keys below are asserted accepted by both to keep it from
# holding vacuously.
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

# SHA256 fingerprint ssh-keygen computes for a key line — the identity OpenSSH
# itself would report for it.
def fingerprint-of [dir: path line: string]: nothing -> string {
    let file = $"($dir)/fingerprint.pub"
    $line | save --force $file
    ^ssh-keygen -lf $file | str trim | split row " " | get 1
}

def canonical-accepts [line: string]: nothing -> bool {
    try { $line | pubkey canonical; true } catch { false }
}

@test
def "canonical never accepts a key ssh-keygen cannot load" [] {
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
        $SK_ECDSA
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
        # The seven shapes the hand-written field walk accepted and ssh-keygen
        # refuses, assembled field by field outside this repo. Counting
        # length-prefixed fields only proves the bytes divide evenly; whether
        # an mpint is a modulus or an EC point is on the curve is decided by
        # the parser that will have to load the key.
        "ssh-rsa AAAAB3NzaC1yc2EAAAABAwAAAAEF"
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAAA=="
        "ssh-rsa AAAAB3NzaC1yc2EAAAAAAAAAAA=="
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBEFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEAAAAEc3NoOg=="
        "ssh-rsa A"
        "ssh-rsa Zm9v"
        "ssh-../../../../tmp/pwn Zm9v"
        "ecdsa-anything Zm9v"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"
        "hello world"
    ]

    # The whole line, not a prefix: several candidates are corruptions of a
    # real key and share its first 48 characters, so a truncated key would put
    # them in the same bucket as the key they attack.
    let verdicts = $candidates | each {|line|
        {
            line: $line
            canonical: (canonical-accepts $line)
            ssh_keygen: (ssh-keygen-accepts $tmp_dir $line)
        }
    }

    # A closure, not `where canonical and not ssh_keygen`: the bare word on the
    # right of a `where` shorthand is a string literal, so that form compares
    # every row against "ssh_keygen" instead of reading the column.
    let unloadable = $verdicts | where {|r| $r.canonical and not $r.ssh_keygen }
        | each {|r| $r | update line ($r.line | str substring 0..48) }
    assert equal $unloadable [] "canonical accepted a key ssh-keygen cannot load"

    # Not vacuous: a `canonical` that refused everything would satisfy the
    # assertion above.
    let real_keys = $generated ++ [$ED25519 $RSA $SK $SK_ECDSA]
    let real = $verdicts | where {|r| $r.line in $real_keys }
    assert equal ($real | length) ($real_keys | length) "a real key is missing from the candidate list"
    assert ($real | all {|r| $r.canonical and $r.ssh_keygen }) $"a real key was refused: ($real | where {|r| not $r.canonical } | get line | each {|l| $l | str substring 0..48 })"
}
