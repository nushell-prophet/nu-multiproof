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
