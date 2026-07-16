# Golden behavior of `pubkey canonical`: the stored pubkey bytes are the
# identity downstream (CID of the file), so the canonical encoding is
# spec-critical — pin it.
use std/assert
use std/testing *

use ../nu-multiproof/pubkey.nu

@test
def "canonical is `<type> <base64>` + newline: comment and extra whitespace dropped" [] {
    assert equal ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 alice@host\n" | pubkey canonical) "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n"
    assert equal ("ssh-ed25519  AAAAC3NzaC1lZDI1NTE5  " | pubkey canonical) "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n"
    # already-canonical input is a fixed point — verifiers rely on this
    assert equal ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n" | pubkey canonical) "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5\n"
    # sk-* types (with their trailing-space files, as ssh-keygen writes them)
    assert equal ("sk-ecdsa-sha2-nistp256@openssh.com AAAAInNr \n" | pubkey canonical) "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNr\n"
}

@test
def "canonical rejects anything that is not a single pubkey line" [] {
    assert error {|| "-----BEGIN OPENSSH PRIVATE KEY-----" | pubkey canonical }
    assert error {|| "hello world" | pubkey canonical }
    assert error {|| "ssh-ed25519" | pubkey canonical }
    assert error {|| "ssh-ed25519 not*base64" | pubkey canonical }
    assert error {|| "ssh-ed25519 AAAA\nssh-rsa BBBB" | pubkey canonical }
}
