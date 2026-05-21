use std/assert
use std/testing *

use ../nu-multiproof/ssh-sign.nu

@test
def "sign creates named sig file" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let key_path = $"($tmp_dir)/somekey"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_path).pub" ($pubkeys_dir | path join "alice.pub")
    "hello world" | save --force $test_file

    ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir
    assert ($"($test_file).alice.sig" | path exists)
    assert (not ($"($test_file).sig" | path exists))

    rm --recursive $tmp_dir
}

@test
def "sign with custom name" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let key_path = $"($tmp_dir)/mykey"
    let test_file = $"($tmp_dir)/test.txt"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    "hello world" | save --force $test_file

    ssh-sign sign $test_file --key $key_path --name bob
    assert ($"($test_file).bob.sig" | path exists)

    rm --recursive $tmp_dir
}

@test
def "sign and verify round-trip" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let key_path = $"($tmp_dir)/test_key"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_path).pub" ($pubkeys_dir | path join "test.pub")

    "hello world" | save --force $test_file

    ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir
    let results = ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir
    assert equal ($results | length) 1
    assert equal ($results | first | get valid) true
    assert equal ($results | first | get signer) "test"

    rm --recursive $tmp_dir
}

@test
def "multiple signers" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let key_alice = $"($tmp_dir)/alice"
    let key_bob = $"($tmp_dir)/bob"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_alice -N "" -q
    ^ssh-keygen -t ed25519 -f $key_bob -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_alice).pub" ($pubkeys_dir | path join "alice.pub")
    cp $"($key_bob).pub" ($pubkeys_dir | path join "bob.pub")

    "hello world" | save --force $test_file

    ssh-sign sign $test_file --key $key_alice --pubkeys-dir $pubkeys_dir
    ssh-sign sign $test_file --key $key_bob --pubkeys-dir $pubkeys_dir
    assert ($"($test_file).alice.sig" | path exists)
    assert ($"($test_file).bob.sig" | path exists)

    let results = ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir
    assert equal ($results | length) 2
    assert equal ($results | where valid == true | length) 2

    rm --recursive $tmp_dir
}

@test
def "verify fails with wrong key" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let sign_key = $"($tmp_dir)/sign_key"
    let wrong_key = $"($tmp_dir)/wrong_key"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $sign_key -N "" -q
    ^ssh-keygen -t ed25519 -f $wrong_key -N "" -q

    mkdir $pubkeys_dir
    cp $"($wrong_key).pub" ($pubkeys_dir | path join "wrong.pub")

    "hello world" | save --force $test_file
    ssh-sign sign $test_file --key $sign_key --name attacker

    # Why: sig is cryptographically valid (good format, matches content) but
    # the signer's key isn't in pubkeys_dir. Must surface as `unrecognized_signer`,
    # not collapse with the tampered-content case below.
    let results = ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir
    assert equal ($results | first | get valid) false
    assert equal ($results | first | get error) "unrecognized_signer"

    rm --recursive $tmp_dir
}

@test
def "verify fails with tampered content" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let key_path = $"($tmp_dir)/test_key"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_path).pub" ($pubkeys_dir | path join "test.pub")

    "original content" | save --force $test_file
    ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir

    "tampered content" | save --force $test_file

    # Why: signature no longer matches content — must surface as
    # `invalid_signature`, distinct from the unrecognized-signer case above.
    let results = ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir
    assert equal ($results | first | get valid) false
    assert equal ($results | first | get error) "invalid_signature"

    rm --recursive $tmp_dir
}

@test
def "verify infers original from .sig path with hyphenated signer" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let key_path = $"($tmp_dir)/test_key"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_path).pub" ($pubkeys_dir | path join "maxim-uvarov2.pub")

    "hello world" | save --force $test_file
    ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir

    # Why: signer names can contain `-`. The infer branch uses a regex on the
    # `.sig` path to recover the original; `\w` excludes `-` so this would fail.
    let sig_path = $"($test_file).maxim-uvarov2.sig"
    assert ($sig_path | path exists) $"sig not written at expected path: ($sig_path)"
    let results = ssh-sign verify $sig_path --pubkeys-dir $pubkeys_dir
    assert equal ($results | length) 1
    assert equal ($results | first | get valid) true
    assert equal ($results | first | get signer) "maxim-uvarov2"

    rm --recursive $tmp_dir
}

@test
def "verify with explicit --sig" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let key_path = $"($tmp_dir)/test_key"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_path).pub" ($pubkeys_dir | path join "test.pub")

    "hello world" | save --force $test_file
    ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir

    # Why explicit --sig: exercises the single-file branch (was unexercised);
    # default flow uses the glob branch.
    let results = ssh-sign verify $test_file --sig $"($test_file).test.sig" --pubkeys-dir $pubkeys_dir
    assert equal ($results | length) 1
    assert equal ($results | first | get valid) true
    assert equal ($results | first | get signer) "test"

    rm --recursive $tmp_dir
}
