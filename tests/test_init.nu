use std/assert
use std/testing *

use ../nu-multiproof/init.nu

# Comment like "alice@bar.com" must be sanitized to "alicebarcom"
# (all non-[a-zA-Z0-9_-] chars stripped, not just the first).
@test
def "init sanitizes all non-allowed chars in inline-key comment" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -C "alice@bar.com" -q

    let pubkey_data = (open --raw $"($key_path).pub" | str trim)
    ^git -C $repo config user.signingKey $"key::($pubkey_data)"

    init --path $repo

    let names = (ls $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
    assert ($names | any { |n| $n == "alicebarcom.pub" }) $"expected alicebarcom.pub, got ($names)"

    rm --recursive $tmp_dir
}

# A user.signingKey pointing at a private-key file (no .pub sibling) must NOT
# be copied into pubkeys/ — init must refuse with a clear error.
@test
def "init refuses to copy a private-key file as pubkey" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    rm $"($key_path).pub"

    ^git -C $repo config user.signingKey $key_path

    let outcome = (try { init --path $repo; "ok" } catch { |e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"

    let copied = (ls $"($repo)/multiproofs/pubkeys" | length)
    assert equal $copied 0

    rm --recursive $tmp_dir
}

# When both <path> and <path>.pub exist, init should prefer the .pub sibling
# even if user.signingKey points at the private file (forgiving misconfig).
@test
def "init prefers .pub sibling when signingKey points to private key" [] {
    let tmp_dir = (^mktemp -d | str trim)
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q

    ^git -C $repo config user.signingKey $key_path

    init --path $repo

    let names = (ls $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
    assert equal ($names | length) 1
    let saved = (open --raw $"($repo)/multiproofs/pubkeys/($names | first)")
    assert ($saved | str starts-with "ssh-")

    rm --recursive $tmp_dir
}
