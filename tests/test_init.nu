use std/assert
use std/testing *

use ../nu-multiproof/init.nu

# Why a fixture, not rm at the end of test bodies: after-each runs even when
# the test throws, so a failing test does not leak its /tmp/tmp.* dir.
@before-each
def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

# Comment like "alice@bar.com" must be sanitized to "alicebarcom"
# (all non-[a-zA-Z0-9_-] chars stripped, not just the first).
@test
def "init sanitizes all non-allowed chars in inline-key comment" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -C "alice@bar.com" -q

    let pubkey_data = (open --raw $"($key_path).pub" | str trim)
    ^git -C $repo config user.signingKey $"key::($pubkey_data)"

    init --repo $repo

    let names = (ls $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
    assert ($names | any { |n| $n == "alicebarcom.pub" }) $"expected alicebarcom.pub, got ($names)"
}

# A user.signingKey pointing at a private-key file (no .pub sibling) must NOT
# be copied into pubkeys/ — init must refuse with a clear error.
@test
def "init refuses to copy a private-key file as pubkey" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    rm $"($key_path).pub"

    ^git -C $repo config user.signingKey $key_path

    let outcome = (try { init --repo $repo; "ok" } catch { |e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"

    let copied = (ls $"($repo)/multiproofs/pubkeys" | length)
    assert equal $copied 0
}

# --pubkey must apply the same private-key refusal as the git-config branch.
# Otherwise an explicit `init --pubkey ~/.ssh/id_ed25519` would copy a private
# key into multiproofs/pubkeys/ (and get committed).
@test
def "init --pubkey refuses a private-key file" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    rm $"($key_path).pub"

    let outcome = (try { init --repo $repo --pubkey $key_path; "ok" } catch { |e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"

    let copied = (ls $"($repo)/multiproofs/pubkeys" | length)
    assert equal $copied 0
}

# --pubkey pointed at the private key with .pub sibling present should still
# resolve to the .pub sibling (mirrors the git-config branch's forgiving lookup).
@test
def "init --pubkey prefers .pub sibling over private-key path" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q

    init --repo $repo --pubkey $key_path

    let names = (ls $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
    assert equal ($names | length) 1
    let saved = (open --raw $"($repo)/multiproofs/pubkeys/($names | first)")
    assert ($saved | str starts-with "ssh-")
}

# When both <path> and <path>.pub exist, init should prefer the .pub sibling
# even if user.signingKey points at the private file (forgiving misconfig).
@test
def "init prefers .pub sibling when signingKey points to private key" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q

    ^git -C $repo config user.signingKey $key_path

    init --repo $repo

    let names = (ls $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
    assert equal ($names | length) 1
    let saved = (open --raw $"($repo)/multiproofs/pubkeys/($names | first)")
    assert ($saved | str starts-with "ssh-")
}

# The inline `key::` branch must apply the same shape check as the file-path
# branch. Without it, `key::<private key material>` lands a private key in
# pubkeys/ under a .pub name — the exact outcome the other branches refuse.
@test
def "init refuses inline key:: material that is not a public key" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    let private_data = (open --raw $key_path | str trim)
    ^git -C $repo config user.signingKey $"key::($private_data)"

    let outcome = (try { init --repo $repo; "ok" } catch { |e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    assert ($outcome | str contains "public key") $"expected a public-key message, got ($outcome)"

    let copied = (ls $"($repo)/multiproofs/pubkeys" | length)
    assert equal $copied 0
}

# The stored pubkey bytes are the identity downstream (nu-cybergraph hashes
# the file), so every write path must land the canonical `<type> <base64>\n`
# form — the comment ssh-keygen embeds must not survive into pubkeys/.
@test
def "init stores the registered pubkey in canonical form, comment dropped" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -C "alice@host" -q

    init --repo $repo --pubkey $"($key_path).pub"

    let names = (ls $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
    assert equal ($names | length) 1
    let saved = (open --raw $"($repo)/multiproofs/pubkeys/($names | first)")
    let src = (open --raw $"($key_path).pub" | str trim | split row " ")
    assert equal $saved $"($src.0) ($src.1)\n"
}
