use std/assert
use std/testing *

use ../nu-multiproof/init.nu

# Why a const: one test checks what init *prints*, which is only observable
# from outside the process — it spawns `nu` and needs the module's real path.
const MODULE_DIR = path self ../nu-multiproof

# SHA256:... fingerprint of a public key file.
def fingerprint-of [pub_file: path]: nothing -> string {
    ^ssh-keygen -lf $pub_file | str trim | split row " " | get 1
}

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

    let names = (ls --all $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
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

    let copied = (ls --all $"($repo)/multiproofs/pubkeys" | length)
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

    let copied = (ls --all $"($repo)/multiproofs/pubkeys" | length)
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

    let names = (ls --all $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
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

    let names = (ls --all $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
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

    let copied = (ls --all $"($repo)/multiproofs/pubkeys" | length)
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

    let names = (ls --all $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
    assert equal ($names | length) 1
    let saved = (open --raw $"($repo)/multiproofs/pubkeys/($names | first)")
    let src = (open --raw $"($key_path).pub" | str trim | split row " ")
    assert equal $saved $"($src.0) ($src.1)\n"
}

# Registering the very same key twice is a no-op, and the message must say so.
# Checked through an external `nu` because print output is not observable
# in-process.
@test
def "init reports the same key registered twice as already registered" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/alice"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q

    init --repo $repo --pubkey $"($key_path).pub"
    let first = (open --raw $"($repo)/multiproofs/pubkeys/alice.pub")

    let out = (^nu -c $"use ($MODULE_DIR)/init.nu; init --repo ($repo) --pubkey ($key_path).pub" | complete)
    assert equal $out.exit_code 0 $"expected exit 0, got ($out)"
    assert ($out.stdout | str contains "pubkey already registered: multiproofs/pubkeys/alice.pub") $"got ($out.stdout)"

    assert equal (ls --all $"($repo)/multiproofs/pubkeys" | length) 1
    assert equal (open --raw $"($repo)/multiproofs/pubkeys/alice.pub") $first
}

# A *different* key whose file shares a stem must be refused out loud: the old
# code printed "already exists" and kept the first key, so the operator was
# told a key was registered when it was rejected.
@test
def "init refuses a different key whose file shares a stem" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let first_key = $"($tmp_dir)/alice"
    ^ssh-keygen -t ed25519 -f $first_key -N "" -q
    init --repo $repo --pubkey $"($first_key).pub"
    let registered = (open --raw $"($repo)/multiproofs/pubkeys/alice.pub")

    # Same stem, different key material.
    mkdir $"($tmp_dir)/other"
    let second_key = $"($tmp_dir)/other/alice"
    ^ssh-keygen -t ed25519 -f $second_key -N "" -q

    let outcome = (try { init --repo $repo --pubkey $"($second_key).pub"; "ok" } catch { |e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    assert ($outcome | str contains "already holds a different key") $"got ($outcome)"
    assert ($outcome | str contains (fingerprint-of $"($first_key).pub")) $"registered fingerprint missing: ($outcome)"
    assert ($outcome | str contains (fingerprint-of $"($second_key).pub")) $"offered fingerprint missing: ($outcome)"

    assert equal (open --raw $"($repo)/multiproofs/pubkeys/alice.pub") $registered
}

# The same key under a second stem yields two matching files, and `ssh-sign`'s
# signer lookup then dies with `multiple pubkeys match`. Refuse at init instead.
@test
def "init refuses the same key material under another name" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/alice"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    init --repo $repo --pubkey $"($key_path).pub"

    cp $"($key_path).pub" $"($tmp_dir)/bob.pub"
    let outcome = (try { init --repo $repo --pubkey $"($tmp_dir)/bob.pub"; "ok" } catch { |e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    assert ($outcome | str contains "already registered as multiproofs/pubkeys/alice.pub") $"got ($outcome)"

    let names = (ls --all $"($repo)/multiproofs/pubkeys" | get name | each { path basename })
    assert equal $names ["alice.pub"]
}

# The inline `key::` branch derives the name from the key comment, so two
# machines' keys sharing "alice@host" collide far more easily than file stems.
@test
def "init refuses a different inline key that derives the same name" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let first_key = $"($tmp_dir)/first"
    ^ssh-keygen -t ed25519 -f $first_key -N "" -C "alice@host" -q
    ^git -C $repo config user.signingKey $"key::(open --raw $"($first_key).pub" | str trim)"
    init --repo $repo
    let registered = (open --raw $"($repo)/multiproofs/pubkeys/alicehost.pub")

    let second_key = $"($tmp_dir)/second"
    ^ssh-keygen -t ed25519 -f $second_key -N "" -C "alice@host" -q
    ^git -C $repo config user.signingKey $"key::(open --raw $"($second_key).pub" | str trim)"

    let outcome = (try { init --repo $repo; "ok" } catch { |e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    assert ($outcome | str contains "already holds a different key") $"got ($outcome)"

    assert equal (open --raw $"($repo)/multiproofs/pubkeys/alicehost.pub") $registered
}

# The attack the duplicate check cannot see: mallory holds alice's *public*
# key — it is public — and files a copy whose RSA modulus carries one redundant
# leading zero. `ssh-keygen -lf` loads it and prints alice's own fingerprint,
# and `check-registration` compares canonical bytes, which differ, so neither
# the stem check nor the twin check fires. Registered, alice's signature then
# verifies as mallory. Refused now because the bytes are not the ones OpenSSH
# writes for that key.
const RSA_PADDED_MODULUS = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAgAAxMZ8FFYbCIeusNTiBhxcq9Ka4qJ8R6BxJpEnYA7zKPOrw2qx8DvPB+ckOGYUXFEwUuKS2DGxjHhkHx0AWySOD/F2q7IMrO03zGfaCau/7b0p7fOcX5F4sYUkkzJpdw/NBQL4UuIT450m6mmlXgXFund7ggxqYm12fXrXnfZ2NT7FbbLxE+e6KCfKhoeHt5apMAlyWgihgGOM6rU2SgBI7JtD3ArnhQ7jfc1k082MvV2bnKnBmgQ7Ja8pYseQFvNUMDs1pZBO57pFhgoLki1Hs5rPMq9TVPWdhwZcLd4VQuQS6jzqw1keeY4RELhlfEVWQU+i2lX1XT6oTQNZSU5/Yw=="
const RSA_ALICE = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDExnwUVhsIh66w1OIGHFyr0prionxHoHEmkSdgDvMo86vDarHwO88H5yQ4ZhRcUTBS4pLYMbGMeGQfHQBbJI4P8Xarsgys7TfMZ9oJq7/tvSnt85xfkXixhSSTMml3D80FAvhS4hPjnSbqaaVeBcW6d3uCDGpibXZ9eted9nY1PsVtsvET57ooJ8qGh4e3lqkwCXJaCKGAY4zqtTZKAEjsm0PcCueFDuN9zWTTzYy9XZucqcGaBDslrylix5AW81QwOzWlkE7nukWGCguSLUezms8yr1NU9Z2HBlwt3hVC5BLqPOrDWR55jhEQuGV8RVZBT6LaVfVdPqhNA1lJTn9j"

@test
def "init refuses a second encoding of a key it already holds" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    $"($RSA_ALICE) alice@host\n" | save --force $"($tmp_dir)/alice.pub"
    init --repo $repo --pubkey $"($tmp_dir)/alice.pub"

    $"($RSA_PADDED_MODULUS) mallory@host\n" | save --force $"($tmp_dir)/mallory.pub"
    let outcome = try { init --repo $repo --pubkey $"($tmp_dir)/mallory.pub"; "ok" } catch {|e| $e.msg }
    assert ($outcome | str contains "not the encoding OpenSSH writes") $"the padded copy was registered: ($outcome)"
    # The same key, so the fingerprints match — that is what makes this a fork
    # rather than two keys, and what the twin check could not see.
    assert equal (fingerprint-of $"($tmp_dir)/alice.pub") (fingerprint-of $"($tmp_dir)/mallory.pub")
    assert equal (ls --all $"($repo)/multiproofs/pubkeys" | get name | each { path basename }) ["alice.pub"]
}

# The key type reaches a file name when the key carries no comment, so a type
# that is a path used to write outside pubkeys/: `key::ssh-../../../../pwned
# Zm9v` created /tmp/pwned.pub. The refusal lives in `pubkey canonical`, which
# only accepts the types OpenSSH writes.
@test
def "init refuses an inline key whose type names a path" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    # One level up, into a directory that exists: the write lands unless the
    # type itself is refused.
    let escape = $"($repo)/multiproofs/pwned.pub"
    ^git -C $repo config user.signingKey "key::ssh-../pwned Zm9v"

    let outcome = (try { init --repo $repo; "ok" } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    assert (not ($escape | path exists)) "init wrote outside pubkeys/"
    assert equal (ls --all $"($repo)/multiproofs/pubkeys" | length) 0
}

# The registered file's stem is this key's principal in every allowed_signers
# the repo renders, so a stem the renderer refuses is a registration that
# breaks every later verify in that repo — no verdict at all, from a command
# that printed success. Hostile input here is the *file name*, which no key
# in this repo's own pubkeys/ would ever carry.
@test
def "init refuses a pubkey whose file name cannot be a principal" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q

    # `*` would be trusted for every signer; the rest write more (or other)
    # principals than the one line they are meant to be.
    # The last one is invisible: `ali<U+200B>ce.pub` reads as `alice.pub` in the
    # PR that adds it and in every `verify` line that names the signer.
    for stem in ["al ice" "*" "alice,mallory" 'ali"ce' "ali?e" "#alice" "ali\u{200b}ce"] {
        let source = $"($tmp_dir)/($stem).pub"
        cp $"($key_path).pub" $source

        let outcome = try { init --repo $repo --pubkey $source; "ok" } catch {|e| $e.msg }
        assert ($outcome | str contains "signer name") $"stem ($stem) was registered: ($outcome)"
        assert equal (ls --all $"($repo)/multiproofs/pubkeys" | length) 0 $"stem ($stem) reached pubkeys/"
        rm $source
    }

    # The same key under an expressible name still registers — the refusal is
    # about the name, not about the key.
    init --repo $repo --pubkey $"($key_path).pub"
    assert equal (ls --all $"($repo)/multiproofs/pubkeys" | get name | each { path basename }) ["sshkey.pub"]
}

# A key with no comment is named after its type. Splitting on a single space
# made `ssh-ed25519  AAAA…` look like three fields, so the "comment" the name
# came from was the base64 blob itself.
@test
def "a commentless key is named after its type, whatever the spacing" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -C "" -q
    let spaced = (open --raw $"($key_path).pub" | str trim | str replace " " "  ")
    ^git -C $repo config user.signingKey $"key::($spaced)"

    init --repo $repo
    assert equal (ls --all $"($repo)/multiproofs/pubkeys" | get name | each { path basename }) ["ed25519.pub"]
}
