use std/assert
use std/testing *

use ../nu-multiproof/init.nu
use ../nu-multiproof/pubkey.nu

# Why a const: one test checks what init *prints*, which is only observable
# from outside the process — it spawns `nu` and needs the module's real path.
const MODULE_DIR = path self ../nu-multiproof

# SHA256:... fingerprint of a public key file — the form ssh-keygen prints, which
# is what init's operator-facing messages carry.
def fingerprint-of [pub_file: path]: nothing -> string {
    ^ssh-keygen -lf $pub_file | str trim | split row " " | get 1
}

# The principal a key registers under, derived the way the module derives it.
def principal-of [pub_file: path]: nothing -> string {
    open --raw $pub_file | pubkey fingerprint
}

def registered [repo: path]: nothing -> list<string> {
    ls --all $"($repo)/multiproofs/pubkeys" | get name | path basename
}

def make-repo [tmp_dir: path]: nothing -> path {
    let repo = $"($tmp_dir)/repo"
    mkdir $repo
    ^git -C $repo init -q
    $repo
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

# Nothing derives a file name from a key comment: the name is the fingerprint,
# and the comment does not survive `pubkey canonical` at all.
@test
def "an inline key registers under its fingerprint, not its comment" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -C "alice@bar.com" -q
    ^git -C $repo config user.signingKey $"key::(open --raw $"($key_path).pub" | str trim)"

    init --repo $repo

    assert equal (registered $repo) [$"(principal-of $"($key_path).pub").pub"]
}

# The vector is the spacing: `ssh-ed25519  AAAA…` looks like three fields when
# split on a single space, and the line still has to reach `canonical` intact.
# No field of it decides a name — the fingerprint does.
@test
def "a commentless inline key registers under its fingerprint, whatever the spacing" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -C "" -q
    let spaced = (open --raw $"($key_path).pub" | str trim | str replace " " "  ")
    ^git -C $repo config user.signingKey $"key::($spaced)"

    init --repo $repo
    assert equal (registered $repo) [$"(principal-of $"($key_path).pub").pub"]
}

# A user.signingKey pointing at a private-key file (no .pub sibling) must NOT
# be copied into pubkeys/ — init must refuse with a clear error.
@test
def "init refuses to copy a private-key file as pubkey" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    rm $"($key_path).pub"

    ^git -C $repo config user.signingKey $key_path

    let outcome = (try { init --repo $repo; "ok" } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"

    assert equal (registered $repo) []
}

# --pubkey must apply the same private-key refusal as the git-config branch.
# Otherwise an explicit `init --pubkey ~/.ssh/id_ed25519` would copy a private
# key into multiproofs/pubkeys/ (and get committed).
@test
def "init --pubkey refuses a private-key file" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    rm $"($key_path).pub"

    let outcome = (try { init --repo $repo --pubkey $key_path; "ok" } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"

    assert equal (registered $repo) []
}

# --pubkey pointed at the private key with .pub sibling present should still
# resolve to the .pub sibling (mirrors the git-config branch's forgiving lookup).
@test
def "init --pubkey prefers .pub sibling over private-key path" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q

    init --repo $repo --pubkey $key_path

    assert equal (registered $repo) [$"(principal-of $"($key_path).pub").pub"]
    let saved = (open --raw $"($repo)/multiproofs/pubkeys/(registered $repo | first)")
    assert ($saved | str starts-with "ssh-")
}

# When both <path> and <path>.pub exist, init should prefer the .pub sibling
# even if user.signingKey points at the private file (forgiving misconfig).
@test
def "init prefers .pub sibling when signingKey points to private key" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q

    ^git -C $repo config user.signingKey $key_path

    init --repo $repo

    assert equal (registered $repo) [$"(principal-of $"($key_path).pub").pub"]
    let saved = (open --raw $"($repo)/multiproofs/pubkeys/(registered $repo | first)")
    assert ($saved | str starts-with "ssh-")
}

# The inline `key::` branch must apply the same shape check as the file-path
# branch. Without it, `key::<private key material>` lands a private key in
# pubkeys/ under a .pub name — the exact outcome the other branches refuse.
@test
def "init refuses inline key:: material that is not a public key" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    let private_data = (open --raw $key_path | str trim)
    ^git -C $repo config user.signingKey $"key::($private_data)"

    let outcome = (try { init --repo $repo; "ok" } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    # The inner refusal must survive: private key material is multi-line, and
    # `pubkey canonical` names that exact reason. A bare `str contains "public
    # key"` was satisfied by the wholesale replacement text just as well.
    assert ($outcome | str contains "not a single-line SSH public key") $"expected canonical's own refusal, got ($outcome)"
    assert ($outcome | str contains "user.signingKey") $"the error does not name where the key came from: ($outcome)"

    assert equal (registered $repo) []
}

# The stored pubkey bytes are the identity downstream (nu-cybergraph hashes
# the file), so every write path must land the canonical `<type> <base64>\n`
# form — the comment ssh-keygen embeds must not survive into pubkeys/.
@test
def "init stores the registered pubkey in canonical form, comment dropped" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -C "alice@host" -q

    init --repo $repo --pubkey $"($key_path).pub"

    assert equal (registered $repo | length) 1
    let saved = (open --raw $"($repo)/multiproofs/pubkeys/(registered $repo | first)")
    let src = (open --raw $"($key_path).pub" | str trim | split row " ")
    assert equal $saved $"($src.0) ($src.1)\n"
}

# Registering the very same key twice is a no-op, and the message must say so.
# Checked through an external `nu` because print output is not observable
# in-process.
@test
def "init reports the same key registered twice as already registered" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/alice"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    let name = $"(principal-of $"($key_path).pub").pub"

    init --repo $repo --pubkey $"($key_path).pub"
    let first = (open --raw $"($repo)/multiproofs/pubkeys/($name)")

    let out = (^nu -c $"use ($MODULE_DIR)/init.nu; init --repo ($repo) --pubkey ($key_path).pub" | complete)
    assert equal $out.exit_code 0 $"expected exit 0, got ($out)"
    assert ($out.stdout | str contains $"pubkey already registered: multiproofs/pubkeys/($name)") $"got ($out.stdout)"

    assert equal (registered $repo) [$name]
    assert equal (open --raw $"($repo)/multiproofs/pubkeys/($name)") $first
}

# The same key from two differently named files. One key has one fingerprint, so
# both registrations land on the same path and the second is a no-op.
@test
def "the same key offered under two file names registers once" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/alice"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    init --repo $repo --pubkey $"($key_path).pub"

    cp $"($key_path).pub" $"($tmp_dir)/bob.pub"
    init --repo $repo --pubkey $"($tmp_dir)/bob.pub"

    assert equal (registered $repo) [$"(principal-of $"($key_path).pub").pub"]
}

# Two different keys carrying the same comment are two keys, so they register
# side by side — a key's identity is not a string anyone else can occupy.
@test
def "two different keys sharing a comment both register" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let expected = ["first" "second"] | each {|which|
            let key = $"($tmp_dir)/($which)"
            ^ssh-keygen -t ed25519 -f $key -N "" -C "alice@host" -q
            ^git -C $repo config user.signingKey $"key::(open --raw $"($key).pub" | str trim)"
            init --repo $repo
            $"(principal-of $"($key).pub").pub"
        }

    assert equal (registered $repo | sort) ($expected | sort)
}

# Not reachable through `init` — the name it writes IS the fingerprint of the
# bytes it writes — so this is a hand-edited trust list: a file named for alice's
# key holding bob's. Registering alice must not overwrite it, and must not report
# success. The file is written by hand for that reason; nothing this repo does
# produces one.
@test
def "a file named for one key but holding another is refused, not overwritten" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let alice = $"($tmp_dir)/alice"
    let bob = $"($tmp_dir)/bob"
    ^ssh-keygen -t ed25519 -f $alice -N "" -q
    ^ssh-keygen -t ed25519 -f $bob -N "" -q

    let lying = $"($repo)/multiproofs/pubkeys/(principal-of $"($alice).pub").pub"
    mkdir ($lying | path dirname)
    open --raw $"($bob).pub" | save --force $lying
    let planted = open --raw $lying

    let outcome = try { init --repo $repo --pubkey $"($alice).pub"; "ok" } catch {|e| $e.msg }
    assert ($outcome | str contains "holds a different key") $"got ($outcome)"
    # Both fingerprints, in the form ssh-keygen prints, so the operator can tell
    # which file to move.
    assert ($outcome | str contains (fingerprint-of $"($alice).pub")) $"offered fingerprint missing: ($outcome)"
    assert ($outcome | str contains (fingerprint-of $"($bob).pub")) $"stored fingerprint missing: ($outcome)"
    assert equal (open --raw $lying) $planted "the planted key was overwritten"
}

# The attack no name-based check can see: mallory holds alice's *public* key — it
# is public — and files a copy whose RSA modulus carries one redundant leading
# zero. `ssh-keygen -lf` loads it and prints alice's own fingerprint, so it is
# the same key by OpenSSH's reckoning, but its blob bytes differ — a second
# canonical line, a second file-byte CID, and (before the fingerprint became the
# principal) a second name to sign under. Refused because the bytes are not the
# ones OpenSSH writes for that key.
const RSA_PADDED_MODULUS = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAgAAxMZ8FFYbCIeusNTiBhxcq9Ka4qJ8R6BxJpEnYA7zKPOrw2qx8DvPB+ckOGYUXFEwUuKS2DGxjHhkHx0AWySOD/F2q7IMrO03zGfaCau/7b0p7fOcX5F4sYUkkzJpdw/NBQL4UuIT450m6mmlXgXFund7ggxqYm12fXrXnfZ2NT7FbbLxE+e6KCfKhoeHt5apMAlyWgihgGOM6rU2SgBI7JtD3ArnhQ7jfc1k082MvV2bnKnBmgQ7Ja8pYseQFvNUMDs1pZBO57pFhgoLki1Hs5rPMq9TVPWdhwZcLd4VQuQS6jzqw1keeY4RELhlfEVWQU+i2lX1XT6oTQNZSU5/Yw=="
const RSA_ALICE = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDExnwUVhsIh66w1OIGHFyr0prionxHoHEmkSdgDvMo86vDarHwO88H5yQ4ZhRcUTBS4pLYMbGMeGQfHQBbJI4P8Xarsgys7TfMZ9oJq7/tvSnt85xfkXixhSSTMml3D80FAvhS4hPjnSbqaaVeBcW6d3uCDGpibXZ9eted9nY1PsVtsvET57ooJ8qGh4e3lqkwCXJaCKGAY4zqtTZKAEjsm0PcCueFDuN9zWTTzYy9XZucqcGaBDslrylix5AW81QwOzWlkE7nukWGCguSLUezms8yr1NU9Z2HBlwt3hVC5BLqPOrDWR55jhEQuGV8RVZBT6LaVfVdPqhNA1lJTn9j"

@test
def "init refuses a second encoding of a key it already holds" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    $"($RSA_ALICE) alice@host\n" | save --force $"($tmp_dir)/alice.pub"
    init --repo $repo --pubkey $"($tmp_dir)/alice.pub"

    $"($RSA_PADDED_MODULUS) mallory@host\n" | save --force $"($tmp_dir)/mallory.pub"
    let outcome = try { init --repo $repo --pubkey $"($tmp_dir)/mallory.pub"; "ok" } catch {|e| $e.msg }
    assert ($outcome | str contains "not the encoding OpenSSH writes") $"the padded copy was registered: ($outcome)"
    # The same key, so OpenSSH reports the same fingerprint for both — that is
    # what makes this a fork rather than two keys.
    assert equal (fingerprint-of $"($tmp_dir)/alice.pub") (fingerprint-of $"($tmp_dir)/mallory.pub")
    assert equal (registered $repo) [$"(principal-of $"($tmp_dir)/alice.pub").pub"]
}

# The same padded-encoding refusal through the inline `key::` path. The catch
# there must not flatten the inner error into "is not an SSH public key": this
# key IS a real public key, and only the canonical error naming both encodings
# (given vs what OpenSSH writes) tells the operator what is wrong with it.
@test
def "an inline key:: padded encoding surfaces the canonical error naming both encodings" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    ^git -C $repo config user.signingKey $"key::($RSA_PADDED_MODULUS)"
    let outcome = try { init --repo $repo; "ok" } catch {|e| $e.msg }
    assert ($outcome | str contains "not the encoding OpenSSH writes") $"canonical's refusal was replaced: ($outcome)"
    assert ($outcome | str contains $RSA_PADDED_MODULUS) $"the given encoding is missing: ($outcome)"
    assert ($outcome | str contains $RSA_ALICE) $"the encoding OpenSSH writes is missing: ($outcome)"
    assert equal (registered $repo) []
}

# The toolchain refusal through the inline `key::` path: with ssh-keygen off
# PATH the catch there must not turn "this is a toolchain problem" into a
# verdict about the key. Same probe shape as tests/test_pubkey.nu "a missing
# ssh-keygen is reported as a toolchain problem, not a bad key"; git joins the
# PATH because init reads the key out of git config before any parsing happens.
@test
def "a missing ssh-keygen through key:: stays a toolchain problem, not a bad key" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    ^git -C $repo config user.signingKey $"key::(open --raw $"($key_path).pub" | str trim)"

    let bin = $"($tmp_dir)/bin"
    mkdir $bin
    for tool in ["nu" "git" "chmod"] {
        ^ln -s (which $tool | get 0.path) $"($bin)/($tool)"
    }
    let script = $"($tmp_dir)/probe.nu"
    [
        $"use ($MODULE_DIR)/init.nu"
        $"try { init --repo ($repo) } catch {|e| print $e.msg }"
    ] | str join "\n" | save --force $script

    let out = ^bash -c $"PATH=($bin) exec ($bin)/nu ($script)" | complete
    assert ($out.stdout | str contains "toolchain problem") $"expected a toolchain message, got: ($out.stdout)($out.stderr)"
    assert (not ($out.stdout | str contains "not an SSH public key")) $"a good key was blamed: ($out.stdout)"
}

# A key type that is a path — `key::ssh-../../../../pwned Zm9v` — is refused in
# `pubkey canonical`, which only accepts the types OpenSSH writes. The file name
# is a fingerprint, so no field of the key can steer a path either.
@test
def "init refuses an inline key whose type names a path" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    # One level up, into a directory that exists: the write lands unless the
    # type itself is refused.
    let escape = $"($repo)/multiproofs/pwned.pub"
    ^git -C $repo config user.signingKey "key::ssh-../pwned Zm9v"

    let outcome = (try { init --repo $repo; "ok" } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    assert (not ($escape | path exists)) "init wrote outside pubkeys/"
    assert equal (registered $repo) []
}

# The source file's stem is not read at all, and nothing gates it: every one of
# these names registers, under the key's fingerprint.
@test
def "a source file name the trust list could never express registers fine" [] {
    let tmp_dir = $in.tmp_dir
    let repo = make-repo $tmp_dir

    let key_path = $"($tmp_dir)/sshkey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    let expected = [$"(principal-of $"($key_path).pub").pub"]

    for stem in ["al ice" "*" "alice,mallory" 'ali"ce' "ali?e" "#alice" "ali\u{200b}ce"] {
        let source = $"($tmp_dir)/($stem).pub"
        cp $"($key_path).pub" $source

        init --repo $repo --pubkey $source
        assert equal (registered $repo) $expected $"source name ($stem | to nuon) reached pubkeys/"
        rm $source
    }
}
