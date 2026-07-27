use std/assert
use std/testing *

use ../nu-multiproof/ssh-sign.nu
# Tested here rather than in its own suite: `ssh-sign sign` is what the key
# lifetime exists for, and signing an inline `key::` key needs an agent.
use ../nu-multiproof/_key-helpers.nu with-signing-key

# Why a const: the namespace test asks what the *command line* accepts, which
# only a separate nu process can answer.
const MODULE_DIR = path self ../nu-multiproof

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

@test
def "sign creates named sig file" [] {
    let tmp_dir = $in.tmp_dir
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
}

# The namespace is written into every allowed_signers line, right beside the
# principal the name grammar guards, and it was interpolated raw. A caller-set
# `file",cert-authority,namespaces="file` rendered every registered key as a
# certificate authority, and a value holding a newline added a trust-list entry
# for a key that is not in pubkeys/ at all — `verify` then answered
# `valid: true` for it. There is no caller-controlled namespace any more, and
# the flag going missing is the thing this pins: nothing to validate, nothing
# to inject through.
@test
def "the signing namespace cannot be set by a caller" [] {
    for cmd in ["sign" "verify"] {
        let out = ^nu -c $"use ($MODULE_DIR)/ssh-sign.nu; ssh-sign ($cmd) f --namespace x" | complete
        assert equal $out.exit_code 1 $"ssh-sign ($cmd) still takes a namespace: ($out)"
        # Not `str contains "--namespace"`: nushell echoes the offending source
        # line in every parse error, and that line holds `--namespace` — so a
        # broken MODULE_DIR or an ssh-sign.nu that stops parsing would satisfy
        # it too. The error *class* is what says the flag is gone.
        assert ($out.stderr | str contains "unknown_flag") $"expected an unknown-flag error for ($cmd), got: ($out.stderr)"
    }
}

# The inline `key::` form has no file on disk, so resolution writes one. Its
# lifetime ends with the signing call — otherwise every call leaks a key file.
@test
def "with-signing-key removes the materialized inline key" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    let key_path = $"($tmp_dir)/inline_key"
    mkdir $repo
    ^git -C $repo init -q
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    ^git -C $repo config user.signingKey $"key::(open --raw $"($key_path).pub" | str trim)"

    let used = with-signing-key --root $repo {|key|
        assert ($key | path exists) $"key not materialized: ($key)"
        $key
    }
    assert (not ($used | path exists)) $"temp key survived the call: ($used)"

    # A throwing action must not skip the cleanup either. The path is recorded
    # to a file because a closure cannot write to a `mut` of the outer scope.
    let marker = $"($tmp_dir)/used_key"
    try {
        with-signing-key --root $repo {|key|
            $key | save --force $marker
            error make {msg: "signing ceremony failed"}
        }
    } catch {|e| assert equal $e.msg "signing ceremony failed" }
    let leaked = open --raw $marker | str trim
    assert (not ($leaked | path exists)) $"temp key survived a failed call: ($leaked)"
}

# An explicit --key is the caller's file: passed through untouched, and still
# there afterwards.
@test
def "with-signing-key leaves an explicit key alone" [] {
    let tmp_dir = $in.tmp_dir
    let key_path = $"($tmp_dir)/mykey"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q

    let used = with-signing-key --key $key_path {|key| $key }
    assert equal $used $key_path
    assert ($key_path | path exists)
}

@test
def "sign with custom name" [] {
    let tmp_dir = $in.tmp_dir
    let key_path = $"($tmp_dir)/mykey"
    let test_file = $"($tmp_dir)/test.txt"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    "hello world" | save --force $test_file

    ssh-sign sign $test_file --key $key_path --name bob
    assert ($"($test_file).bob.sig" | path exists)
}

@test
def "sign and verify round-trip" [] {
    let tmp_dir = $in.tmp_dir
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
}

@test
def "multiple signers" [] {
    let tmp_dir = $in.tmp_dir
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
}

@test
def "verify fails with wrong key" [] {
    let tmp_dir = $in.tmp_dir
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
}

@test
def "verify fails with tampered content" [] {
    let tmp_dir = $in.tmp_dir
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
}

@test
def "verify infers original from .sig path with hyphenated signer" [] {
    let tmp_dir = $in.tmp_dir
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
}

@test
def "verify --fail errors on invalid signature" [] {
    let tmp_dir = $in.tmp_dir
    let key_path = $"($tmp_dir)/test_key"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_path).pub" ($pubkeys_dir | path join "test.pub")

    "original content" | save --force $test_file
    ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir
    "tampered content" | save --force $test_file

    # Why --fail: a silent {valid: false} pass lets a CI step succeed on a bad
    # sig. --fail must turn that into a non-zero exit (a thrown error here).
    let outcome = (try {
        ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir --fail | ignore
        "ok"
    } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"

    # Without --fail the same bad sig returns a record (no throw)
    let results = ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir
    assert equal ($results | first | get valid) false
}

@test
def "verify with explicit --sig" [] {
    let tmp_dir = $in.tmp_dir
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
}

# `verify foo.txt.alice.sig` names one signature, so it must report on alice's
# sig alone. Discovery from the inferred original would also pull in bob's —
# answering a question the caller never asked.
@test
def "verify with a positional sig file checks only that signature" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let alice_key = $"($tmp_dir)/alice_key"
    let bob_key = $"($tmp_dir)/bob_key"

    mkdir $pubkeys_dir
    "hello world" | save --force $test_file
    ^ssh-keygen -t ed25519 -f $alice_key -N "" -q
    ^ssh-keygen -t ed25519 -f $bob_key -N "" -q
    cp $"($alice_key).pub" ($pubkeys_dir | path join "alice.pub")
    cp $"($bob_key).pub" ($pubkeys_dir | path join "bob.pub")

    ssh-sign sign $test_file --key $alice_key --name alice --pubkeys-dir $pubkeys_dir
    ssh-sign sign $test_file --key $bob_key --name bob --pubkeys-dir $pubkeys_dir

    let one = (ssh-sign verify $"($test_file).alice.sig" --pubkeys-dir $pubkeys_dir)
    assert equal ($one | get signer) ["alice"]

    # The original still fans out to every sig — the two forms stay distinct.
    let all = (ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir)
    assert equal ($all | get signer | sort) ["alice" "bob"]
}

# A hand-written trust list, not one `init` produced: keys stored with two
# spaces between type and material. The old key comparison split on a single
# space and took the first two fields, so both keys reduced to `ssh-ed25519 `
# — equal to each other, and the lookup refused with "multiple pubkeys match".
@test
def "the signer lookup compares key material, not the spacing around it" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let alice_key = $"($tmp_dir)/alice_key"
    let bob_key = $"($tmp_dir)/bob_key"

    mkdir $pubkeys_dir
    "hello world" | save --force $test_file
    ^ssh-keygen -t ed25519 -f $alice_key -N "" -q
    ^ssh-keygen -t ed25519 -f $bob_key -N "" -q
    for pair in [[src, stem]; [$alice_key, "alice"], [$bob_key, "bob"]] {
        open --raw $"($pair.src).pub"
        | str replace " " "  "
        | save --force ($pubkeys_dir | path join $"($pair.stem).pub")
    }

    ssh-sign sign $test_file --key $alice_key --pubkeys-dir $pubkeys_dir
    assert ($"($test_file).alice.sig" | path exists)
    assert (not ($"($test_file).bob.sig" | path exists))
}

# A bare `<file>.sig` — what plain `ssh-keygen -Y sign` writes, and what an
# older seal left behind. Verifying it by name used to strip `.txt.sig` and
# look for `doc`: "cannot find original file", or a silent verify of a sibling
# actually named `doc`.
@test
def "verify resolves the bare sig form of a file with an extension" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/doc.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let key_path = $"($tmp_dir)/alice_key"

    mkdir $pubkeys_dir
    "hello world" | save --force $test_file
    # A decoy with the name the old grammar resolved to.
    "not this one" | save --force $"($tmp_dir)/doc"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    cp $"($key_path).pub" ($pubkeys_dir | path join "alice.pub")
    ^ssh-keygen -Y sign -f $key_path -n file $test_file

    let result = (ssh-sign verify $"($test_file).sig" --pubkeys-dir $pubkeys_dir)
    assert equal ($result | get signer) ["alice"]
    assert equal ($result | get valid) [true]
}

# A file name is data. ssh-keygen has no `--`, so `-weird.txt` was read as an
# option: it signed standard input instead and wrote no .sig at all.
@test
def "a file whose name starts with a dash can be signed and verified" [] {
    let tmp_dir = $in.tmp_dir
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let key_path = $"($tmp_dir)/alice_key"

    mkdir $pubkeys_dir
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    cp $"($key_path).pub" ($pubkeys_dir | path join "alice.pub")

    # Relative, from inside the directory: an absolute path never starts with
    # `-`, so passing one would not exercise this at all.
    cd $tmp_dir
    "hello world" | save --force "-weird.txt"

    # Empty stdin so a regression fails instead of hanging: read as an option,
    # ssh-keygen waits for standard input forever.
    "" | ssh-sign sign "-weird.txt" --key $key_path --pubkeys-dir $pubkeys_dir
    let result = (ssh-sign verify "-weird.txt" --pubkeys-dir $pubkeys_dir)
    assert equal ($result | get signer) ["alice"]
    assert equal ($result | get valid) [true]
}

# `ssh-keygen -Y sign <file>` writes to the fixed name `<file>.sig`, which every
# process signing that file shares: two concurrent signs raced there and the
# surviving `<file>.<signer>.sig` held the *other* signer's signature, while
# `signer-from-sig` reads the filename as truth. Pinned without a race: a bare
# `<file>.sig` left beside the target must come out untouched.
@test
def "signing never writes through the shared <file>.sig name" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/doc.txt"
    let bare_sig = $"($test_file).sig"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let key_path = $"($tmp_dir)/alice_key"

    mkdir $pubkeys_dir
    "hello world" | save --force $test_file
    "not a signature, and not ours to touch" | save --force $bare_sig
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    cp $"($key_path).pub" ($pubkeys_dir | path join "alice.pub")

    ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir

    assert ($"($test_file).alice.sig" | path exists)
    assert equal (open --raw $bare_sig) "not a signature, and not ours to touch"
}

# The same property under actual concurrency: each signature must end up under
# its own signer's name. With the shared intermediate this either lost a
# signature ("Not found" from the mv) or filed one under the other's name.
@test
def "concurrent signs of one file keep their own signatures" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/doc.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    mkdir $pubkeys_dir
    "hello world" | save --force $test_file
    let signers = ["alice" "bob" "carol" "dave"]
    for s in $signers {
        ^ssh-keygen -t ed25519 -f $"($tmp_dir)/($s)_key" -N "" -q
        cp $"($tmp_dir)/($s)_key.pub" ($pubkeys_dir | path join $"($s).pub")
    }

    $signers | par-each {|s|
        ssh-sign sign $test_file --key $"($tmp_dir)/($s)_key" --pubkeys-dir $pubkeys_dir
    }

    # find-principals names the signer from the key inside the sig; the file
    # name claims one too. They must agree for every signature.
    let result = (ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir)
    assert equal ($result | get signer | sort) $signers
    assert equal ($result | get valid) [true true true true]
}

# A cancelled signing ceremony must not cost the signature already on disk.
# Saving the new sig straight to `<file>.<signer>.sig` and deleting it when the
# check failed did exactly that — and `seal` re-signs an unchanged
# tree-root.txt whose sig it deliberately kept, so one cancelled Touch ID
# prompt was enough. A stubbed ssh-keygen stands in for the fail-open: it
# reports success for `-Y sign` and emits bytes that are not a signature.
@test
def "a failed signing ceremony leaves the previous signature alone" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/doc.txt"
    let sig_path = $"($test_file).alice.sig"
    let stub_dir = $"($tmp_dir)/stub"

    mkdir $stub_dir
    "hello world" | save --force $test_file
    "THE SIGNATURE FROM AN EARLIER GOOD RUN" | save --force $sig_path
    [
        "#!/bin/sh"
        # `-Y sign` succeeds and writes junk; check-novalidate then refuses it.
        'for a in "$@"; do case "$a" in sign) m=sign ;; check-novalidate) m=check ;; esac; done'
        'if [ "$m" = sign ]; then echo NOT-A-SIGNATURE; exit 0; fi'
        'exit 1'
    ] | str join "\n" | save --force $"($stub_dir)/ssh-keygen"
    ^chmod +x $"($stub_dir)/ssh-keygen"
    $env.PATH = ([$stub_dir] ++ $env.PATH)

    assert error {|| ssh-sign sign $test_file --key $"($tmp_dir)/nokey" --name alice }
    assert equal (open --raw $sig_path) "THE SIGNATURE FROM AN EARLIER GOOD RUN"
}

# The two ends of one grammar. A signer name becomes a principal in the trust
# list, so a name the renderer refuses signs a file that can then never be
# verified — `al ice.pub` signed fine and made every later verify in that repo
# throw. And `--name` is interpolated into the sig's file name, so a slash put
# the signature in another directory, out of discovery's reach.
@test
def "sign refuses a signer name the trust list cannot express" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/doc.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let key_path = $"($tmp_dir)/alice_key"

    mkdir $pubkeys_dir
    "hello world" | save --force $test_file
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q

    for bad in ["al ice" "a/../b" "*" "ali,ce" 'ali"ce'] {
        let outcome = (try {
            ssh-sign sign $test_file --key $key_path --name $bad --pubkeys-dir $pubkeys_dir
            "signed"
        } catch {|e| $e.msg })
        assert ($outcome | str contains "signer name") $"name ($bad) got: ($outcome)"
    }
    # nothing was written under any of them
    assert equal (ls --all $tmp_dir | get name | each { path basename } | sort) ["alice_key" "alice_key.pub" "doc.txt" "pubkeys"]

    # the lookup path is the same grammar: a pubkey stem the renderer refuses
    # must fail at signing time, not at the next verify
    cp $"($key_path).pub" ($pubkeys_dir | path join "al ice.pub")
    let outcome = (try { ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir; "signed" } catch {|e| $e.msg })
    assert ($outcome | str contains "signer name") $"got: ($outcome)"
}
