use std/assert
use std/testing *

use ../nu-multiproof/ssh-sign.nu
# Tested here rather than in its own suite: `ssh-sign sign` is what the key
# lifetime exists for, and signing an inline `key::` key needs an agent.
use ../nu-multiproof/_key-helpers.nu with-signing-key
use ../nu-multiproof/_sig.nu sig-files-for
use _fixtures.nu [ setup cleanup principal-of ]

# Why a const: the namespace test asks what the *command line* accepts, which
# only a separate nu process can answer.
const MODULE_DIR = path self ../nu-multiproof

# The registered file is called `alice.pub` and the private key `somekey`, and
# neither name reaches the signature: the sig is named for the key's fingerprint.
@test
def "sign names the sig file after the key, not after either file holding it" [] {
    let tmp_dir = $in.tmp_dir
    let key_path = $"($tmp_dir)/somekey"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_path).pub" ($pubkeys_dir | path join "alice.pub")
    "hello world" | save --force $test_file

    ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir
    assert ($"($test_file).(principal-of $key_path).sig" | path exists)
    assert (not ($"($test_file).alice.sig" | path exists)) "the sig was named after a file name"
    assert (not ($"($test_file).sig" | path exists))
}

# A key nobody registered can still sign anything — that is what `ssh-keygen -Y
# sign` does — but a signature no trust list can name is one nothing reading the
# artifact can check. Refused at signing time, where the operator can still fix
# it, rather than at somebody else's verify.
@test
def "sign refuses a key the trust list does not hold" [] {
    let tmp_dir = $in.tmp_dir
    let key_path = $"($tmp_dir)/stranger"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    ^ssh-keygen -t ed25519 -f $"($tmp_dir)/other" -N "" -q
    mkdir $pubkeys_dir
    cp $"($tmp_dir)/other.pub" ($pubkeys_dir | path join "other.pub")
    "hello world" | save --force $test_file

    let outcome = try { ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir; "signed" } catch {|e| $e.msg }
    assert ($outcome | str contains "not registered") $"got: ($outcome)"
    assert equal (ls --all $tmp_dir | get name | path basename | where ($it | str ends-with ".sig")) []
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

# `--name` let the signer pick their own principal: it became the `.sig` file
# name and, through the pubkey stem it was matched against, a trust-list entry.
# A principal is key material now, so there is nothing left for a flag to say —
# and the flag going missing is what this pins. `--name alice` on mallory's key
# is the shape it enabled.
@test
def "the signer name cannot be set by a caller" [] {
    let out = ^nu -c $"use ($MODULE_DIR)/ssh-sign.nu; ssh-sign sign f --name alice" | complete
    assert equal $out.exit_code 1 $"ssh-sign sign still takes a name: ($out)"
    # Not `str contains "--name"`: nushell echoes the offending source line in
    # every parse error, and that line holds `--name`. The error *class* is what
    # says the flag is gone.
    assert ($out.stderr | str contains "unknown_flag") $"expected an unknown-flag error, got: ($out.stderr)"
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
    assert equal ($results | first | get signer) (principal-of $key_path)
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
    assert ($"($test_file).(principal-of $key_alice).sig" | path exists)
    assert ($"($test_file).(principal-of $key_bob).sig" | path exists)

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

    # The signer's own list, holding the signer's own key: signing requires the
    # key to be registered somewhere, and the point here is a *verifier* whose
    # list does not hold it.
    let signer_dir = $"($tmp_dir)/signer-trust"
    mkdir $signer_dir
    cp $"($sign_key).pub" ($signer_dir | path join "signer.pub")

    "hello world" | save --force $test_file
    ssh-sign sign $test_file --key $sign_key --pubkeys-dir $signer_dir

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

# A junk file planted at `doc.<alice-fp>.sig` — a name anyone can write — used
# to come back as `{signer: <alice-fp>, valid: false, error: invalid_signature}`,
# byte-identical to the row alice's registered key produces when the content no
# longer matches (the test above). The two states must be distinguishable, and a
# failed verification must never be attributed to a principal read off a file
# name: no key was established here, so the row names no signer at all — only
# the sig file to inspect.
@test
def "a planted non-signature named for a registered signer is not attributed to them" [] {
    let tmp_dir = $in.tmp_dir
    let key_path = $"($tmp_dir)/alice_key"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_path).pub" ($pubkeys_dir | path join "alice.pub")
    "hello world" | save --force $test_file

    let planted = $"($test_file).(principal-of $key_path).sig"
    "this is not a signature" | save --force $planted

    let results = ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir
    assert equal ($results | length) 1
    let row = $results | first
    assert equal $row.valid false
    assert equal $row.error "unreadable_signature" $"a planted junk file read as a real bad signature: ($row)"
    assert equal $row.signer null $"a filename label was reported as the signer: ($row)"
    assert equal $row.sig $planted
}

@test
def "verify infers the original from a named .sig path" [] {
    let tmp_dir = $in.tmp_dir
    let key_path = $"($tmp_dir)/test_key"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_path).pub" ($pubkeys_dir | path join "test.pub")

    "hello world" | save --force $test_file
    ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir

    # Naming the sig has to recover `test.txt` from `test.txt.<fingerprint>.sig`.
    # The grammar itself is _sig.nu's, and tests/test_sig.nu pins its shapes; what
    # this asks is that `verify` reads it through that one implementation.
    let sig_path = $"($test_file).(principal-of $key_path).sig"
    assert ($sig_path | path exists) $"sig not written at expected path: ($sig_path)"
    let results = ssh-sign verify $sig_path --pubkeys-dir $pubkeys_dir
    assert equal ($results | length) 1
    assert equal ($results | first | get valid) true
    assert equal ($results | first | get signer) (principal-of $key_path)
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
    let outcome = (
        try {
            ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir --fail | ignore
            "ok"
        } catch {|e| $"err:($e.msg)" }
    )
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"

    # Without --fail the same bad sig returns a record (no throw)
    let results = ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir
    assert equal ($results | first | get valid) false
}

# A typo'd sig path is the verifier's own mistake; a `{valid: false, error:
# invalid_signature}` row would read it as evidence against the artifact, the
# exact shape check-signer-known refuses for --signer. It must throw, naming
# the path the caller typed.
@test
def "verify throws on a named sig path that does not exist" [] {
    let tmp_dir = $in.tmp_dir
    let key_path = $"($tmp_dir)/alice_key"
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"

    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    mkdir $pubkeys_dir
    cp $"($key_path).pub" ($pubkeys_dir | path join "alice.pub")
    "hello world" | save --force $test_file
    ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir

    let missing = $"($test_file).nope.sig"
    let outcome = try { ssh-sign verify $missing --pubkeys-dir $pubkeys_dir; "ok" } catch {|e| $e.msg }
    assert ($outcome | str contains "not found") $"expected an error, got: ($outcome)"
    assert ($outcome | str contains $missing) $"the error does not name the typo'd path: ($outcome)"
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

    ssh-sign sign $test_file --key $alice_key --pubkeys-dir $pubkeys_dir
    ssh-sign sign $test_file --key $bob_key --pubkeys-dir $pubkeys_dir

    let one = (ssh-sign verify $"($test_file).(principal-of $alice_key).sig" --pubkeys-dir $pubkeys_dir)
    assert equal ($one | get signer) [(principal-of $alice_key)]

    # The original still fans out to every sig — the two forms stay distinct.
    let all = (ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir)
    assert equal ($all | get signer | sort) ([(principal-of $alice_key) (principal-of $bob_key)] | sort)
}

# Every verdict says which signature file it is about, whatever its outcome.
# A caller acting per-signature cannot get that from `signer`: an unreadable
# row has none, and two rows may share a principal. Without it `merkle verify`
# re-ran discovery and verified one signature twice to recover the mapping.
# All four row shapes here, because the column has to be on the failures too —
# those are the rows a caller most needs to trace back to a file.
@test
def "every verdict row names the signature file it is about" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let alice_key = $"($tmp_dir)/alice"
    let mallory_key = $"($tmp_dir)/mallory"

    mkdir $pubkeys_dir
    "hello world" | save --force $test_file
    ^ssh-keygen -t ed25519 -f $alice_key -N "" -q
    ^ssh-keygen -t ed25519 -f $mallory_key -N "" -q
    cp $"($alice_key).pub" ($pubkeys_dir | path join "alice.pub")

    # valid
    let good = ssh-sign sign $test_file --key $alice_key --pubkeys-dir $pubkeys_dir
    # unrecognized_signer: real signature, key never registered
    let unknown = $"($test_file).mallory.sig"
    open --raw $test_file | into binary | ^ssh-keygen -Y sign -q -f $mallory_key -n file | save --raw --force $unknown
    # unreadable_signature: junk planted at a signature name
    let junk = $"($test_file).junk.sig"
    "not a signature" | save --raw --force $junk

    let rows = ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir
    assert equal ($rows | get sig | sort) ([$good $unknown $junk] | sort)
    assert equal ($rows | where sig == $good | get valid) [true]
    assert equal ($rows | where sig == $unknown | get error) ["unrecognized_signer"]
    assert equal ($rows | where sig == $junk | get error) ["unreadable_signature"]

    # invalid_signature: registered key, content changed under it
    "tampered" | save --force $test_file
    let after = ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir
    assert equal ($after | where sig == $good | get error) ["invalid_signature"]
}

# A hand-written trust list, not one `init` produced: keys stored with two
# spaces between type and material. Registration is decided on key material, and
# an earlier comparison split on a single space and took the first two fields, so
# both keys reduced to `ssh-ed25519 ` — equal to each other, and signing refused
# with "multiple pubkeys match". Both keys must still be recognized as
# registered, each under its own fingerprint.
@test
def "registration compares key material, not the spacing around it" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/test.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let alice_key = $"($tmp_dir)/alice_key"
    let bob_key = $"($tmp_dir)/bob_key"

    mkdir $pubkeys_dir
    "hello world" | save --force $test_file
    ^ssh-keygen -t ed25519 -f $alice_key -N "" -q
    ^ssh-keygen -t ed25519 -f $bob_key -N "" -q
    for pair in [[src stem]; [$alice_key "alice"] [$bob_key "bob"]] {
        open --raw $"($pair.src).pub"
        | str replace " " "  "
        | save --force ($pubkeys_dir | path join $"($pair.stem).pub")
    }

    ssh-sign sign $test_file --key $alice_key --pubkeys-dir $pubkeys_dir
    ssh-sign sign $test_file --key $bob_key --pubkeys-dir $pubkeys_dir
    assert equal (
        sig-files-for $test_file | each {|f| $f | path basename } | sort
    ) ([$"test.txt.(principal-of $alice_key).sig" $"test.txt.(principal-of $bob_key).sig"] | sort)
}

# A bare `<file>.sig` — what plain `ssh-keygen -Y sign` writes, and what an
# older seal left behind. Read as the named form — strip `.txt.sig`, look for
# `doc` — it gives "cannot find original file", or a silent verify of a sibling
# actually named `doc`.
@test
def "verify resolves the bare sig form of a file with an extension" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/doc.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let key_path = $"($tmp_dir)/alice_key"

    mkdir $pubkeys_dir
    "hello world" | save --force $test_file
    # A decoy at the name the named-form reading would pick.
    "not this one" | save --force $"($tmp_dir)/doc"
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    cp $"($key_path).pub" ($pubkeys_dir | path join "alice.pub")
    ^ssh-keygen -Y sign -f $key_path -n file $test_file

    let result = (ssh-sign verify $"($test_file).sig" --pubkeys-dir $pubkeys_dir)
    assert equal ($result | get signer) [(principal-of $key_path)]
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
    assert equal ($result | get signer) [(principal-of $key_path)]
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

    assert ($"($test_file).(principal-of $key_path).sig" | path exists)
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
    assert equal ($result | get signer | sort) (
        $signers | each {|s| principal-of $"($tmp_dir)/($s)_key" } | sort
    )
    assert equal ($result | get valid) [true true true true]
}

# A cancelled signing ceremony must not cost the signature already on disk.
# Saving the new sig straight to `<file>.<signer>.sig` and deleting it when the
# check failed did exactly that — and `seal` re-signs an unchanged
# tree-root.txt whose sig it deliberately kept, so one cancelled Touch ID
# prompt was enough. A stubbed ssh-keygen stands in for the fail-open: it
# reports success for `-Y sign` and emits bytes that are not a signature.
#
# Why the stub delegates everything else to the real binary: signing now derives
# the signer from key material, which is OpenSSH's answer to give — so a stub
# that refused every other subcommand would fail before reaching the ceremony,
# and the test would pass for the wrong reason.
@test
def "a failed signing ceremony leaves the previous signature alone" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/doc.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let key_path = $"($tmp_dir)/alice_key"
    let stub_dir = $"($tmp_dir)/stub"
    let real_keygen = which ssh-keygen | get 0.path

    mkdir $stub_dir $pubkeys_dir
    "hello world" | save --force $test_file
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    cp $"($key_path).pub" ($pubkeys_dir | path join "alice.pub")
    let sig_path = $"($test_file).(principal-of $key_path).sig"
    "THE SIGNATURE FROM AN EARLIER GOOD RUN" | save --force $sig_path
    [
        "#!/bin/sh"
        # `-Y sign` succeeds and writes junk; check-novalidate then refuses it.
        'for a in "$@"; do case "$a" in sign) m=sign ;; check-novalidate) m=check ;; esac; done'
        'if [ "$m" = sign ]; then echo NOT-A-SIGNATURE; exit 0; fi'
        'if [ "$m" = check ]; then exit 1; fi'
        $"exec ($real_keygen) \"$@\""
    ] | str join "\n" | save --force $"($stub_dir)/ssh-keygen"
    ^chmod +x $"($stub_dir)/ssh-keygen"
    $env.PATH = ([$stub_dir] ++ $env.PATH)

    assert error {|| ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir }
    assert equal (open --raw $sig_path) "THE SIGNATURE FROM AN EARLIER GOOD RUN"
}

# The pubkey file's own name is not read, so the hostile names below are all
# *file* names, and every one of them signs and verifies.
@test
def "a pubkey file name the trust list could never express still signs and verifies" [] {
    let tmp_dir = $in.tmp_dir
    let test_file = $"($tmp_dir)/doc.txt"
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let key_path = $"($tmp_dir)/alice_key"

    mkdir $pubkeys_dir
    "hello world" | save --force $test_file
    ^ssh-keygen -t ed25519 -f $key_path -N "" -q
    let principal = principal-of $key_path

    for stem in ["al ice" "*" "ali,ce" 'ali"ce' "ali\u{200b}ce"] {
        let registered = $pubkeys_dir | path join $"($stem).pub"
        cp $"($key_path).pub" $registered

        ssh-sign sign $test_file --key $key_path --pubkeys-dir $pubkeys_dir
        let result = ssh-sign verify $test_file --pubkeys-dir $pubkeys_dir
        assert equal ($result | get signer) [$principal] $"pubkey named ($stem | to nuon) changed the signer"
        assert equal ($result | get valid) [true]

        rm $registered $"($test_file).($principal).sig"
    }
}
