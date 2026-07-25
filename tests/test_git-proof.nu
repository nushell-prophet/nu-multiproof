use std/assert
use std/testing *

use ../nu-multiproof/git-proof.nu
use ../nu-multiproof/_fs.nu list-files

# A real key that signed nothing here — for tests that need a well-formed key
# which is not the signer's.
const OTHER_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOi7LinplEQewM3/l8Ol9rE85+YwhvLPKf+ZUUf36Xuf"

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
def "extract single file" [] {
    let proof_dir = $in.tmp_dir

    let result = (git-proof extract nu-multiproof/mod.nu --out-dir $proof_dir)

    assert equal $result.version 1
    assert equal $result.object_format "sha256"
    assert equal ($result.files | length) 1
    assert equal ($result.files | first | get path) "nu-multiproof/mod.nu"
    assert (($proof_dir | path join "manifest.json") | path exists)
    assert (($proof_dir | path join "objects") | path exists)
    assert (($proof_dir | path join "pubkeys") | path exists)
}

@test
def "extract multiple files with deduplication" [] {
    let proof_dir = $in.tmp_dir

    let result = (git-proof extract nu-multiproof/mod.nu toolkit.nu --out-dir $proof_dir)

    assert equal ($result.files | length) 2
    # commit + root tree + nu-multiproof subtree + 2 blobs = 5 unique objects
    assert equal ($result.objects | length) 5
}

@test
def "verify valid proof" [] {
    let proof_dir = $in.tmp_dir

    # Why signed commit: top-level `valid` requires both structure AND signature.
    # HEAD may not be signed, so pick any commit with a signature attached.
    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract nu-multiproof/mod.nu --commit $signed --out-dir $proof_dir
    let result = (git-proof verify $proof_dir)

    assert equal $result.valid true
    assert equal $result.structure_valid true
    assert equal ($result.files | length) 1
    assert equal ($result.files | first | get path) "nu-multiproof/mod.nu"
}

@test
def "verify checks signature" [] {
    let proof_dir = $in.tmp_dir

    # Use any signed commit — HEAD may not be signed.
    # Not status == "G" because: %G? reflects *local* trust (allowedSignersFile),
    # not whether the commit carries a signature. The proof bundles its own pubkeys
    # and points git at them at verify time, so any non-"N" status is a valid fixture.
    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir
    let result = (git-proof verify $proof_dir)

    assert equal $result.valid true
    assert equal $result.signature.valid true
}

@test
def "verify fails when signer key not in bundle" [] {
    let proof_dir = $in.tmp_dir

    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    let signer_fp = (^git log -1 --format='%GK' $signed | str trim)

    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    # Remove the pubkey that matches the signer; remaining keys are non-matching.
    # This models a bundle whose pubkeys/ never contained the signer's key.
    glob ($proof_dir | path join "pubkeys/*.pub") | each {|f|
        let fp = (^ssh-keygen -lf $f | split row " " | get 1)
        if $fp == $signer_fp { rm $f }
    }

    let result = (git-proof verify $proof_dir)
    assert equal $result.signature.valid false
    # Why: callers checking only `.valid` must reject this bundle.
    assert equal $result.valid false
    assert equal $result.structure_valid true
}

@test
def "verify --fail errors on an invalid proof" [] {
    let proof_dir = $in.tmp_dir

    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    let signer_fp = (^git log -1 --format='%GK' $signed | str trim)

    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    # Remove the matching pubkey → signature can't verify → invalid proof.
    glob ($proof_dir | path join "pubkeys/*.pub") | each {|f|
        let fp = (^ssh-keygen -lf $f | split row " " | get 1)
        if $fp == $signer_fp { rm $f }
    }

    # Why --fail: without it verify returns {valid: false} with exit 0 and a
    # CI step silently passes. --fail must throw on the invalid bundle.
    let outcome = (try {
        git-proof verify $proof_dir --fail | ignore
        "ok"
    } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
}

@test
def "verify fails when bundled pubkey tampered" [] {
    let proof_dir = $in.tmp_dir

    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    let signer_fp = (^git log -1 --format='%GK' $signed | str trim)

    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    # Swap the matching pubkey for a different, perfectly well-formed key.
    # Why not a malformed line: that is refused while the trust list is being
    # rendered (see below), which proves nothing about the signature check.
    # This is the actual attack — a bundle carrying the wrong key.
    list-files ($proof_dir | path join "pubkeys") --suffix ".pub" | each {|f|
        let fp = (^ssh-keygen -lf $f | split row " " | get 1)
        if $fp == $signer_fp {
            $"($OTHER_KEY)\n" | save --force $f
        }
    }

    let result = (git-proof verify $proof_dir)
    assert equal $result.signature.valid false
    assert equal $result.valid false
    assert equal $result.structure_valid true
}

# A bundle is untrusted input, so its pubkeys/ can hold anything. ssh-keygen
# rejects a whole allowed_signers file over one bad entry, so rendering it
# anyway would turn "this key is junk" into "no principal matched" for every
# other signer in the bundle.
@test
def "verify refuses a bundle whose pubkey is not a public key" [] {
    let proof_dir = $in.tmp_dir

    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITAMPERED tampered\n" | save --force ($proof_dir | path join "pubkeys" "mallory.pub")

    assert error {|| git-proof verify $proof_dir }
}

# A bundle whose object bytes were swapped under the same oid name must fail
# the object-integrity step. Why: `git cat-file` does NOT re-hash loose objects,
# so a tampered object reads back with exit 0 — verify must re-hash to catch it.
# Without a real check, an attacker who controls the bundle can substitute
# arbitrary blob/tree content while the proof still verifies.
@test
def "verify rejects a bundle with tampered object content" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    let proof = $"($tmp_dir)/proof"
    mkdir $repo
    ^git -C $repo init --object-format=sha256 -q
    ^git -C $repo config user.email "test@example.com"
    ^git -C $repo config user.name "test"

    # Binary content, to prove the re-hash round-trips raw bytes exactly.
    0x[5245414c00010203ff20434f4e54454e540a] | save --raw --force $"($repo)/secret.bin"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo commit -m init o+e>| ignore

    # An unrelated blob whose compressed object file we can graft in.
    let evil_oid = ("EVIL FORGED CONTENT\n" | ^git -C $repo hash-object -w --stdin | str trim)

    git-proof extract secret.bin --repo $repo --out-dir $proof

    # Overwrite the bundle's blob object with the evil object's bytes, keeping
    # the authentic oid filename — the exact substitution attack.
    let blob_oid = (open ($proof | path join "manifest.json") | get files.0.hash)
    let dst = ($proof | path join "objects" ($blob_oid | str substring 0..<2) ($blob_oid | str substring 2..))
    let src = ($repo | path join ".git/objects" ($evil_oid | str substring 0..<2) ($evil_oid | str substring 2..))
    ^chmod u+w $dst
    cp $src $dst

    let result = (git-proof verify $proof)
    assert equal $result.structure_valid false
    assert equal $result.valid false
    assert ($result.error | str contains "object hash") $"expected object-hash failure, got ($result.error)"
}

# The same substitution, but the attacker also edits manifest.json — which ships
# inside the bundle they control. Emptying `objects` used to walk the integrity
# check past every object ("OK: all 0 objects verified"), after which the merkle
# walk read the tampered bytes through `git cat-file` (which does not re-hash)
# and the genuine commit signature carried the bundle to `valid: true`.
# The verified set must come from the filesystem, never from the manifest.
@test
def "verify rejects a tampered object dropped from the manifest object list" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    let proof = $"($tmp_dir)/proof"
    mkdir $repo
    ^git -C $repo init --object-format=sha256 -q
    ^git -C $repo config user.email "test@example.com"
    ^git -C $repo config user.name "test"

    "REAL CONTENT\n" | save --force $"($repo)/secret.txt"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo commit -m init o+e>| ignore

    let evil_oid = ("EVIL FORGED CONTENT\n" | ^git -C $repo hash-object -w --stdin | str trim)

    git-proof extract secret.txt --repo $repo --out-dir $proof

    let blob_oid = (open ($proof | path join "manifest.json") | get files.0.hash)
    let dst = ($proof | path join "objects" ($blob_oid | str substring 0..<2) ($blob_oid | str substring 2..))
    let src = ($repo | path join ".git/objects" ($evil_oid | str substring 0..<2) ($evil_oid | str substring 2..))
    ^chmod u+w $dst
    cp $src $dst

    # The manifest is the attacker's to edit — strip the list the check reads.
    let manifest_path = ($proof | path join "manifest.json")
    open $manifest_path | update objects [] | to json --indent 2 | save --force $manifest_path

    let result = (git-proof verify $proof)
    assert equal $result.valid false
    assert equal $result.structure_valid false
    assert ($result.error | str contains "object hash") $"expected object-hash failure, got ($result.error)"
}

# A bundle listing no files passes every check vacuously — objects re-hash, the
# commit->tree link holds, the commit signature is genuine — so it reported
# `valid: true` while proving nothing. `extract` refuses an empty file list; a
# bundle that the producer cannot emit must not verify.
@test
def "verify rejects a bundle that proves no files" [] {
    let proof_dir = $in.tmp_dir

    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    let manifest_path = ($proof_dir | path join "manifest.json")
    open $manifest_path | update files [] | to json --indent 2 | save --force $manifest_path

    let outcome = (try {
        git-proof verify $proof_dir | ignore
        "ok"
    } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    assert ($outcome | str contains "proves nothing") $"expected empty-file-list rejection, got ($outcome)"
}

# The bundle declares its format; the verifier must read it. A v2 bundle read as
# v1 would fail later as "content does not hash to its name", blaming the objects
# for what is a format mismatch. Same category as a missing manifest.json — an
# error, not a proof that failed.
@test
def "verify rejects an unknown bundle version" [] {
    let proof_dir = $in.tmp_dir

    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    let manifest_path = ($proof_dir | path join "manifest.json")
    open $manifest_path | update version 2 | to json --indent 2 | save --force $manifest_path

    let outcome = (try {
        git-proof verify $proof_dir | ignore
        "ok"
    } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    assert ($outcome | str contains "unsupported proof bundle version") $"expected version rejection, got ($outcome)"
}

@test
def "verify rejects a missing bundle version" [] {
    let proof_dir = $in.tmp_dir

    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    let manifest_path = ($proof_dir | path join "manifest.json")
    open $manifest_path | reject version | to json --indent 2 | save --force $manifest_path

    let outcome = (try {
        git-proof verify $proof_dir | ignore
        "ok"
    } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str contains "unsupported proof bundle version: missing") $"expected missing-version rejection, got ($outcome)"
}

@test
def "verify rejects an unknown object format" [] {
    let proof_dir = $in.tmp_dir

    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    let manifest_path = ($proof_dir | path join "manifest.json")
    open $manifest_path | update object_format "sha1" | to json --indent 2 | save --force $manifest_path

    let outcome = (try {
        git-proof verify $proof_dir | ignore
        "ok"
    } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str contains "unsupported object format: sha1") $"expected object-format rejection, got ($outcome)"
}

# A path like `a/b` where `a` is a blob must fail-fast inside `extract`.
# Previously, the cursor only advanced on trees, so `b` was searched in the
# root tree — silently succeeding (when `b` was a sibling) or erroring with
# a misleading "not found in tree <root>" message (when it wasn't).
@test
def "extract errors when path descends into a blob with sibling at root" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    let proof_dir = $"($tmp_dir)/proof"
    mkdir $repo
    ^git -C $repo init --object-format=sha256 -q
    ^git -C $repo config user.email "test@example.com"
    ^git -C $repo config user.name "test"

    "blob a" | save --force $"($repo)/a"
    "blob b" | save --force $"($repo)/b"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo commit -m init o+e>| ignore

    let outcome = (try {
        git-proof extract "a/b" --repo $repo --out-dir $proof_dir
        "ok"
    } catch {|e| $"err:($e.msg)" })

    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    assert ($outcome | str contains "is a blob") $"expected blob-descend error, got ($outcome)"
    # Why: error must fire before any objects are extracted.
    assert (not ($proof_dir | path exists)) "proof dir created despite error"
}

@test
def "extract errors when path descends into a blob without sibling" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    let proof_dir = $"($tmp_dir)/proof"
    mkdir $repo
    ^git -C $repo init --object-format=sha256 -q
    ^git -C $repo config user.email "test@example.com"
    ^git -C $repo config user.name "test"

    "blob a" | save --force $"($repo)/a"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo commit -m init o+e>| ignore

    let outcome = (try {
        git-proof extract "a/b" --repo $repo --out-dir $proof_dir
        "ok"
    } catch {|e| $"err:($e.msg)" })

    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    assert ($outcome | str contains "is a blob") $"expected blob-descend error, got ($outcome)"
    assert (not ($proof_dir | path exists)) "proof dir created despite error"
}

@test
def "extract refuses a sha1 repo" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    let proof_dir = $"($tmp_dir)/proof"
    mkdir $repo
    ^git -C $repo init --object-format=sha1 -q
    ^git -C $repo config user.email "test@example.com"
    ^git -C $repo config user.name "test"

    "blob a" | save --force $"($repo)/a"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo commit -m init o+e>| ignore

    let outcome = (try {
        git-proof extract "a" --repo $repo --out-dir $proof_dir
        "ok"
    } catch {|e| $"err:($e.msg)" })

    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
    # Why the name: git leaves extensions.objectFormat unset on a sha1 repo, so
    # the message used to report an empty format for every standard repo.
    assert ($outcome | str contains "'sha1'") $"expected sha1 named in the error, got ($outcome)"
    assert (not ($proof_dir | path exists)) "proof dir created despite error"
}

# With git's default core.quotePath=true, plain `ls-tree` renders a non-ASCII
# name as "\321\204\320\260\320\271\320\273.md". The lookup by raw name then
# never matched and `extract` reported the file as missing from its own tree.
# The directory segment is non-ASCII too, so the tree descent is covered as well.
@test
def "extract and verify a file with a non-ascii name" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    let proof = $"($tmp_dir)/proof"
    mkdir $"($repo)/каталог"
    ^git -C $repo init --object-format=sha256 -q
    ^git -C $repo config user.email "test@example.com"
    ^git -C $repo config user.name "test"

    "привет\n" | save --force $"($repo)/каталог/файл.md"
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo commit -m init o+e>| ignore

    let result = (git-proof extract "каталог/файл.md" --repo $repo --out-dir $proof)
    assert equal ($result.files | first | get path) "каталог/файл.md"

    # Why structure_valid, not valid: the fixture commit is unsigned, so the
    # signature leg fails by construction. The merkle walk is what's under test.
    let verified = (git-proof verify $proof)
    assert equal $verified.structure_valid true
}

# core.quotePath also C-quotes a name containing `"` — same missed lookup.
@test
def "extract and verify a file with a quote in its name" [] {
    let tmp_dir = $in.tmp_dir
    let repo = $"($tmp_dir)/repo"
    let proof = $"($tmp_dir)/proof"
    mkdir $repo
    ^git -C $repo init --object-format=sha256 -q
    ^git -C $repo config user.email "test@example.com"
    ^git -C $repo config user.name "test"

    "quoted\n" | save --force ($repo | path join 'say "hi".txt')
    ^git -C $repo add . o+e>| ignore
    ^git -C $repo commit -m init o+e>| ignore

    let result = (git-proof extract 'say "hi".txt' --repo $repo --out-dir $proof)
    assert equal ($result.files | first | get path) 'say "hi".txt'

    let verified = (git-proof verify $proof)
    assert equal $verified.structure_valid true
}

@test
def "render-allowed-signers writes one wildcard line per pubkey" [] {
    let tmp_dir = $in.tmp_dir
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let out = $"($tmp_dir)/allowed_signers"
    mkdir $pubkeys_dir

    ^ssh-keygen -t ed25519 -f $"($tmp_dir)/k1" -N "" -q -C "alice"
    ^ssh-keygen -t ed25519 -f $"($tmp_dir)/k2" -N "" -q -C "bob"
    cp $"($tmp_dir)/k1.pub" ($pubkeys_dir | path join "alice.pub")
    cp $"($tmp_dir)/k2.pub" ($pubkeys_dir | path join "bob.pub")

    git-proof render-allowed-signers $out --pubkeys-dir $pubkeys_dir

    let lines = open --raw $out | lines
    assert equal ($lines | length) 2
    # Why wildcard principal: collective trust statement — keys are in the
    # project's signer list without attaching personal identity.
    for line in $lines {
        assert ($line | str starts-with "* namespaces=\"git\" ") $"unexpected line: ($line)"
    }
}

@test
def "render-allowed-signers errors on empty pubkeys dir" [] {
    let tmp_dir = $in.tmp_dir
    let pubkeys_dir = $"($tmp_dir)/pubkeys"
    let out = $"($tmp_dir)/allowed_signers"
    mkdir $pubkeys_dir

    let outcome = (try {
        git-proof render-allowed-signers $out --pubkeys-dir $pubkeys_dir
        "ok"
    } catch {|e| $"err:($e.msg)" })
    assert ($outcome | str starts-with "err:") $"expected error, got ($outcome)"
}

@test
def "blob hash matches git" [] {
    let proof_dir = $in.tmp_dir

    let git_hash = (
        ^git ls-tree HEAD toolkit.nu
        | lines
        | parse "{mode} {type} {hash}\t{name}"
        | first
        | get hash
    )

    let result = (git-proof extract toolkit.nu --out-dir $proof_dir)
    let proof_hash = ($result.files | first | get hash)

    assert equal $proof_hash $git_hash
}

# A bundle is untrusted input, and every oid in it reaches git as a command
# line argument. `git verify-commit --help` exits 0 and prints a man page, so a
# manifest naming `--help` as its commit would have read as a good signature.
@test
def "verify refuses a manifest whose commit is not an object id" [] {
    let proof_dir = $in.tmp_dir
    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    let manifest_path = ($proof_dir | path join "manifest.json")
    for bad in ["--help" "HEAD" "" "../../etc/passwd"] {
        open $manifest_path | merge {commit: $bad} | to json | save --force $manifest_path
        let outcome = (try { git-proof verify $proof_dir; "ok" } catch {|e| $e.msg })
        assert ($outcome | str contains "not a SHA-256 object id") $"commit ($bad) got: ($outcome)"
    }
}

@test
def "verify refuses a manifest file hash that is not an object id" [] {
    let proof_dir = $in.tmp_dir
    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    let manifest_path = ($proof_dir | path join "manifest.json")
    let manifest = open $manifest_path
    $manifest | merge {files: [{path: "LICENSE" hash: "--help"}]} | to json | save --force $manifest_path
    assert error {|| git-proof verify $proof_dir }

    # The tree link is read straight out of the manifest too.
    $manifest | merge {tree: "-x"} | to json | save --force $manifest_path
    assert error {|| git-proof verify $proof_dir }
}

# The oid re-hashing loop builds its argument from a *file name* in the bundle,
# so a directory named `--` is an option, not an object.
@test
def "an object file that names an option is an invalid object" [] {
    let proof_dir = $in.tmp_dir
    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    mkdir ($proof_dir | path join "objects" "--")
    "x" | save --force ($proof_dir | path join "objects" "--" "help")

    let result = (git-proof verify $proof_dir)
    assert equal $result.valid false
    assert equal $result.structure_valid false
    assert equal $result.error "object hash verification failed"
}

# `--commit` is whatever the caller typed. `git rev-parse --help` exits 0.
@test
def "extract refuses a commit that is an option" [] {
    let proof_dir = $in.tmp_dir
    assert error {|| git-proof extract LICENSE --commit "--help" --out-dir $proof_dir }
    assert (not (($proof_dir | path join "manifest.json") | path exists))
}

# The shape of the manifest is untrusted too, not just its values. `files`
# holding bare strings reached `get --optional hash` and failed there as
# "only supports list, table, record" — a nushell error about the verifier
# where the operator needed one naming the bundle.
@test
def "verify refuses a manifest whose files are not records" [] {
    let proof_dir = $in.tmp_dir
    let signed = (^git log --format='%H %G?' | lines | parse "{hash} {status}" | where status != "N" | first | get hash)
    git-proof extract LICENSE --commit $signed --out-dir $proof_dir

    let manifest_path = ($proof_dir | path join "manifest.json")
    let manifest = open $manifest_path

    $manifest | merge {files: ["--help"]} | to json | save --force $manifest_path
    let outcome = (try { git-proof verify $proof_dir; "ok" } catch {|e| $e.msg })
    assert ($outcome | str contains "files entry is not a record") $"got: ($outcome)"

    $manifest | merge {files: "LICENSE"} | to json | save --force $manifest_path
    let outcome = (try { git-proof verify $proof_dir; "ok" } catch {|e| $e.msg })
    assert ($outcome | str contains "files is not a list") $"got: ($outcome)"
}
