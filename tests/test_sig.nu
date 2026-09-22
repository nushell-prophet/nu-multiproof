use std/assert
use std/testing *

use ../nu-multiproof/_sig.nu [ sig-files-for signer-from-sig sig-path-for original-for-sig ]

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

# Discovery must return both grammar forms — a caller that clears only the
# named one leaves a stale bare `.sig` behind.
@test
def "discovery finds the named and the bare form" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "content" | save --force $file
    "sig" | save --force $"($file).sig"
    "sig" | save --force $"($file).alice.sig"
    "sig" | save --force $"($file).bob.sig"

    let found = sig-files-for $file | each {|f| $f | path basename } | sort
    assert equal $found ["doc.txt.alice.sig" "doc.txt.bob.sig" "doc.txt.sig"]
}

# The regression this module's discovery was rewritten for: the path is data,
# so `[`, `*` and `?` in a filename must not be read as pattern syntax.
@test
def "discovery survives glob metacharacters in the filename" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/w[1]?x*y.txt"
    "content" | save --force $file
    "sig" | save --force $"($file).sig"
    "sig" | save --force $"($file).bob.sig"

    let found = sig-files-for $file
    assert equal ($found | each {|f| $f | path basename } | sort) ["w[1]?x*y.txt.bob.sig" "w[1]?x*y.txt.sig"]
    # The returned paths must be usable as-is, not just look right
    $found | each {|f| assert ($f | path exists) $"discovered path does not exist: ($f)" }
}

# A sibling whose name merely starts with the same characters is a different
# file — its signature is not ours.
@test
def "discovery ignores sigs of a different file" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "content" | save --force $file
    "sig" | save --force $"($file).alice.sig"
    "other" | save --force $"($tmp_dir)/doc.txt2"
    "sig" | save --force $"($tmp_dir)/doc.txt2.sig"
    "sig" | save --force $"($tmp_dir)/doc.txt2.bob.sig"

    let found = sig-files-for $file | each {|f| $f | path basename }
    assert equal $found ["doc.txt.alice.sig"]
}

# A dotfile's sigs are dotfiles too. Plain `ls` hides them, which lost
# `.env.alice.sig` for verify and left it stale through seal's clearing step.
@test
def "discovery finds sigs of a dotfile" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/.env"
    "content" | save --force $file
    "sig" | save --force $"($file).sig"
    "sig" | save --force $"($file).alice.sig"

    let found = sig-files-for $file | each {|f| $f | path basename } | sort
    assert equal $found [".env.alice.sig" ".env.sig"]
}

# Discovery feeds `seal`'s `rm`, so anything it returns gets deleted. A
# directory wearing a signature's name is not a signature: the empty one was
# removed silently and the non-empty one made `rm` throw mid-seal, leaving the
# catalogue regenerated but unsigned. Symlinks are out for the other half of
# the reason — verify would read through one to bytes its name does not name.
@test
def "discovery returns signatures only, not directories or links wearing the name" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "content" | save --force $file
    "sig" | save --force $"($file).alice.sig"
    mkdir $"($file).bundle.sig"
    mkdir $"($file).full.sig"
    "decoy" | save --force $"($file).full.sig/inside"
    "elsewhere" | save --force $"($tmp_dir)/elsewhere"
    ^ln -s $"($tmp_dir)/elsewhere" $"($file).link.sig"

    let found = sig-files-for $file | each {|f| $f | path basename }
    assert equal $found ["doc.txt.alice.sig"]
}

# The ambiguity `original-for-sig` resolves, asked from the discovery side:
# `doc.txt.gz.sig` is the bare sig of `doc.txt.gz` when that file exists, and
# only otherwise a "gz"-named sig of `doc.txt`. Skip the question and `seal`
# clears an archive's signature as stale while the archive sits untouched.
@test
def "the bare signature of a sibling file is not ours" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "content" | save --force $file
    "archive" | save --force $"($file).gz"
    "sig of the archive" | save --force $"($file).gz.sig"
    "sig" | save --force $"($file).alice.sig"

    let found = sig-files-for $file | each {|f| $f | path basename }
    assert equal $found ["doc.txt.alice.sig"]
    # ...and the archive's own discovery still finds it
    assert equal (sig-files-for $"($file).gz" | each {|f| $f | path basename }) ["doc.txt.gz.sig"]

    # With no such sibling on disk the same name is a named sig of doc.txt —
    # the grammar is unchanged, only the ambiguity is settled.
    rm $"($file).gz"
    let now_named = sig-files-for $file | each {|f| $f | path basename } | sort
    assert equal $now_named ["doc.txt.alice.sig" "doc.txt.gz.sig"]
}

@test
def "discovery returns an empty list when nothing is signed" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "content" | save --force $file

    assert equal (sig-files-for $file) []
}

# Discovery over a directory that does not exist yet is "nothing signed", not a
# failure — seal clears sigs for targets whose parent dir it has not created.
@test
def "discovery returns an empty list when the directory is absent" [] {
    let tmp_dir = $in.tmp_dir
    assert equal (sig-files-for $"($tmp_dir)/no-such-dir/doc.txt") []
}

# Discovery and naming encode one grammar; they must agree on which discovered
# file is bare (null signer) and which carries a signer label.
@test
def "signer-from-sig agrees with discovery" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/w[1]?x*y.txt"
    "content" | save --force $file
    "sig" | save --force $"($file).sig"
    "sig" | save --force $"($file).maxim-uvarov2.sig"

    let labelled = sig-files-for $file
        | each {|sig| {sig: ($sig | path basename) signer: (signer-from-sig $file $sig)} }
        | sort-by sig
    assert equal $labelled [
        {sig: "w[1]?x*y.txt.maxim-uvarov2.sig" signer: "maxim-uvarov2"}
        {sig: "w[1]?x*y.txt.sig" signer: null}
    ]
}

# The inverse of discovery: given only the sig's name, which file does it
# cover? `doc.txt.sig` is the bare sig of `doc.txt` and also the "txt"-named
# sig of `doc`, so only the filesystem decides. ssh-sign verify's own copy of
# this grammar always read it as the named form.
@test
def "the file a sig covers is found for both forms" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "content" | save --force $file
    "sig" | save --force $"($file).sig"
    "sig" | save --force $"($file).alice.sig"

    assert equal (original-for-sig $"($file).sig") $file
    assert equal (original-for-sig $"($file).alice.sig") $file
}

# The ambiguous name resolved the other way: here `doc` exists and `doc.txt`
# does not, so `doc.txt.sig` really is the "txt"-named sig of `doc`.
@test
def "the named form wins only when the bare original is absent" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc"
    "content" | save --force $file
    "sig" | save --force $"($file).txt.sig"

    assert equal (original-for-sig $"($file).txt.sig") $file
}

@test
def "a sig covering nothing on disk is an error, not a guess" [] {
    let tmp_dir = $in.tmp_dir
    assert error {|| original-for-sig $"($tmp_dir)/gone.txt.sig" }
    assert error {|| original-for-sig $"($tmp_dir)/doc.txt" }
}

# Naming and discovery are the same grammar read in two directions.
@test
def "sig-path-for names what discovery finds" [] {
    let tmp_dir = $in.tmp_dir
    let file = $"($tmp_dir)/doc.txt"
    "content" | save --force $file
    "sig" | save --force (sig-path-for $file)
    "sig" | save --force (sig-path-for $file "alice")

    assert equal (sig-files-for $file | each {|f| $f | path basename } | sort) ["doc.txt.alice.sig" "doc.txt.sig"]
}
