use std/assert
use std/testing *

use ../nu-multiproof/_repo.nu repo-root

# A git repo at <tmp>/outer with a project at outer/sub/deep, the monorepo
# shape the default exists for. Paths come back from git, so the fixture
# resolves the tmp dir the same way before comparing.
@before-each
def setup []: nothing -> record {
    let tmp_dir = mktemp --directory
    let outer = $tmp_dir | path join outer

    mkdir ($outer | path join sub deep)
    ^git -C $outer init --quiet
    {tmp_dir: $tmp_dir outer: (^git -C $outer rev-parse --show-toplevel | str trim)}
}

@after-each
def cleanup [] {
    rm --recursive --force $in.tmp_dir
}

@test
def "a multiproofs dir in the current directory is the default" [] {
    let outer = $in.outer
    let sub = $outer | path join sub

    mkdir ($outer | path join multiproofs) ($sub | path join multiproofs)
    cd $sub
    assert equal (repo-root) $sub
}

@test
def "the nearest multiproofs dir above the current directory is the default" [] {
    let outer = $in.outer
    let sub = $outer | path join sub

    mkdir ($outer | path join multiproofs) ($sub | path join multiproofs)
    cd ($sub | path join deep)
    assert equal (repo-root) $sub
}

@test
def "with no multiproofs dir the default is the git root" [] {
    let outer = $in.outer

    cd ($outer | path join sub deep)
    assert equal (repo-root) $outer
}

@test
def "with no multiproofs dir the default under init is the current directory" [] {
    let deep = $in.outer | path join sub deep

    cd $deep
    assert equal (repo-root --init) $deep
}

# The monorepo case: the root holds its own multiproofs/, and a new project
# below it must not register into the root's trust list.
@test
def "a multiproofs dir above does not move init from the current directory" [] {
    let outer = $in.outer
    let deep = $outer | path join sub deep

    mkdir ($outer | path join multiproofs)
    cd $deep
    assert equal (repo-root --init) $deep
}

# Inside the marker cwd is part of a home, and a new home there would nest
# inside it.
@test
def "init from inside a multiproofs dir is refused and names the home" [] {
    let sub = $in.outer | path join sub

    mkdir ($sub | path join multiproofs pubkeys)
    cd ($sub | path join multiproofs pubkeys)
    let err = try { repo-root --init; null } catch {|e| $e.msg }

    assert ($err != null) "init resolved to a directory inside a home"
    assert str contains $err $sub
    assert str contains $err "--repo"
}

@test
def "a multiproofs file is not a home" [] {
    let outer = $in.outer
    let sub = $outer | path join sub

    "" | save ($sub | path join multiproofs)
    cd $sub
    assert equal (repo-root) $outer
}

@test
def "an explicit repo wins over a multiproofs dir in the current directory" [] {
    let outer = $in.outer
    let sub = $outer | path join sub

    mkdir ($sub | path join multiproofs)
    cd $sub
    assert equal (repo-root $outer) $outer
}

# The walk stops at the git root: a home in a directory that contains the
# repo is another project, not this one.
@test
def "a multiproofs dir above the git root is out of reach" [] {
    let tmp_dir = $in.tmp_dir
    let outer = $in.outer

    mkdir ($tmp_dir | path join multiproofs)
    cd $outer
    assert equal (repo-root) $outer
}

# The case that rules out walking `$env.PWD` up to the git root: through a
# symlink the two spell one directory differently, and that walk never stops.
@test
def "a current directory reached through a symlink resolves inside the repo" [] {
    let tmp_dir = $in.tmp_dir
    let outer = $in.outer
    let link = $tmp_dir | path join link

    mkdir ($outer | path join sub multiproofs)
    ^ln --symbolic ($outer | path join sub) $link
    cd ($link | path join deep)
    assert equal (repo-root) ($outer | path join sub)
}

@test
def "outside a git repo the default fails and names the flag" [] {
    cd $in.tmp_dir
    let err = try { repo-root; null } catch {|e| $e.msg }

    assert str contains $err "--repo"
}
