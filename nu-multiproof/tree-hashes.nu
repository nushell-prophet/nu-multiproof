#!/usr/bin/env nu

# Generate a CSV manifest of content hashes (SHA-256, git object, IPFS CID v0)
# for all git-tracked files, their parent directories and the repo root ".".
#
# Every hash is computed in-process: the CIDs come from _cid-helpers.nu, which
# reproduces `ipfs add` byte for byte, so no ipfs daemon or CLI is involved and
# there is only ever one manifest shape to sign.

use _cid-helpers.nu node-cid
use _tracked.nu content-tree
use _repo.nu repo-root
use _layout.nu [ multiproofs-dir manifest-path ]
use _temp-helpers.nu [ with-temp-dir with-temp-file ]
use _snapshot.nu write-snapshot

# Git object hashes for every tracked file AND its parent directories, in one
# object format, keyed by repo-relative path.
#
# Why a scratch repo rather than the target's own: git hashes only in the format
# its own repo was created with, so the other format would be missing — and the
# 2026-07-18 session assumed that meant assembling tree object bytes by hand, in
# the trust path. It does not: `git init --object-format` gives that format a
# home, GIT_WORK_TREE still points at the real working tree, and git produces
# blob and tree hashes there.
#
# Why git and not a hash computed here: git defines what a git object hash is,
# nushell has no sha1 at all, and nothing here serializes a git tree object — so
# for three of the four halves of these columns git is the only source. Not for
# speed: measured 2026-08-28 on git 2.39.5 over 2460 files, git's blob pass and
# the equivalent nushell one land within 10% of each other.
#
# Why a temp index over the working tree and not `ls-tree HEAD`: HEAD reflects
# committed state, not the tree the manifest describes. One `write-tree` gives
# blob AND tree hashes from the same snapshot, so a modified file changes its
# parent directory's hash too.
def git-hashes [root: path tracked_files: list<string> format: string]: nothing -> record {
    if ($tracked_files | is-empty) { return {} }

    with-temp-dir $"build-tree-($format)" {|scratch|
        # --bare: the scratch holds objects only; the tree being hashed is the
        # target's, named by GIT_WORK_TREE.
        ^git init --quiet --object-format $format --bare $scratch
        with-temp-file $"build-tree-index-($format)" {|tmp_index|
            with-env {GIT_DIR: $scratch GIT_WORK_TREE: $root GIT_INDEX_FILE: $tmp_index} {
                # Why -z on all three: same core.quotePath issue as ls-files
                # above — ls-tree C-quotes non-ASCII paths, so the lookup by raw
                # path would silently miss them.
                $tracked_files | str join (char -i 0) | ^git -C $root update-index --add -z --stdin
                let tree = ^git -C $root write-tree | str trim
                ^git -C $root ls-tree -r -t -z $tree
            }
        }
    }
    | split row (char -i 0)
    | where { $in != "" }
    | parse "{mode} {type} {hash}\t{path}"
    | select path hash
    | reduce --fold {} {|row acc| $acc | insert $row.path $row.hash }
}

def build-tree [
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> table {
    let root = repo-root $repo

    # The enumeration, the per-file hashes and the folded directory nodes all
    # come from _tracked.nu, because `merkle verify` re-derives directory CIDs
    # from disk and must walk the tree exactly as this does. Two enumerations
    # that differ by a hair disagree for reasons unrelated to tampering.
    let tree = content-tree $root
    let tracked_files = $tree.files | get rel

    let entries = (
        ($tree.dirs | each {|d| {rel: $d content_sha256: ""} })
        ++ ($tree.files | select rel content_sha256)
        | sort-by rel
    )

    let nodes = $tree.nodes

    # Both git object formats, always — never just the one this repo happens to
    # run. The column is a lookup key, so a manifest that carries only SHA-256
    # is useless to the SHA-1 repos that are most of the world. Carrying both
    # also makes every column a function of the content alone, so the merkle
    # root stops depending on the repo's object format.
    let git_sha1 = git-hashes $root $tracked_files "sha1"
    let git_sha256 = git-hashes $root $tracked_files "sha256"

    # Join lookup tables into final CSV structure. Every row carries a CID —
    # files from their own node, directories from the node folded above.
    let rows = $entries
        | each {|e|
            {
                filepath: $e.rel
                content_sha256: $e.content_sha256
                # Why: a lookup key, not an integrity anchor — it is here so a
                # file can be found cheaply in a repo whatever object format
                # that repo uses. The user's own framing, 2026-07-18: "this is
                # not about integrity, it is about cheap lookup of files in
                # repositories, whatever format they are in."
                content_git_sha1: ($git_sha1 | get --optional $e.rel | default "")
                content_git_sha256: ($git_sha256 | get --optional $e.rel | default "")
                content_cid: ($nodes | get $e.rel | node-cid)
            }
        }

    # The root "." row goes in during this same pass, so the manifest is written
    # once, complete — no reopen-and-rewrite.
    # Why re-sort: the "." row must obey the manifest's own byte-wise order
    # ("." sorts before ".woodpecker.yaml"), not sit appended last — merkle
    # leaf ordering depends on the CSV honoring its own rule.
    $rows
    | append {filepath: "." content_sha256: "" content_git_sha1: "" content_git_sha256: "" content_cid: ($nodes | get "." | node-cid)}
    | sort-by filepath
}

# Regenerate the manifest and return the root CID (CID v0) it records.
#
# The root CID lands in the manifest as the "." row, so it becomes a merkle leaf
# like any other row and the signed root statement covers it. Not a separate
# file/git tag/provenance bundle because: the "." row collapses the root CID
# into the existing manifest — no new artifact to track. tree-hashes.csv is
# excluded from its own manifest (build-tree filters multiproofs/ out), so the
# root CID covers all listed files but not the CSV itself.
@example "compute and record the IPFS root CID" { nu-multiproof tree-hashes root-cid }
export def root-cid [
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> string {
    let root = repo-root $repo
    main --repo $repo
    open (manifest-path $root) | where filepath == "." | get content_cid.0
}

# Generate tree hashes. Saves to multiproofs/tree-hashes.csv and returns its
# path; --echo instead returns the table (and does not save).
#
# Alongside the manifest it records which commit that manifest describes, in
# multiproofs/snapshot.txt — but only when the tree it read equals HEAD, so the
# record is one a third party can check by rebuilding. See _snapshot.nu for why a
# dirty tree gets no record instead of a hedged one. This step owns the record
# because it is the only one that reads the working tree: the commit is answered
# in the same pass that produces the manifest, leaving no window between them.
@example "preview the manifest without saving" { nu-multiproof tree-hashes --echo }
export def main [
    --echo # Output as nushell table instead of saving to file
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> any {
    let table = (build-tree --repo $repo)
    let target_root = repo-root $repo
    if $echo {
        # Nothing is written under --echo, the snapshot record included: it
        # describes a manifest on disk, and --echo puts none there.
        $table
    } else {
        mkdir (multiproofs-dir $target_root)
        $table | to csv | save --raw --force (manifest-path $target_root)
        write-snapshot $target_root
        manifest-path $target_root
    }
}
