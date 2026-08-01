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
use _temp-helpers.nu with-temp-file

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

    # Git hashes: build a temp index from working-tree files, then ls-tree the
    # resulting tree. Gives blob AND tree hashes from the same snapshot, so a
    # modified file's parent dir hash changes too. Not `ls-tree HEAD` because:
    # it reflects committed state, not the working tree the manifest describes.
    let git_hashes = if ($tracked_files | is-empty) {
        {}
    } else {
        # Why -z on all three: same core.quotePath issue as ls-files above —
        # ls-tree C-quotes non-ASCII paths, so the git_hashes lookup by raw
        # path would silently miss them.
        with-temp-file "build-tree-index" {|tmp_index|
            with-env {GIT_INDEX_FILE: $tmp_index} {
                $tracked_files | str join (char -i 0) | ^git -C $root update-index --add -z --stdin
                let tree = ^git -C $root write-tree | str trim
                ^git -C $root ls-tree -r -t -z $tree
            }
        }
        | split row (char -i 0)
        | where { $in != "" }
        | parse "{mode} {type} {hash}\t{path}"
        | select path hash
        | reduce --fold {} {|row acc| $acc | insert $row.path $row.hash }
    }

    # Join lookup tables into final CSV structure. Every row carries a CID —
    # files from their own node, directories from the node folded above.
    let rows = $entries
        | each {|e|
            {
                filepath: $e.rel
                content_sha256: $e.content_sha256
                content_git: ($git_hashes | get --optional $e.rel | default "")
                content_cid: ($nodes | get $e.rel | node-cid)
            }
        }

    # The root "." row goes in during this same pass, so the manifest is written
    # once, complete — no reopen-and-rewrite.
    # Why re-sort: the "." row must obey the manifest's own byte-wise order
    # ("." sorts before ".woodpecker.yaml"), not sit appended last — merkle
    # leaf ordering depends on the CSV honoring its own rule.
    $rows
    | append {filepath: "." content_sha256: "" content_git: "" content_cid: ($nodes | get "." | node-cid)}
    | sort-by filepath
}

# Regenerate the manifest and return the root CID (CID v0) it records.
#
# The root CID lands in the manifest as the "." row, so it becomes a merkle leaf
# like any other row and the signed root statement covers it — the whole-CSV
# signature that used to cover it was dropped in 6bcfa24. Not a separate
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
@example "preview the manifest without saving" { nu-multiproof tree-hashes --echo }
export def main [
    --echo # Output as nushell table instead of saving to file
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> any {
    let table = (build-tree --repo $repo)
    let target_root = repo-root $repo
    if $echo {
        $table
    } else {
        mkdir (multiproofs-dir $target_root)
        $table | to csv | save --raw --force (manifest-path $target_root)
        manifest-path $target_root
    }
}
