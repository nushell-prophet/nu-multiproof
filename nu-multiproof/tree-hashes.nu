#!/usr/bin/env nu

# Generate a CSV manifest of content hashes (SHA-256, git object, IPFS CID v0)
# for all git-tracked files, their parent directories and the repo root ".".
#
# Every hash is computed in-process: the CIDs come from _cid-helpers.nu, which
# reproduces `ipfs add` byte for byte, so no ipfs daemon or CLI is involved and
# there is only ever one manifest shape to sign.

use _cid-helpers.nu [file-node dir-node node-cid]
use _repo.nu repo-root
use _layout.nu [MULTIPROOFS_DIR multiproofs-dir manifest-path]
use _temp-helpers.nu with-temp-file

# Fold file nodes up into directory nodes, keyed by manifest row name — "." is
# the repo root, whose node is the CID the "." row publishes.
#
# A UnixFS directory commits to its entries by name and CID, so every child must
# exist before its parent: walking the directories deepest-first gives that in
# one pass.
def cid-nodes [file_entries: table, dir_entries: table]: nothing -> record {
    let child_index = (
        ($file_entries | select rel) ++ ($dir_entries | select rel)
        | each {|e|
            let parent = $e.rel | path dirname
            {parent: (if ($parent | is-empty) { "." } else { $parent }) name: ($e.rel | path basename) rel: $e.rel}
        }
        | group-by parent
    )
    let deepest_first = (
        ($dir_entries | get rel) ++ ["."]
        | each {|rel| {rel: $rel depth: (if $rel == "." { 0 } else { $rel | path split | length })} }
        | sort-by depth --reverse
        | get rel
    )
    mut nodes = $file_entries | reduce --fold {} {|e acc| $acc | insert $e.rel $e.node }
    for d in $deepest_first {
        let built = $nodes # a closure cannot capture a mutable variable
        # Why sort by name: `ipfs add` walks directory entries in byte-wise name
        # order, and the link order is part of what the directory CID commits
        # to. Nushell compares strings byte-wise, so a plain sort-by is it.
        let links = $child_index
            | get --optional $d
            | default []
            | sort-by name
            | each {|c| {name: $c.name node: ($built | get $c.rel)} }
        $nodes = ($nodes | insert $d (dir-node $links))
    }
    $nodes
}

def build-tree [
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> table {
    let root = repo-root $repo
    # Why: multiproofs/ is the proof-output dir, derived from the source it
    # describes. Hashing it would make the manifest mutate every seal (new .ots
    # nonce, new .sig) and entangle proof-of-content with proof-of-proof. The
    # folder rule also subsumes the self-reference — the manifest can't hash
    # itself — so no separate single-file exclude is needed.
    let exclude_prefix = $MULTIPROOFS_DIR + "/"

    # File set: git-tracked files only. Hidden tracked files (.woodpecker.yaml,
    # .gitignore) are included; .git/ is excluded by ls-files semantics.
    # Not glob+filter because: it dropped hidden tracked files and mixed
    # working-tree with VCS noise.
    # Why -z: without it core.quotePath C-quotes non-ASCII names
    # ("\346\226\207.md"), poisoning the filepath as an open path and as
    # future merkle leaf bytes. Filepath = the raw path bytes as stored in git.
    # Why -s: it carries the staged mode in the same pass, which the symlink
    # gate below needs — no extra stat over the tree.
    let tracked_entries = (
        ^git -C $root ls-files -s -z
        | split row (char -i 0)
        | where { $in != "" }
        # Why split on the first tab instead of `parse`: ls-files -s separates
        # "<mode> <object> <stage>" from the path with one tab, and the path
        # itself may contain tabs (see the control-byte gate below).
        | each {|row|
            let parts = $row | split row --number 2 (char tab)
            {mode: ($parts.0 | split row " " | first) path: $parts.1}
        }
        | where { not ($in.path | str starts-with $exclude_prefix) }
        | sort-by path
    )
    let tracked_files = $tracked_entries | get path

    # Why reject control bytes here, not only in merkle validate-leaf: git
    # allows tab/ESC/\n in filenames. Such a name would pass manifest
    # generation but fail later at `merkle write-root` — which seal runs AFTER
    # regenerating the CSV, leaving a fresh manifest beside the previous
    # seal's still-valid signed root; rebuild-and-compare consumers read that
    # as tampering. Fail before writing anything (merkle's check stays as the
    # verifier-side guard for untrusted manifests). Consequence accepted: the
    # repo is unsealable until the file is renamed — per the spec's
    # "reject, never normalize".
    let control_byte_paths = $tracked_files | where { $in =~ '[\x00-\x1f]' }
    if ($control_byte_paths | is-not-empty) {
        error make {msg: $"git-tracked filenames contain control bytes \(< 0x20\), which merkle leaves reject — rename: ($control_byte_paths | to json)"}
    }

    # Why reject symlinks (mode 120000) rather than follow or hash them: one
    # manifest row must describe one object. `open --raw` follows the link, so
    # content_sha256 and content_cid would describe the target while
    # content_git describes git's blob holding the link string — one row, two
    # objects, and two honest verifiers (re-hash the worktree vs. rebuild from
    # git objects) that disagree without either being wrong. A link pointing
    # outside the repo would also pull foreign content into the sealed
    # catalogue. Same "reject, never normalize" rule as the control-byte gate.
    # Naming the offending paths also replaces the opaque death a broken link
    # caused downstream in `open` ("Eval block failed with pipeline input").
    let symlink_paths = $tracked_entries | where mode == "120000" | get path
    if ($symlink_paths | is-not-empty) {
        error make {msg: $"git-tracked symlinks are not supported — one manifest row cannot describe both the link and its target; remove or replace: ($symlink_paths | to json)"}
    }

    # Synthesize directory entries from file paths (ls-files returns only files).
    let dir_entries = (
        $tracked_files
        | each {|f|
            let parts = $f | path split
            if ($parts | length) <= 1 { [] } else {
                1..(($parts | length) - 1) | each {|n| $parts | first $n | path join }
            }
        }
        | flatten
        | uniq
        | sort
        | each {|d| {rel: $d is_dir: true content_sha256: ""} }
    )

    # Read each file once and derive both the sha256 and the CID node from that
    # single read — not one read per hash.
    let file_entries = (
        $tracked_files
        | each {|f|
            let content = open --raw ($root | path join $f) | into binary
            {
                rel: $f
                is_dir: false
                content_sha256: ($content | hash sha256)
                node: ($content | file-node)
            }
        }
    )

    let entries = ($dir_entries ++ ($file_entries | reject node)) | sort-by rel

    let nodes = cid-nodes $file_entries $dir_entries

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
    # once, complete — no reopen-and-rewrite (B2).
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
@example "compute and record the IPFS root CID" { tree-hashes root-cid }
export def root-cid [
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> string {
    let root = repo-root $repo
    main --repo $repo
    open (manifest-path $root) | where filepath == "." | get content_cid.0
}

# Generate tree hashes. Saves to multiproofs/tree-hashes.csv and returns its
# path; --echo instead returns the table (and does not save).
@example "preview the manifest without saving" { tree-hashes --echo }
export def main [
    --echo # Output as nushell table instead of saving to file
    --repo: path # Target git repo root (default: git root of current directory)
] {
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
