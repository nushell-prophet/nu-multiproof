# The file set this project catalogues, and the CID nodes folded from it.
#
# Extracted from tree-hashes.nu so `merkle verify` can re-derive a directory
# row's CID from disk instead of trusting it. A directory CID commits to every
# entry under it, so the verifier must enumerate the same way the builder did —
# a second, slightly different enumeration would disagree with the manifest for
# reasons that have nothing to do with tampering.
#
# Internal module: mod.nu does not re-export _*.nu files.

use _cid-helpers.nu [file-node dir-node]
use _layout.nu MULTIPROOFS_DIR

# git-tracked files, minus the proof directory, sorted byte-wise.
#
# Why multiproofs/ is excluded: it is the proof-output dir, derived from the
# source it describes. Hashing it would make the manifest mutate every seal
# (new .ots nonce, new .sig) and entangle proof-of-content with
# proof-of-proof. The folder rule also subsumes the self-reference — the
# manifest cannot hash itself.
#
# File set: git-tracked files only. Hidden tracked files (.woodpecker.yaml,
# .gitignore) are included; .git/ is excluded by ls-files semantics. Not
# glob+filter because: it dropped hidden tracked files and mixed working-tree
# with VCS noise.
# Why -z: without it core.quotePath C-quotes non-ASCII names ("\346\226\207.md"),
# poisoning the filepath as an open path and as future merkle leaf bytes.
# Filepath = the raw path bytes as stored in git.
# Why -s: it carries the staged mode in the same pass, which the symlink gate
# needs — no extra stat over the tree.
export def tracked-entries [root: path]: nothing -> table {
    let exclude_prefix = $MULTIPROOFS_DIR + "/"
    let entries = (
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

    # Why reject control bytes here, not only in merkle validate-leaf: git
    # allows tab/ESC/\n in filenames. Such a name would pass manifest
    # generation but fail later at `merkle write-root` — which seal runs AFTER
    # regenerating the CSV, leaving a fresh manifest beside the previous
    # seal's still-valid signed root; rebuild-and-compare consumers read that
    # as tampering. Fail before writing anything (merkle's check stays as the
    # verifier-side guard for untrusted manifests). Consequence accepted: the
    # repo is unsealable until the file is renamed — per the spec's
    # "reject, never normalize".
    let control_byte_paths = $entries | get path | where { $in =~ '[\x00-\x1f]' }
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
    let symlink_paths = $entries | where mode == "120000" | get path
    if ($symlink_paths | is-not-empty) {
        error make {msg: $"git-tracked symlinks are not supported — one manifest row cannot describe both the link and its target; remove or replace: ($symlink_paths | to json)"}
    }

    $entries
}

# Every directory that appears as a parent of a tracked file. ls-files returns
# only files, so the manifest's directory rows are synthesized from the paths.
export def tracked-dirs [tracked_files: list<string>]: nothing -> list<string> {
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
}

# Fold file nodes up into directory nodes, keyed by manifest row name — "." is
# the repo root, whose node is the CID the "." row publishes.
#
# A UnixFS directory commits to its entries by name and CID, so every child must
# exist before its parent: walking the directories deepest-first gives that in
# one pass.
export def cid-nodes [file_entries: table, dirs: list<string>]: nothing -> record {
    let child_index = (
        ($file_entries | get rel) ++ $dirs
        | each {|rel|
            let parent = $rel | path dirname
            {parent: (if ($parent | is-empty) { "." } else { $parent }) name: ($rel | path basename) rel: $rel}
        }
        | group-by parent
    )
    let deepest_first = (
        $dirs ++ ["."]
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
        $nodes = ($nodes | insert $d (dir-node $links --path $d))
    }
    $nodes
}

# The whole content side of the manifest, read from disk in one pass:
# every tracked file's sha256 and UnixFS node, and every directory node
# folded from them — including ".".
#
# Each file is read once and both hashes derive from that single read, not one
# read per hash.
export def content-tree [root: path]: nothing -> record<files: table, dirs: list<string>, nodes: record> {
    let tracked_files = tracked-entries $root | get path
    let dirs = tracked-dirs $tracked_files
    let files = (
        $tracked_files
        | each {|f|
            let content = open --raw ($root | path join $f) | into binary
            {
                rel: $f
                content_sha256: ($content | hash sha256)
                node: ($content | file-node)
            }
        }
    )
    {files: $files dirs: $dirs nodes: (cid-nodes $files $dirs)}
}
