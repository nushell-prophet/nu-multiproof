#!/usr/bin/env nu

# Generate a CSV manifest of content hashes (SHA-256, git object, IPFS CID v0)
# for all git-tracked files and their parent directories.

use cid-v0.nu
use cid-v0.nu MAX_SINGLE_CHUNK
use _repo.nu repo-root
use _layout.nu [MULTIPROOFS_DIR multiproofs-dir manifest-path]
use _temp-helpers.nu [with-temp-dir with-temp-file]

# IPFS CID parameters shared by the pure-nu reproduction (cid-v0.nu) and the
# ipfs CLI, so the two agree. To reproduce a name hash: printf '%s' 'name' | ipfs add ...
# --only-hash is the default (no daemon needed); --publish-to-ipfs drops it to
# actually store the content so the shared root CID is retrievable.
const IPFS_CID_FLAGS = ["--progress=false" "--cid-version=0" "--raw-leaves=false" "--hash=sha2-256" $"--chunker=size-($MAX_SINGLE_CHUNK)"]

def build-tree [
    --ipfs # Compute CIDs using ipfs CLI (records per-file, per-dir and the root "." CID)
    --publish-to-ipfs # With --ipfs: store content in the local IPFS daemon (default: only-hash)
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
    # generation but fail later at `merkle root` — which seal runs AFTER
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

    # Read each file once and derive both the sha256 and (in default mode) the
    # CID from that single read — not one read per hash.
    let file_entries = (
        $tracked_files
        | each {|f|
            let content = open --raw ($root | path join $f) | into binary
            let size = $content | bytes length
            {
                rel: $f
                is_dir: false
                content_sha256: ($content | hash sha256)
                # Empty in --ipfs mode (the add pass fills CIDs) and for files
                # over the single-chunk limit; otherwise the pure-nu CID.
                content_cid: (
                    if $ipfs { "" } else if $size > $MAX_SINGLE_CHUNK {
                        print $"skip: ($f) \(($size) bytes\) exceeds 256 KB single-chunk limit"
                        ""
                    } else { $content | cid-v0 }
                )
            }
        }
    )

    let entries = $dir_entries ++ $file_entries | sort-by rel

    # Content CIDs. In --ipfs mode a single `ipfs add -r` pass yields per-file,
    # per-dir AND the root "." CID together; default mode already computed
    # per-file CIDs above (pure Nushell, no daemon) and has no directory/root CID.
    let cid_result = if $ipfs {
        # Stage tracked files into a temp dir and ipfs-add that — so the CIDs
        # cover exactly the manifest file set. Not `ipfs add -r $root` because:
        # it walks .git/ and ignored files, polluting directory CIDs.
        with-temp-dir "build-tree-ipfs" {|tmp|
            $tracked_files | each {|f|
                let dest = $tmp | path join $f
                mkdir ($dest | path dirname)
                cp ($root | path join $f) $dest
            }
            let tmp_basename = $tmp | path basename
            let publish_flags = if $publish_to_ipfs { [] } else { ["--only-hash"] }
            # Why complete: on failure (notably `ipfs` repo-lock contention when
            # another add runs concurrently) stdout is empty and the root-row lookup
            # below would crash with a cryptic index error. Surface the ipfs stderr.
            # Why --hidden: ipfs add skips dotfiles by default, silently dropping
            # tracked dotfiles (.gitignore) from the add — and thus from the dir and
            # root CIDs the seal signs. Safe here: the staging dir holds only
            # tracked files, so there is no .git/ or ignored noise to pick up.
            # Not in IPFS_CID_FLAGS because: that const is the hashing parameters
            # shared with cid-v0.nu; --hidden is a traversal flag.
            let add = ^ipfs add --recursive --hidden ...$publish_flags ...$IPFS_CID_FLAGS $tmp | complete
            if $add.exit_code != 0 {
                error make {msg: $"ipfs add failed: ($add.stderr | str trim)"}
            }
            let rows = $add.stdout | lines | parse "added {cid} {path}"
            # The row whose path is the bare staging basename (no slash) is the root.
            let root_cid = $rows | where path == $tmp_basename | get cid.0
            let table = $rows
                | where path != $tmp_basename
                | reduce --fold {} {|row acc|
                    let rel = $row.path | str replace $"($tmp_basename)/" ""
                    $acc | insert $rel $row.cid
                }
            {table: $table root_cid: $root_cid}
        }
    } else {
        {table: {} root_cid: null}
    }
    let content_cid_table = $cid_result.table
    let root_cid = $cid_result.root_cid

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

    # Join lookup tables into final CSV structure. In --ipfs mode CIDs (files and
    # dirs — A3) come from the add pass's table; default mode uses the per-file
    # CID computed during the single read (dirs stay empty).
    let rows = $entries
        | each {|e|
            {
                filepath: $e.rel
                content_sha256: $e.content_sha256
                content_git: ($git_hashes | get --optional $e.rel | default "")
                content_cid: (
                    if $ipfs {
                        # Why an error, not `default ""`: every staged path must
                        # come back from the add pass — a miss means the add
                        # disagrees with the manifest file set. The silent empty
                        # fallback is what hid ipfs add skipping dotfiles.
                        let cid = $content_cid_table | get --optional $e.rel
                        if $cid == null {
                            error make {msg: $"ipfs add returned no CID for staged path ($e.rel)"}
                        }
                        $cid
                    } else {
                        $e | get --optional content_cid | default ""
                    }
                )
            }
        }

    # Append the root "." row when we have a root CID (only --ipfs computes one),
    # so the manifest is written once, complete — no reopen-and-rewrite (B2).
    # Why re-sort: the "." row must obey the manifest's own byte-wise order
    # ("." sorts before ".woodpecker.yaml"), not sit appended last — merkle
    # leaf ordering will depend on the CSV honoring its own rule.
    if $root_cid != null {
        $rows
        | append {filepath: "." content_sha256: "" content_git: "" content_cid: $root_cid}
        | sort-by filepath
    } else {
        $rows
    }
}

# Regenerate the manifest with IPFS CIDs and return the root CID (CID v0).
#
# One `ipfs add -r` pass over the staged worktree yields per-file, per-dir and
# the root "." CID together (build-tree does this in --ipfs mode), so the
# manifest is written once, complete — no reopen-and-rewrite and no
# stale-signature guard (B2). The root CID lands in the manifest as the "." row;
# signing the CSV implicitly covers it. Not a separate file/git tag/provenance
# bundle because: the "." row collapses the root CID into the existing manifest
# — no new artifact to track. tree-hashes.csv is excluded from its own manifest
# (build-tree filters multiproofs/ out), so the root CID covers all listed files
# but not the CSV itself.
@example "compute and record the IPFS root CID" { tree-hashes root-cid }
export def root-cid [
    --repo: path # Target git repo root (default: git root of current directory)
    --publish-to-ipfs # Publish content to local IPFS daemon (default: only-hash, no daemon needed)
]: nothing -> string {
    let root = repo-root $repo
    main --ipfs --publish-to-ipfs=$publish_to_ipfs --repo $repo
    open (manifest-path $root) | where filepath == "." | get content_cid.0
}

# Generate tree hashes. Saves to multiproofs/tree-hashes.csv and returns its
# path; --echo instead returns the table (and does not save).
@example "preview the manifest without saving" { tree-hashes --echo }
export def main [
    --echo # Output as nushell table instead of saving to file
    --ipfs # Compute CIDs using ipfs CLI (records per-file, per-dir and the root "." CID)
    --publish-to-ipfs # With --ipfs: store content in the local IPFS daemon (default: only-hash)
    --repo: path # Target git repo root (default: git root of current directory)
] {
    let table = (build-tree --ipfs=$ipfs --publish-to-ipfs=$publish_to_ipfs --repo $repo)
    let target_root = repo-root $repo
    if $echo {
        $table
    } else {
        mkdir (multiproofs-dir $target_root)
        $table | to csv | save --raw --force (manifest-path $target_root)
        manifest-path $target_root
    }
}
