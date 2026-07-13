#!/usr/bin/env nu

# Generate a CSV manifest of content hashes (SHA-256, git object, IPFS CID v0)
# for all git-tracked files and their parent directories.

use cid-v0.nu
use _repo.nu repo-root
use _layout.nu [MULTIPROOFS_DIR multiproofs-dir manifest-path]

# IPFS CID parameters shared by the pure-nu reproduction (cid-v0.nu) and the
# ipfs CLI, so the two agree. To reproduce a name hash: printf '%s' 'name' | ipfs add ...
# --only-hash is the default (no daemon needed); --publish-to-ipfs drops it to
# actually store the content so the shared root CID is retrievable.
const IPFS_CID_FLAGS = ["--progress=false" "--cid-version=0" "--raw-leaves=false" "--hash=sha2-256" "--chunker=size-262144"]

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
    let tracked_files = (
        ^git -C $root ls-files
        | lines
        | where { not ($in | str starts-with $exclude_prefix) }
        | sort
    )

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

    let file_entries = (
        $tracked_files
        | each {|f|
            {
                rel: $f
                is_dir: false
                content_sha256: (open --raw ($root | path join $f) | hash sha256)
            }
        }
    )

    let entries = $dir_entries ++ $file_entries | sort-by rel

    # Content CIDs. In --ipfs mode a single `ipfs add -r` pass yields per-file,
    # per-dir AND the root "." CID together; default mode computes per-file CIDs
    # in pure Nushell (no daemon) and has no directory/root CID.
    let cid_result = if $ipfs {
        # Stage tracked files into a temp dir and ipfs-add that — so the CIDs
        # cover exactly the manifest file set. Not `ipfs add -r $root` because:
        # it walks .git/ and ignored files, polluting directory CIDs.
        let tmp = $nu.temp-dir | path join $"nu-multiproof-build-tree-ipfs-(random uuid)"
        rm --recursive --force $tmp
        mkdir $tmp
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
        let add = ^ipfs add --recursive ...$publish_flags ...$IPFS_CID_FLAGS $tmp | complete
        rm --recursive --force $tmp
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
    } else {
        let table = (
            $file_entries
            | each {|e|
                let content = open --raw ($root | path join $e.rel) | into binary
                let size = $content | bytes length
                if $size > 262144 {
                    print $"skip: ($e.rel) \(($size) bytes\) exceeds 256 KB single-chunk limit"
                    {key: $e.rel val: ""}
                } else {
                    {key: $e.rel val: ($content | cid-v0)}
                }
            }
            | reduce --fold {} {|row acc| $acc | insert $row.key $row.val }
        )
        {table: $table root_cid: null}
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
        let tmp_index = $nu.temp-dir | path join $"nu-multiproof-build-tree-index-(random uuid)"
        rm --force $tmp_index
        let ls_tree = with-env {GIT_INDEX_FILE: $tmp_index} {
            $tracked_files | str join (char nl) | ^git -C $root update-index --add --stdin
            let tree = ^git -C $root write-tree | str trim
            ^git -C $root ls-tree -r -t $tree
        }
        rm --force $tmp_index
        $ls_tree
        | lines
        | parse "{mode} {type} {hash}\t{path}"
        | select path hash
        | reduce --fold {} {|row acc| $acc | insert $row.path $row.hash }
    }

    # Join lookup tables into final CSV structure. In --ipfs mode dir rows carry
    # their CID too (A3); default mode leaves them empty. get --optional guards
    # a file the ipfs pass somehow missed — shows empty, not a cryptic crash.
    let rows = $entries
        | each {|e|
            {
                filepath: $e.rel
                content_sha256: $e.content_sha256
                content_git: ($git_hashes | get --optional $e.rel | default "")
                content_cid: ($content_cid_table | get --optional $e.rel | default "")
            }
        }

    # Append the root "." row when we have a root CID (only --ipfs computes one),
    # so the manifest is written once, complete — no reopen-and-rewrite (B2).
    if $root_cid != null {
        $rows | append {filepath: "." content_sha256: "" content_git: "" content_cid: $root_cid}
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
export def root-cid [
    --repo: path # Target git repo root (default: git root of current directory)
    --publish-to-ipfs # Publish content to local IPFS daemon (default: only-hash, no daemon needed)
]: nothing -> string {
    let root = repo-root $repo
    main --ipfs --publish-to-ipfs=$publish_to_ipfs --repo $repo
    open (manifest-path $root) | where filepath == "." | get content_cid.0
}

# Generate tree hashes and save to multiproofs/tree-hashes.csv
export def main [
    --echo # Output as nushell table instead of saving to file
    --ipfs # Compute CIDs using ipfs CLI (records per-file, per-dir and the root "." CID)
    --publish-to-ipfs # With --ipfs: store content in the local IPFS daemon (default: only-hash)
    --repo: path # Target git repo root (default: git root of current directory)
] {
    let table = (build-tree --ipfs=$ipfs --publish-to-ipfs=$publish_to_ipfs --repo $repo)
    let target_root = repo-root $repo
    mkdir (multiproofs-dir $target_root)
    $table
    | if $echo { } else {
        to csv
        | save --raw --force (manifest-path $target_root)
    }
}
