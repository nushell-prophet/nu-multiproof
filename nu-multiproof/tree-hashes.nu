#!/usr/bin/env nu

# Generate a CSV manifest of content hashes (SHA-256, git object, IPFS CID v0)
# for all git-tracked files and their parent directories.

use cid-v0.nu

# Hashes name strings as-is (no trailing newline). To reproduce: printf '%s' 'name' | ipfs add ...
# --only-hash is baked in here on purpose: per-file content_cid is a column in the manifest,
# not something the user shares standalone. Publishing N individual files to the daemon serves
# no use case — only the root CID gets shared, and root-cid has its own --publish-to-ipfs opt-in.
const IPFS_CID_FLAGS = ["--progress=false" "--cid-version=0" "--raw-leaves=false" "--hash=sha2-256" "--chunker=size-262144"]
const OUTPUT_FILE = "tree-hashes.csv"
const MULTIPROOFS_DIR = "multiproofs"

def build-tree [
    --ipfs # Compute CIDs using ipfs CLI (supports large files and directory CIDs)
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> table {
    let root = if $repo != null { $repo | path expand } else {
        ^git rev-parse --show-toplevel | str trim
    }
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

    # Content CIDs
    let content_cid_table = if $ipfs {
        # Stage tracked files into a temp dir and ipfs-add that — so per-file and
        # per-dir CIDs cover exactly the manifest file set. Not `ipfs add -r $root`
        # because: it walks .git/ and ignored files, polluting directory CIDs.
        let tmp = $nu.temp-dir | path join $"nu-multiproof-build-tree-ipfs-(random uuid)"
        rm --recursive --force $tmp
        mkdir $tmp
        $tracked_files | each {|f|
            let dest = $tmp | path join $f
            mkdir ($dest | path dirname)
            cp ($root | path join $f) $dest
        }
        let tmp_basename = $tmp | path basename
        let table = (
            ^ipfs add --recursive --only-hash ...$IPFS_CID_FLAGS $tmp
            | lines
            | parse "added {cid} {path}"
            | where { $in.path != $tmp_basename }
            | reduce --fold {} {|row acc|
                let rel = $row.path | str replace $"($tmp_basename)/" ""
                $acc | insert $rel $row.cid
            }
        )
        rm --recursive --force $tmp
        $table
    } else {
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
    }

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

    # Join lookup tables into final CSV structure
    $entries
    | each {|e|
        {
            filepath: $e.rel
            content_sha256: $e.content_sha256
            content_git: ($git_hashes | get --optional $e.rel | default "")
            content_cid: (if $e.is_dir { "" } else { $content_cid_table | get $e.rel })
        }
    }
}

# Add manifest files to IPFS and return the root CID (CID v0, 46 chars).
# Reads tree-hashes.csv for the file list, stages them into a temp directory,
# runs `ipfs add -r` to get a single root hash for the whole worktree.
#
# The root CID is stored as a "." row in tree-hashes.csv. No circularity:
# tree-hashes.csv is excluded from its own manifest (build-tree filters it out),
# so the root CID covers all listed files but not the CSV itself.
# Not a separate file/git tag/provenance bundle because: the "." row collapses
# the root CID into the existing manifest — no new artifact to track.
# Signing the CSV implicitly covers the root CID. User decided signing the
# 46-char CID string separately is unnecessary — the CSV is the single artifact.
#
# The temp-dir staging ensures we add exactly the files from the manifest,
# not whatever happens to be on disk. CID parameters match IPFS_CID_FLAGS
# so individual file CIDs are consistent with the content_cid column.
export def root-cid [
    --repo: path # Target git repo root (default: git root of current directory)
    --publish-to-ipfs # Publish content to local IPFS daemon (default: only-hash, no daemon needed)
]: nothing -> string {
    let root = if $repo != null { $repo | path expand } else {
        ^git rev-parse --show-toplevel | str trim
    }
    let manifest_path = $root | path join $MULTIPROOFS_DIR $OUTPUT_FILE

    # Why: root-cid rewrites the manifest by appending/replacing the "." row.
    # Any existing sibling .sig signs the old content, so silently rewriting
    # would leave a sig that no longer matches. Fail-fast so a user running
    # the primitive standalone doesn't end up with a stale signature. `seal`
    # removes the sig itself before calling root-cid so it can proceed.
    # Both `<manifest>.<signer>.sig` and bare `<manifest>.sig` are checked —
    # mirrors what `ssh-sign verify` itself accepts.
    let named_sigs = glob $"($manifest_path).*.sig"
    let bare_sig = $"($manifest_path).sig"
    let stale_sigs = if ($bare_sig | path exists) { $named_sigs ++ [$bare_sig] } else { $named_sigs }
    if not ($stale_sigs | is-empty) {
        let names = $stale_sigs | each { path basename } | str join ", "
        error make {msg: $"manifest has signatures \(($names)\) — root-cid would invalidate them. Delete them or run `main seal` which handles this."}
    }

    let manifest = open $manifest_path
    # Why manifest not glob/git-ls-files: the manifest defines what's "in" the worktree.
    # The user's file list is the CSV, not whatever happens to be on disk.
    let files = $manifest | where content_sha256 != "" | get filepath

    # Why uuid: matches the other two stage dirs in this file. Without it,
    # two concurrent root-cid invocations (e.g. seal pipelines against
    # different repos under the same user) race on the same path.
    let tmp = $nu.temp-dir | path join $"nu-multiproof-ipfs-add-(random uuid)"
    rm --recursive --force $tmp
    mkdir $tmp

    $files | each {|f|
        let dest = $tmp | path join $f
        mkdir ($dest | path dirname)
        cp ($root | path join $f) $dest
    }

    let flags = if $publish_to_ipfs {
        ["--recursive" ...$IPFS_CID_FLAGS]
    } else {
        ["--recursive" "--only-hash" ...$IPFS_CID_FLAGS]
    }

    let cid = ^ipfs add ...$flags $tmp
        | lines | last
        | parse "added {cid} {path}" | get cid.0

    rm --recursive --force $tmp

    # Store root CID as "." row in the manifest
    $manifest
    | where filepath != "."
    | append {filepath: "." content_sha256: "" content_git: "" content_cid: $cid}
    | to csv --separator ','
    | save --raw --force $manifest_path

    $cid
}

# Generate tree hashes and save to multiproofs/tree-hashes.csv
export def main [
    --echo # Output as nushell table instead of saving to file
    --ipfs # Compute CIDs using ipfs CLI (supports large files and directory CIDs)
    --repo: path # Target git repo root (default: git root of current directory)
] {
    let table = (build-tree --ipfs=$ipfs --repo $repo)
    let target_root = if $repo != null { $repo | path expand } else {
        ^git rev-parse --show-toplevel | str trim
    }
    let out_dir = $target_root | path join $MULTIPROOFS_DIR
    mkdir $out_dir
    $table
    | if $echo { } else {
        to csv --separator ','
        | save --raw --force ($out_dir | path join $OUTPUT_FILE)
    }
}
