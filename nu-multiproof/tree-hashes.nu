#!/usr/bin/env nu

# Generate a CSV manifest of content hashes (SHA-256, git object, IPFS CID v0)
# for all non-hidden files and directories in the repo.

use cid-v0.nu

# Hashes name strings as-is (no trailing newline). To reproduce: printf '%s' 'name' | ipfs add ...
const IPFS_FLAGS = ["--only-hash" "--progress=false" "--cid-version=0" "--raw-leaves=false" "--hash=sha2-256" "--chunker=size-262144"]
const IPFS_CID_FLAGS = ["--progress=false" "--cid-version=0" "--raw-leaves=false" "--hash=sha2-256" "--chunker=size-262144"]
const OUTPUT_FILE = "tree-hashes.csv"
const MULTIPROOFS_DIR = "multiproofs"

export def build-tree [
    --ipfs  # Compute CIDs using ipfs CLI (supports large files and directory CIDs)
    --path: path  # Target git repo root (default: git root of current directory)
]: nothing -> table {
    let root = if $path != null { $path | path expand } else {
        ^git rev-parse --show-toplevel | str trim
    }
    let multiproofs = $root | path join $MULTIPROOFS_DIR
    let exclude_path = $multiproofs | path join $OUTPUT_FILE
    let root_basename = $root | path basename

    # Build file list with SHA-256 hashes (Nushell built-in, no process spawning)
    let entries = (
        glob ($root | path join '**/*') --no-symlink --exclude [**/.*/** tree-hashes.csv.*.ots]
        | where { path basename | str starts-with "." | not $in }
        | where $it != $exclude_path
        | sort
        | each {|entry|
            let is_dir = ($entry | path type) == dir
            let rel = $entry | path relative-to $root
            {
                rel: $rel
                is_dir: $is_dir
                content_sha256: (if $is_dir { "" } else { open --raw $entry | hash sha256 })
            }
        }
    )

    # Content CIDs
    let content_cid_table = if $ipfs {
        ^ipfs add --recursive ...$IPFS_FLAGS $root
        | lines
        | parse "added {cid} {path}"
        | where { $in.path != $root_basename }
        | reduce --fold {} {|row acc|
            let rel = $row.path | str replace $"($root_basename)/" ""
            $acc | insert $rel $row.cid
        }
    } else {
        $entries
        | where not $it.is_dir
        | each {|e|
            let content = open --raw ($root | path join $e.rel) | into binary
            let size = $content | bytes length
            if $size > 262144 {
                print $"skip: ($e.rel) \(($size) bytes\) exceeds 256 KB single-chunk limit"
                {key: $e.rel, val: ""}
            } else {
                {key: $e.rel, val: ($content | cid-v0)}
            }
        }
        | reduce --fold {} {|row acc| $acc | insert $row.key $row.val }
    }

    # Git hashes: tree hashes for directories, blob hashes for files (working copy)
    let git_hashes = (
        ^git -C $root ls-tree -r -t HEAD
        | lines
        | parse "{mode} {type} {hash}\t{path}"
        | select path hash
        | reduce --fold {} {|row acc| $acc | insert $row.path $row.hash }
    )

    let file_entries = $entries | where not $it.is_dir
    let git_blob_hashes = if ($file_entries | is-empty) {
        {}
    } else {
        $file_entries
        | each {|e| $root | path join $e.rel }
        | str join (char nl)
        | ^git -C $root hash-object --stdin-paths
        | lines
        | zip ($file_entries | each { $in.rel })
        | reduce --fold {} {|pair acc| $acc | insert $pair.1 $pair.0 }
    }

    # Join lookup tables into final CSV structure
    $entries
    | where { $in.rel | into string | is-not-empty }
    | each {|e|
        {
            filepath: $e.rel
            content_sha256: $e.content_sha256
            content_git: (if $e.is_dir {
                $git_hashes | get --optional $e.rel | default ""
            } else {
                $git_blob_hashes | get --optional $e.rel | default ""
            })
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
# Signing the CSV therefore implicitly covers the root CID — no need to sign
# the 46-char string separately.
#
# The temp-dir staging ensures we add exactly the files from the manifest,
# not whatever happens to be on disk. CID parameters match IPFS_CID_FLAGS
# so individual file CIDs are consistent with the content_cid column.
export def root-cid [
    --path: path  # Target git repo root (default: git root of current directory)
    --only-hash   # Compute CID without adding content to IPFS
]: nothing -> string {
    let root = if $path != null { $path | path expand } else {
        ^git rev-parse --show-toplevel | str trim
    }
    let manifest_path = $root | path join $MULTIPROOFS_DIR $OUTPUT_FILE
    let manifest = open $manifest_path
    let files = $manifest | where content_sha256 != "" | get filepath

    let tmp = $nu.temp-dir | path join "nu-multiproof-ipfs-add"
    rm --recursive --force $tmp
    mkdir $tmp

    $files | each {|f|
        let dest = $tmp | path join $f
        mkdir ($dest | path dirname)
        cp ($root | path join $f) $dest
    }

    let flags = if $only_hash {
        ["--recursive" "--only-hash" ...$IPFS_CID_FLAGS]
    } else {
        ["--recursive" ...$IPFS_CID_FLAGS]
    }

    let cid = ^ipfs add ...$flags $tmp
        | lines | last
        | parse "added {cid} {path}" | get cid.0

    rm --recursive --force $tmp

    # Store root CID as "." row in the manifest
    $manifest
    | where filepath != "."
    | append {filepath: ".", content_sha256: "", content_git: "", content_cid: $cid}
    | to csv --separator ','
    | save --raw --force $manifest_path

    $cid
}

# Generate tree hashes and save to multiproofs/tree-hashes.csv
export def main [
    --echo # Output as nushell table instead of saving to file
    --ipfs # Compute CIDs using ipfs CLI (supports large files and directory CIDs)
    --path: path  # Target git repo root (default: git root of current directory)
] {
    let table = if $ipfs { build-tree --ipfs --path $path } else { build-tree --path $path }
    let target_root = if $path != null { $path | path expand } else {
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
