# Extract and verify git merkle proofs.
#
# Creates compact cryptographic proof that specific files existed
# in a signed git commit — without transferring the full repository.
#
# Proof bundle format:
#   proof/
#     manifest.json        — commit hash, target files, objects list
#     objects/XX/YYY...    — git loose objects (commit, trees, blobs)
#     pubkeys/*.pub        — signer's public keys

use _repo.nu repo-root
use _layout.nu pubkeys-dir
use _allowed-signers.nu allowed-signers-body

# --- Shared helpers ---

# Parse `git ls-tree` output into a table
def parse-ls-tree []: string -> table<mode: string, type: string, hash: string, name: string> {
    lines | parse "{mode} {type} {hash}\t{name}"
}

# Extract tree hash from commit object text.
# Why: commit body lines can start with "tree " — only the header section
# (everything before the first blank line) carries the actual tree pointer.
def parse-commit-tree []: string -> string {
    split row --regex '\r?\n\r?\n'
    | first
    | lines
    | where ($it starts-with "tree ")
    | first
    | str replace "tree " ""
}

# Copy git loose objects between directories
def copy-loose-objects [src: path dest: path] {
    let src = $src | path expand
    glob ($src | path join "??/*") | each {|file|
        let rel = ($file | path relative-to $src)
        mkdir ($dest | path join $rel | path dirname)
        cp $file ($dest | path join $rel)
    }
}

# Walk file_path's segments from tree_hash down through the git trees, returning
# the hash chain [{name, hash, type}] from the first segment to the target
# blob/tree. Shared by extract (collects the objects) and verify (compares the
# final hash), so both get the same errors. `git_args` addresses the repo:
# ["-C" $root] for a working repo, ["--git-dir" $bare] for a bare one.
def walk-tree-path [
    git_args: list<string>
    tree_hash: string
    file_path: string
]: nothing -> list<record<name: string, hash: string, type: string>> {
    let parts = ($file_path | split row "/")
    let last_index = ($parts | length) - 1
    mut chain = []
    mut current_tree = $tree_hash

    for it in ($parts | enumerate) {
        let name = $it.item
        let is_last = $it.index == $last_index

        let tree = $current_tree # immutable copy — mut vars can't be captured in the do closure
        let result = (do { ^git ...$git_args ls-tree $tree } | complete)
        if $result.exit_code != 0 {
            error make {msg: $"cannot read tree ($tree | str substring 0..12)... for ($file_path): ($result.stderr | str trim)"}
        }
        let entry = ($result.stdout | parse-ls-tree | where name == $name)

        if ($entry | is-empty) {
            error make {msg: $"'($name)' not found in tree ($tree | str substring 0..12)... \(path: ($file_path)\)"}
        }

        let entry = ($entry | first)
        $chain = ($chain | append {name: $name hash: $entry.hash type: $entry.type})

        if $entry.type == "tree" {
            $current_tree = $entry.hash
        } else if not $is_last {
            # Why: without this, the cursor stayed at the previous tree and the
            # next segment was looked up there — producing either a misleading
            # "not found in tree <root>" message or, worse, a silent success
            # with a bogus proof (when a sibling at the wrong level happened to
            # share the name).
            error make {msg: $"'($name)' is a ($entry.type); cannot descend into ($file_path)"}
        }
    }

    $chain
}

# --- Extraction ---

# Extract loose objects from the source repo into a fresh bare repo
# of the same object format, then copy them out.
#
# Not a SHA-1→SHA-256 conversion: tree object bodies encode child references
# as raw hash bytes, which `git unpack-objects` does not rewrite. The bundle
# format must match the source; cross-format conversion would need
# tree-rewriting (out of scope). Caller must ensure source repo is SHA-256.
def extract-loose-objects [
    hashes: list<string> # Object hashes to extract
    dest: path # Directory to receive loose objects
    --repo: path # Target git repo root
] {
    let tmp_dir = (^mktemp -d | str trim)
    let hashes_file = ($tmp_dir | path join "hashes.txt")
    let pack_file = ($tmp_dir | path join "pack.bin")
    let bare_repo = ($tmp_dir | path join "bare-repo")

    $hashes | str join "\n" | save --force $hashes_file
    ^git init --bare --object-format=sha256 $bare_repo o+e>| ignore
    open --raw $hashes_file | ^git -C $repo pack-objects --stdout | save --raw --force $pack_file
    open --raw $pack_file | ^git --git-dir $bare_repo unpack-objects

    copy-loose-objects ($bare_repo | path join "objects") $dest
    rm --recursive $tmp_dir
}

# Extract a merkle proof bundle for given files at a given commit
export def extract [
    ...files: string # Target file paths to prove
    --commit: string = "HEAD" # Commit to prove against
    --out-dir: path = "proof" # Output directory for proof bundle
    --repo: path # Target git repo root (default: git root of current directory)
] {
    if ($files | is-empty) {
        error make {msg: "no files specified"}
    }

    let root = repo-root $repo
    # Why: tree objects encode children as raw hash bytes; SHA-1 sources would
    # need tree rewriting to produce a self-consistent SHA-256 bundle.
    let src_format = (^git -C $root config extensions.objectFormat | complete | get stdout | str trim)
    if $src_format != "sha256" {
        error make {msg: $"git-proof requires a SHA-256 repo \(extensions.objectFormat=sha256\); source is '($src_format)'"}
    }
    let commit_hash = (^git -C $root rev-parse $commit | str trim)
    let tree_hash = (^git -C $root cat-file -p $commit_hash | parse-commit-tree)

    # Collect merkle path objects for all target files
    mut all_objects = [
        {hash: $commit_hash type: "commit"}
        {hash: $tree_hash type: "tree"}
    ]
    mut target_files = []

    for file in $files {
        let chain = (walk-tree-path ["-C" $root] $tree_hash $file)
        $all_objects = ($all_objects | append ($chain | select hash type))
        $target_files = (
            $target_files | append {
                path: $file
                hash: ($chain | last | get hash)
            }
        )
    }

    let unique_objects = ($all_objects | uniq-by hash)

    # Build proof directory. Refuse to recursively delete a dir we didn't
    # create: `extract --out-dir .` (or any dir holding unrelated content)
    # would otherwise be wiped silently. Absent or empty is fine to (re)create;
    # a prior proof bundle (has manifest.json) is ours to overwrite.
    if ($out_dir | path exists) {
        let is_proof = ($out_dir | path join "manifest.json" | path exists)
        let is_empty = (ls --all $out_dir | is-empty)
        if not ($is_proof or $is_empty) {
            error make {msg: $"refusing to overwrite ($out_dir): not empty and not a proof bundle \(no manifest.json\). Remove it or choose another --out-dir."}
        }
        rm --recursive $out_dir
    }
    let objects_dir = ($out_dir | path join "objects")
    mkdir $objects_dir

    extract-loose-objects ($unique_objects | get hash) $objects_dir --repo $root

    # Copy pubkeys from target repo's multiproofs/pubkeys/
    let pubkeys_dir = ($out_dir | path join "pubkeys")
    mkdir $pubkeys_dir
    let repo_pubkeys = pubkeys-dir $root
    if ($repo_pubkeys | path exists) {
        glob ($repo_pubkeys | path join "*.pub") | each {|file| cp $file $pubkeys_dir }
    }

    # Write manifest
    let manifest = {
        version: 1
        object_format: "sha256"
        commit: $commit_hash
        tree: $tree_hash
        files: $target_files
        objects: ($unique_objects | select hash type)
        pubkeys: (ls $pubkeys_dir | get name | each { path basename })
    }
    $manifest | to json --indent 2 | save --force ($out_dir | path join "manifest.json")

    print $"Proof extracted to ($out_dir)/"
    print $"  Commit: ($commit_hash | str substring 0..12)..."
    print $"  Files: ($files | str join ', ')"
    print $"  Objects: ($unique_objects | length)"

    $manifest
}

# --- Verification ---

# Verify object integrity: git validates the SHA-256 hash on read,
# so any tampered object will fail cat-file.
def verify-object-hashes [
    repo: path
    objects: list<record<hash: string, type: string>>
]: nothing -> table<hash: string, valid: bool> {
    $objects | each {|obj|
        let result = (do { ^git --git-dir $repo cat-file -t $obj.hash } | complete)
        if $result.exit_code == 0 {
            {hash: $obj.hash valid: true type: ($result.stdout | str trim)}
        } else {
            {hash: $obj.hash valid: false error: ($result.stderr | str trim)}
        }
    }
}

# Walk a single file's merkle path through the tree, verifying each link.
# The chain commit → tree → ... → blob must be unbroken for the proof to hold.
def verify-file-path [
    repo: path
    tree_hash: string
    file_entry: record<path: string, hash: string>
]: nothing -> record<step: string, valid: bool> {
    let step = $"file ($file_entry.path)"
    try {
        let final = (walk-tree-path ["--git-dir" $repo] $tree_hash $file_entry.path | last | get hash)
        if $final == $file_entry.hash {
            {step: $step valid: true hash: $final}
        } else {
            {step: $step valid: false error: $"expected ($file_entry.hash), got ($final)"}
        }
    } catch {|e|
        {step: $step valid: false error: $e.msg}
    }
}

# Verify merkle paths: commit → root tree → each target file
def verify-merkle-paths [
    repo: path
    manifest: record
]: nothing -> list<record<step: string, valid: bool>> {
    let tree_hash = (^git --git-dir $repo cat-file -p $manifest.commit | parse-commit-tree)

    if $tree_hash != $manifest.tree {
        return [
            {
                step: "commit->tree"
                valid: false
                error: $"commit tree ($tree_hash) != manifest tree ($manifest.tree)"
            }
        ]
    }

    let file_results = $manifest.files | each { verify-file-path $repo $tree_hash $in }

    [{step: "commit->tree" valid: true hash: $tree_hash}] ++ $file_results
}

# Render the repo's pubkeys/ into an allowed_signers file usable by
# `git -c gpg.ssh.allowedSignersFile=<path> verify-commit`.
# Does not modify git config — the caller chooses how to wire it up.
export def "render-allowed-signers" [
    out: path # Output path for the rendered file
    --pubkeys-dir: path # Source directory of *.pub files (default: <git-root>/multiproofs/pubkeys)
] {
    let dir = if $pubkeys_dir != null { $pubkeys_dir | path expand } else {
        pubkeys-dir (repo-root)
    }

    let signers = (allowed-signers-body $dir --namespace "git" --wildcard)
    if ($signers | str trim | is-empty) {
        error make {msg: $"no *.pub files in ($dir)"}
    }

    $signers | save --force $out
    print $"Wrote ($out)"
    print "Use it without persisting git config:"
    print $"  git -c gpg.ssh.allowedSignersFile=($out) verify-commit HEAD"
}

# Verify commit signature against bundled pubkeys
def verify-signature [
    proof_dir: path
    manifest: record
    tmp_repo: path
]: nothing -> record<valid: bool> {
    let signers = (allowed-signers-body ($proof_dir | path join "pubkeys") --namespace "git" --wildcard)

    if ($signers | str trim | is-empty) {
        return {valid: false error: "no public keys in proof bundle"}
    }

    let signers_file = ($tmp_repo | path dirname | path join "allowed_signers")
    $signers | save --force $signers_file

    # Pass the signers file via -c so we don't persist git config in the temp repo
    let result = (
        do {
            ^git -c $"gpg.ssh.allowedSignersFile=($signers_file)" --git-dir $tmp_repo verify-commit $manifest.commit
        } | complete
    )
    let output = if ($result.stderr | str trim | is-not-empty) {
        $result.stderr | str trim
    } else {
        $result.stdout | str trim
    }

    if $result.exit_code == 0 {
        {valid: true detail: $output}
    } else {
        {valid: false error: $output}
    }
}

# Verify a proof bundle autonomously (without access to original repo)
export def verify [
    proof_dir: path = "proof" # Proof bundle directory
] {
    let manifest_path = ($proof_dir | path join "manifest.json")
    if not ($manifest_path | path exists) {
        error make {msg: $"manifest.json not found in ($proof_dir)/"}
    }
    let manifest = (open $manifest_path)
    let objects_dir = ($proof_dir | path join "objects")

    print "Verifying proof bundle..."
    print $"  Commit: ($manifest.commit | str substring 0..12)..."
    print $"  Files: ($manifest.files | length)"

    # Set up isolated SHA-256 repo with proof objects. Why one cleanup point:
    # a thrown error inside the checks (e.g. cat-file on a malformed object)
    # used to leak this temp dir and skip the remaining legs. Run the checks
    # in a try, remove the dir once, then rethrow.
    let tmp_dir = (^mktemp -d | str trim)
    let outcome = try {
        let tmp_repo = ($tmp_dir | path join "repo")
        ^git init --bare --object-format=sha256 $tmp_repo o+e>| ignore
        copy-loose-objects $objects_dir ($tmp_repo | path join "objects")

        # Step 1: Object integrity — git rejects any object whose content doesn't match its SHA-256 name
        print "\n1. Verifying object integrity..."
        let hash_results = (verify-object-hashes $tmp_repo $manifest.objects)
        let invalid = ($hash_results | where valid == false)

        if ($invalid | length) > 0 {
            print $"   FAIL: ($invalid | length) objects have invalid hashes"
            $invalid | each {|r| print $"     ($r.hash | str substring 0..12)...: ($r.error)" }
            {valid: false structure_valid: false error: "object hash verification failed"}
        } else {
            print $"   OK: all ($hash_results | length) objects verified"

            # Step 2: Merkle paths — the commit→tree→blob chain is unbroken for each target file
            print "\n2. Verifying merkle paths..."
            let path_results = (verify-merkle-paths $tmp_repo $manifest)
            let path_invalid = ($path_results | where valid == false)

            if ($path_invalid | length) > 0 {
                print "   FAIL: merkle path verification failed"
                $path_invalid | each {|r| print $"     ($r.step): ($r.error)" }
                {valid: false structure_valid: false error: "merkle path verification failed"}
            } else {
                $path_results | each {|r| print $"   OK: ($r.step)" }

                # Step 3: Signature — commit was signed by one of the bundled pubkeys
                print "\n3. Verifying commit signature..."
                let sig_result = (verify-signature $proof_dir $manifest $tmp_repo)
                if $sig_result.valid {
                    print $"   OK: ($sig_result.detail)"
                } else {
                    print $"   FAIL: ($sig_result.error)"
                }
                {
                    valid: $sig_result.valid
                    structure_valid: true
                    commit: $manifest.commit
                    files: $manifest.files
                    signature: $sig_result
                }
            }
        }
    } catch {|e|
        rm --recursive --force $tmp_dir
        error make {msg: $e.msg}
    }
    rm --recursive --force $tmp_dir

    # Why: callers checking only `.valid` must reject unsigned/wrongly-signed
    # bundles. `structure_valid` is exposed for callers that want each leg.
    if $outcome.valid {
        print "\nProof is VALID."
    } else if $outcome.structure_valid {
        print "\nProof is INVALID (structure ok, signature failed)."
    }
    $outcome
}
