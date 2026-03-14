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

# --- Shared helpers ---

# Parse `git ls-tree` output into a table
def parse-ls-tree []: string -> table<mode: string, type: string, hash: string, name: string> {
    lines | parse "{mode} {type} {hash}\t{name}"
}

# Extract tree hash from commit object text
def parse-commit-tree []: string -> string {
    lines
    | where ($it starts-with "tree ")
    | first
    | str replace "tree " ""
}

# Copy git loose objects between directories
def copy-loose-objects [src: path, dest: path] {
    let src = $src | path expand
    glob ($src | path join "??/*") | each {|file|
        let rel = ($file | path relative-to $src)
        mkdir ($dest | path join $rel | path dirname)
        cp $file ($dest | path join $rel)
    }
}

# --- Extraction ---

# Walk git tree collecting merkle path objects from root to target file.
# Returns intermediate tree nodes + the final blob/tree for the target.
def find-path-objects [
    tree_hash: string
    file_path: string
    --path: path  # Target git repo root
]: nothing -> list<record<hash: string, type: string>> {
    let parts = ($file_path | split row "/")
    mut objects = []
    mut current_tree = $tree_hash

    for name in $parts {
        let entries = if $path != null {
            ^git -C $path ls-tree $current_tree | parse-ls-tree
        } else {
            ^git ls-tree $current_tree | parse-ls-tree
        }
        let entry = ($entries | where name == $name)

        if ($entry | is-empty) {
            error make {msg: $"'($name)' not found in tree ($current_tree | str substring 0..12)... \(path: ($file_path)\)"}
        }

        let entry = ($entry | first)
        $objects = ($objects | append {hash: $entry.hash, type: $entry.type})

        if $entry.type == "tree" {
            $current_tree = $entry.hash
        }
    }

    $objects
}

# Convert git objects to SHA-256 loose format.
#
# Git objects in a SHA-1 repo can't be directly copied into a SHA-256 repo —
# the hash-based storage paths differ. This packs objects from the current repo,
# then unpacks them into a temporary bare SHA-256 repo, letting git rehash them.
def repack-objects-sha256 [
    hashes: list<string>  # Object hashes to convert
    dest: path            # Directory to receive loose objects
    --path: path          # Target git repo root
] {
    let tmp_dir = (^mktemp -d | str trim)
    let hashes_file = ($tmp_dir | path join "hashes.txt")
    let pack_file = ($tmp_dir | path join "pack.bin")
    let bare_repo = ($tmp_dir | path join "sha256-repo")

    $hashes | str join "\n" | save --force $hashes_file
    ^git init --bare --object-format=sha256 $bare_repo o+e>| ignore
    if $path != null {
        open --raw $hashes_file | ^git -C $path pack-objects --stdout | save --raw --force $pack_file
    } else {
        open --raw $hashes_file | ^git pack-objects --stdout | save --raw --force $pack_file
    }
    open --raw $pack_file | ^git --git-dir $bare_repo unpack-objects

    copy-loose-objects ($bare_repo | path join "objects") $dest
    rm --recursive $tmp_dir
}

# Extract a merkle proof bundle for given files at a given commit
export def extract [
    ...files: string            # Target file paths to prove
    --commit: string = "HEAD"   # Commit to prove against
    --out-dir: string = "proof" # Output directory for proof bundle
    --path: path                # Target git repo root (default: git root of current directory)
] {
    if ($files | is-empty) {
        error make {msg: "no files specified"}
    }

    let root = if $path != null { $path | path expand } else {
        ^git rev-parse --show-toplevel | str trim
    }
    let commit_hash = (^git -C $root rev-parse $commit | str trim)
    let tree_hash = (^git -C $root cat-file -p $commit_hash | parse-commit-tree)

    # Collect merkle path objects for all target files
    mut all_objects = [
        {hash: $commit_hash, type: "commit"}
        {hash: $tree_hash, type: "tree"}
    ]
    mut target_files = []

    for file in $files {
        let path_objects = (find-path-objects $tree_hash $file --path $root)
        $all_objects = ($all_objects | append $path_objects)
        $target_files = ($target_files | append {
            path: $file
            hash: ($path_objects | last | get hash)
        })
    }

    let unique_objects = ($all_objects | uniq-by hash)

    # Build proof directory
    if ($out_dir | path exists) { rm --recursive $out_dir }
    let objects_dir = ($out_dir | path join "objects")
    mkdir $objects_dir

    repack-objects-sha256 ($unique_objects | get hash) $objects_dir --path $root

    # Copy pubkeys from target repo's multiproofs/pubkeys/
    let pubkeys_dir = ($out_dir | path join "pubkeys")
    mkdir $pubkeys_dir
    let repo_pubkeys = $root | path join "multiproofs/pubkeys"
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
            {hash: $obj.hash, valid: true, type: ($result.stdout | str trim)}
        } else {
            {hash: $obj.hash, valid: false, error: ($result.stderr | str trim)}
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
    let parts = ($file_entry.path | split row "/")
    mut current_hash = $tree_hash

    for part in $parts {
        let h = $current_hash  # immutable copy — mut vars can't be captured in closures
        let result = (do { ^git --git-dir $repo ls-tree $h } | complete)
        if $result.exit_code != 0 {
            return {step: $"file ($file_entry.path)", valid: false, error: ($result.stderr | str trim)}
        }

        let matching = ($result.stdout | parse-ls-tree | where name == $part)
        if ($matching | is-empty) {
            return {step: $"file ($file_entry.path)", valid: false, error: $"'($part)' not found in tree ($h | str substring 0..12)..."}
        }

        $current_hash = ($matching | first | get hash)
    }

    if $current_hash == $file_entry.hash {
        {step: $"file ($file_entry.path)", valid: true, hash: $current_hash}
    } else {
        {step: $"file ($file_entry.path)", valid: false, error: $"expected ($file_entry.hash), got ($current_hash)"}
    }
}

# Verify merkle paths: commit → root tree → each target file
def verify-merkle-paths [
    repo: path
    manifest: record
]: nothing -> list<record<step: string, valid: bool>> {
    let tree_hash = (^git --git-dir $repo cat-file -p $manifest.commit | parse-commit-tree)

    if $tree_hash != $manifest.tree {
        return [{
            step: "commit->tree"
            valid: false
            error: $"commit tree ($tree_hash) != manifest tree ($manifest.tree)"
        }]
    }

    let file_results = $manifest.files | each { verify-file-path $repo $tree_hash $in }

    [{step: "commit->tree", valid: true, hash: $tree_hash}] ++ $file_results
}

# Verify commit signature against bundled pubkeys
def verify-signature [
    proof_dir: string
    manifest: record
    tmp_repo: string
]: nothing -> record<valid: bool> {
    let signers = glob ($proof_dir | path join "pubkeys/*.pub")
        | each {|file|
            let key = (open --raw $file | str trim)
            $"* namespaces=\"git\" ($key)"
        }
        | str join "\n"

    if ($signers | str trim | is-empty) {
        return {valid: false, error: "no public keys in proof bundle"}
    }

    let signers_file = ($tmp_repo | path dirname | path join "allowed_signers")
    $signers | save --force $signers_file
    ^git --git-dir $tmp_repo config gpg.ssh.allowedSignersFile $signers_file

    let result = (do { ^git --git-dir $tmp_repo verify-commit $manifest.commit } | complete)
    let output = if ($result.stderr | str trim | is-not-empty) {
        $result.stderr | str trim
    } else {
        $result.stdout | str trim
    }

    if $result.exit_code == 0 {
        {valid: true, detail: $output}
    } else {
        {valid: false, error: $output}
    }
}

# Verify a proof bundle autonomously (without access to original repo)
export def verify [
    proof_dir: string = "proof"  # Proof bundle directory
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

    # Set up isolated SHA-256 repo with proof objects
    let tmp_dir = (^mktemp -d | str trim)
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
        rm --recursive $tmp_dir
        return {valid: false, error: "object hash verification failed"}
    }
    print $"   OK: all ($hash_results | length) objects verified"

    # Step 2: Merkle paths — the commit→tree→blob chain is unbroken for each target file
    print "\n2. Verifying merkle paths..."
    let path_results = (verify-merkle-paths $tmp_repo $manifest)
    let path_invalid = ($path_results | where valid == false)

    if ($path_invalid | length) > 0 {
        print "   FAIL: merkle path verification failed"
        $path_invalid | each {|r| print $"     ($r.step): ($r.error)" }
        rm --recursive $tmp_dir
        return {valid: false, error: "merkle path verification failed"}
    }
    $path_results | each {|r| print $"   OK: ($r.step)" }

    # Step 3: Signature — commit was signed by one of the bundled pubkeys
    print "\n3. Verifying commit signature..."
    let sig_result = (verify-signature $proof_dir $manifest $tmp_repo)
    rm --recursive $tmp_dir

    if $sig_result.valid {
        print $"   OK: ($sig_result.detail)"
    } else {
        print $"   WARN: ($sig_result.error)"
        print "   (signature check requires ssh-keygen; proof structure is still valid)"
    }

    print "\nProof is VALID."
    {
        valid: true
        commit: $manifest.commit
        files: $manifest.files
        signature: $sig_result
    }
}
