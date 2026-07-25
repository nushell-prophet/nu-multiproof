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
use _temp-helpers.nu with-temp-dir
use _fs.nu [list-files list-dirs]
use _allowed-signers.nu allowed-signers-body

# --- Shared helpers ---

# A SHA-256 object id, as git writes it. Bundles are untrusted input and every
# oid in one reaches git as a command-line argument, where a value starting
# with `-` is read as an option: `git verify-commit --help` exits 0 and prints
# a man page, so `manifest.commit = "--help"` would have produced
# {valid: true, detail: <man page>}. Today that is unreachable only because an
# earlier `cat-file` happens to run first and fail.
export const OID_PATTERN = '^[0-9a-f]{64}$'

# Refuse an oid-shaped manifest field that is not an oid, naming the field.
def check-oid [value: any field: string]: nothing -> string {
    if ($value | describe) != "string" or not ($value =~ $OID_PATTERN) {
        error make {msg: $"manifest ($field) is not a SHA-256 object id: ($value | to nuon)"}
    }
    $value
}

# Parse `git ls-tree -z` output into a table.
# Why -z: with git's default core.quotePath=true, plain `ls-tree` C-quotes any
# name holding non-ASCII bytes or a `"` — `файл.md` comes back as
# "\321\204\320\260\320\271\320\273.md", so a lookup by the raw name never
# matches and the file reads as missing from its own tree. NUL-terminated
# records carry the path bytes exactly as git stored them.
def parse-ls-tree []: string -> table<mode: string, type: string, hash: string, name: string> {
    split row (char -i 0) | where { $in != "" } | parse "{mode} {type} {hash}\t{name}"
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

# Loose object files under an objects/ directory: `<2 hex chars>/<rest of oid>`.
# Packed objects live in `pack/` and are deliberately not matched — everything
# this module produces and reads is loose.
def loose-object-files [objects_dir: path]: nothing -> list<path> {
    list-dirs $objects_dir
    | where {|d| ($d | path basename | str length) == 2 }
    | each {|d| list-files $d }
    | flatten
}

# Copy git loose objects between directories
def copy-loose-objects [src: path dest: path] {
    let src = $src | path expand
    loose-object-files $src | each {|file|
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
        let result = (do { ^git ...$git_args ls-tree -z $tree } | complete)
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

# Extract loose objects from the source repo into a fresh SHA-256 bare repo,
# then copy them out.
#
# The SHA-256 object format is hardcoded, not read from the source: `extract`
# already refuses any repo whose extensions.objectFormat is not sha256, so the
# two always agree.
def extract-loose-objects [
    hashes: list<string> # Object hashes to extract
    dest: path # Directory to receive loose objects
    --repo: path # Target git repo root
] {
    # Why with-temp-dir: a bare `rm` after the externals is never reached when
    # pack-objects or unpack-objects throws, leaking the dir.
    with-temp-dir "git-proof-extract" {|tmp_dir|
        let hashes_file = ($tmp_dir | path join "hashes.txt")
        let pack_file = ($tmp_dir | path join "pack.bin")
        let bare_repo = ($tmp_dir | path join "bare-repo")

        $hashes | str join "\n" | save --force $hashes_file
        ^git init --bare --object-format=sha256 $bare_repo o+e>| ignore
        open --raw $hashes_file | ^git -C $repo pack-objects --stdout | save --raw --force $pack_file
        open --raw $pack_file | ^git --git-dir $bare_repo unpack-objects

        copy-loose-objects ($bare_repo | path join "objects") $dest
    }
}

# Extract a merkle proof bundle for given files at a given commit
@example "prove a file existed in HEAD" { git-proof extract src/main.rs }
export def extract [
    ...files: string # Target file paths to prove
    --commit: string = "HEAD" # Commit to prove against
    --out-dir: path = "proof" # Bundle output dir, relative to the CWD (not --repo): it's a portable artifact to ship, not part of the repo
    --repo: path # Target git repo root (default: git root of current directory)
] {
    if ($files | is-empty) {
        error make {msg: "no files specified"}
    }

    let root = repo-root $repo
    # Why refuse rather than emit a SHA-1 bundle: nothing here converts hashes —
    # a SHA-1 source could produce a native SHA-1 bundle if the three hardcoded
    # --object-format=sha256 sites read the format instead. The blocker is that
    # the proof would then rest on SHA-1 collision resistance: chosen-prefix
    # collisions have been practical since 2019, so one path from a signed commit
    # to a blob can be made to fit a second, different blob. Git's sha1dc
    # detection catches known techniques, which is a patch, not a proof.
    # git writes extensions.objectFormat only for sha256 repos; absent means sha1.
    let declared = (^git -C $root config extensions.objectFormat | complete | get stdout | str trim)
    let src_format = if ($declared | is-empty) { "sha1" } else { $declared }
    if $src_format != "sha256" {
        error make {msg: $"git-proof requires a SHA-256 repo \(extensions.objectFormat=sha256\); source is '($src_format)' — a SHA-1 merkle path is not accepted as evidence"}
    }
    # --end-of-options: `--commit` is whatever the caller typed, and a rev
    # starting with `-` is read as an option. --verify keeps the output to the
    # single object name (bare rev-parse echoes flags it does not recognise).
    let commit_hash = (^git -C $root rev-parse --verify --end-of-options $commit | str trim)
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
        list-files $repo_pubkeys --suffix ".pub" | each {|file| cp $file $pubkeys_dir }
    }

    # Write manifest
    let manifest = {
        version: 1
        object_format: "sha256"
        commit: $commit_hash
        tree: $tree_hash
        files: $target_files
        objects: ($unique_objects | select hash type)
        # Why --all: the copy above is a glob, which matches dotfiles, so plain
        # `ls` listed fewer keys than the bundle actually carries.
        pubkeys: (ls --all $pubkeys_dir | get name | each { path basename })
    }
    $manifest | to json --indent 2 | save --force ($out_dir | path join "manifest.json")

    print $"Proof extracted to ($out_dir)/"
    print $"  Commit: ($commit_hash | str substring 0..12)..."
    print $"  Files: ($files | str join ', ')"
    print $"  Objects: ($unique_objects | length)"

    $manifest
}

# --- Verification ---

# Verify object integrity by re-hashing every object and comparing to its oid.
# Why not trust `git cat-file`: it does NOT re-hash loose objects — a file
# swapped under the same oid name reads back as the wrong content with exit 0,
# so `cat-file -t` alone would pass a tampered bundle. Why not `git fsck`: it
# rejects a legitimate partial bundle, reporting the unbundled sibling objects
# a merkle proof deliberately omits as broken links. Re-hashing each object with
# `git hash-object` is the one check that catches altered content without
# flagging those intentionally-absent siblings.
#
# Why the object set comes from the filesystem, not manifest.json: the manifest
# ships INSIDE the bundle, so whoever tampers with an object also controls the
# list naming it. Dropping the tampered oid from `objects` (or emptying the
# list outright) walked this check straight past it, while the merkle walk below
# still read the tampered bytes through `git cat-file`. Enumerating what is
# physically present makes the verified set a superset of everything the walk
# can possibly read — `copy-loose-objects` only ever brings in `??/*`, so
# nothing else is reachable. manifest.objects is now descriptive only.
def verify-object-hashes [repo: path]: nothing -> table<hash: string, valid: bool> {
    loose-object-files ($repo | path join "objects") | each {|file|
        let oid = $"($file | path dirname | path basename)($file | path basename)"
        # The oid comes from a file name inside the bundle, and goes to git as an
        # argument: `objects/--/help` would call `git cat-file -t --help`, which
        # exits 0 with a man page. An object git could never have written is an
        # invalid object, not an error — the bundle is what fails.
        if not ($oid =~ $OID_PATTERN) {
            return {hash: $oid valid: false error: "not a SHA-256 object id"}
        }
        let type_result = (do { ^git --git-dir $repo cat-file -t $oid } | complete)
        if $type_result.exit_code != 0 {
            {hash: $oid valid: false error: ($type_result.stderr | str trim)}
        } else {
            # Recompute the oid from the stored bytes. git derives it from scratch,
            # so a mismatch means the object's content was altered under its name.
            let type = ($type_result.stdout | str trim)
            let recomputed = (do {
                ^git --git-dir $repo cat-file $type $oid | ^git --git-dir $repo hash-object -t $type --stdin
            } | complete)
            let rehashed = ($recomputed.stdout | str trim)
            if $recomputed.exit_code == 0 and $rehashed == $oid {
                {hash: $oid valid: true type: $type}
            } else {
                {hash: $oid valid: false error: $"content does not hash to its name \(recomputed ($rehashed | str substring 0..12)...\)"}
            }
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
@example "render pubkeys into an allowed_signers file" { git-proof render-allowed-signers /tmp/allowed_signers }
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

# Verify a proof bundle autonomously (without access to original repo).
# Returns a uniform record {valid, structure_valid, commit, files, signature,
# error}. --fail turns an invalid proof into a non-zero exit (for CI), instead
# of returning {valid: false} with exit 0 that a caller might not inspect.
@example "verify a bundle, failing on invalid (for CI)" { git-proof verify proof --fail }
export def verify [
    proof_dir: path = "proof" # Proof bundle directory
    --fail # Exit non-zero on an invalid proof (for CI)
] {
    let manifest_path = ($proof_dir | path join "manifest.json")
    if not ($manifest_path | path exists) {
        error make {msg: $"manifest.json not found in ($proof_dir)/"}
    }
    let manifest = (open $manifest_path)
    # Read the format the bundle declares before trusting anything in it. Errors,
    # not {valid: false}: a bundle this verifier cannot read is the same category
    # as a missing manifest.json — not a proof that failed. Without the check, a
    # future v2 (or SHA-1) bundle would be read as v1 and fail downstream as
    # "content does not hash to its name", blaming the objects for a format
    # mismatch. Checked before the temp repo is built, which hardcodes sha256.
    let version = ($manifest | get --optional version | default "missing")
    if $version != 1 {
        error make {msg: $"unsupported proof bundle version: ($version) — expected 1"}
    }
    let object_format = ($manifest | get --optional object_format | default "missing")
    if $object_format != "sha256" {
        error make {msg: $"unsupported object format: ($object_format) — expected sha256"}
    }
    # Why an error, not {valid: false}: a bundle claiming no files is malformed,
    # the same category as a missing manifest.json — not a proof that failed.
    # Every check below passes vacuously on it (objects re-hash fine, the
    # commit->tree link holds, the commit signature is genuine), so it used to
    # report `valid: true` for a proof of nothing. `extract` already refuses an
    # empty file list; the verifier must not accept what the producer can't emit.
    # The shape before the values: a manifest is untrusted input, and `files`
    # holding a bare string reached `$entry | get --optional hash` as a raw
    # "only supports list, table, record" failure — a nushell error about the
    # verifier, where the operator needed one about the bundle.
    let files = ($manifest | get --optional files)
    if ($files | describe --detailed | get type) != "list" {
        error make {msg: $"($proof_dir)/manifest.json: files is not a list, it is ($files | describe)"}
    }
    if ($files | is-empty) {
        error make {msg: $"($proof_dir)/manifest.json lists no files — the bundle proves nothing"}
    }
    # Every manifest value that reaches git as an argument, checked once, here.
    check-oid ($manifest | get --optional commit) "commit"
    check-oid ($manifest | get --optional tree) "tree"
    for entry in $files {
        if ($entry | describe --detailed | get type) != "record" {
            error make {msg: $"($proof_dir)/manifest.json: files entry is not a record: ($entry | to nuon)"}
        }
        check-oid ($entry | get --optional hash) $"files hash for ($entry | get --optional path | default '?')"
    }
    let objects_dir = ($proof_dir | path join "objects")

    print "Verifying proof bundle..."
    print $"  Commit: ($manifest.commit | str substring 0..12)..."
    print $"  Files: ($manifest.files | length)"

    # Set up isolated SHA-256 repo with proof objects. Why with-temp-dir: a
    # thrown error inside the checks (e.g. cat-file on a malformed object) used
    # to leak this temp dir and skip the remaining legs.
    let outcome = with-temp-dir "git-proof-verify" {|tmp_dir|
        let tmp_repo = ($tmp_dir | path join "repo")
        ^git init --bare --object-format=sha256 $tmp_repo o+e>| ignore
        copy-loose-objects $objects_dir ($tmp_repo | path join "objects")

        # Step 1: Object integrity — every object physically in the bundle must
        # hash to the name it is stored under
        print "\n1. Verifying object integrity..."
        let hash_results = (verify-object-hashes $tmp_repo)
        let invalid = ($hash_results | where valid == false)

        # Uniform record shape across every exit (kinder to scripts than the old
        # structure-fail returns that lacked commit/files/signature).
        let base = {commit: $manifest.commit files: $manifest.files signature: null error: null}
        if ($invalid | length) > 0 {
            print $"   FAIL: ($invalid | length) objects have invalid hashes"
            $invalid | each {|r| print $"     ($r.hash | str substring 0..12)...: ($r.error)" }
            $base | merge {valid: false structure_valid: false error: "object hash verification failed"}
        } else {
            print $"   OK: all ($hash_results | length) objects verified"

            # Step 2: Merkle paths — the commit→tree→blob chain is unbroken for each target file
            print "\n2. Verifying merkle paths..."
            let path_results = (verify-merkle-paths $tmp_repo $manifest)
            let path_invalid = ($path_results | where valid == false)

            if ($path_invalid | length) > 0 {
                print "   FAIL: merkle path verification failed"
                $path_invalid | each {|r| print $"     ($r.step): ($r.error)" }
                $base | merge {valid: false structure_valid: false error: "merkle path verification failed"}
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
                $base | merge {valid: $sig_result.valid structure_valid: true signature: $sig_result}
            }
        }
    }

    # Why: callers checking only `.valid` must reject unsigned/wrongly-signed
    # bundles. `structure_valid` is exposed for callers that want each leg.
    if $outcome.valid {
        print "\nProof is VALID."
    } else if $outcome.structure_valid {
        print "\nProof is INVALID (structure ok, signature failed)."
    } else {
        print "\nProof is INVALID (structure verification failed)."
    }

    if $fail and not $outcome.valid {
        error make {msg: $"proof invalid: ($outcome.error | default 'signature verification failed')"}
    }
    $outcome
}
