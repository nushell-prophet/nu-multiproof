# Compact merkle inclusion proofs over tree-hashes.csv (RFC 6962 shape).
#
# The CSV stays the authoritative catalogue; the tree root is a pure function
# of it, so anyone holding the full CSV rebuilds the same root. seal signs and
# stamps only the one-line root statement — a consumer then proves one file
# with its row + ~log2(n) sibling hashes instead of keeping the whole CSV.
# Tree spec: README.md "Merkle inclusion proofs"; primitives: _merkle-helpers.nu.

use _repo.nu repo-root
use _fs.nu [list-files list-dirs]
use _tracked.nu content-tree
use _cid-helpers.nu node-cid
use _layout.nu [manifest-path merkle-root-path inclusion-proofs-dir pubkeys-dir ots-dir MERKLE_ROOT_FILE]
use _merkle-helpers.nu [
    MERKLE_SCHEMA load-leaves leaf-hash mth audit-path fold-path
    root-statement parse-root-statement validate-leaf
]
use _allowed-signers.nu check-signer-known
use ssh-sign.nu
use ots.nu

# Where a leaf's filepath actually lands on disk, and whether that object is
# the kind of thing the catalogue can describe.
#
# validate-leaf constrains the path *text* — no leading "/", no ".." — but the
# text is not the object. `open --raw` follows links, so a bundle shipping
# `leaked.txt -> /home/victim/secret` alongside a row whose content_sha256 is
# the hash of the guessed content got `content_verified: true, valid: true`:
# the bundle "proved" it contains a file it does not contain, and doubled as a
# confirmation oracle for the verifier's own files. README's tree spec says
# "Symlinks: refused, never followed", but that refusal lived only in
# tree-hashes, the builder — a verifier must not assume the builder ran.
#
# Two distinct invariants, so two checks:
#   symlink — a manifest row describes one object, and a link is two (the link
#             and its target). tree-hashes refuses to catalogue one, so finding
#             one here means disk diverges from the catalogue. Checked before
#             existence: `path exists` is false for a broken link, which would
#             otherwise report the vaguer "missing".
#   outside — an intermediate component can be a link even when the final one
#             is a regular file (`a/b.txt` with `a -> /etc`). `path expand`
#             resolves the whole chain, so containment is checked on the
#             resolved path, not on the text validate-leaf already saw.
def resolve-leaf-file [target: path, filepath: string]: nothing -> record {
    let joined = $target | path join $filepath
    if ($joined | path type) == "symlink" {
        return {status: "symlink" path: $joined}
    }
    let real = $joined | path expand
    let root = $target | path expand
    if $real != $root and not ($real | str starts-with ($root + "/")) {
        return {status: "outside" path: $joined}
    }
    if not ($joined | path exists) {
        return {status: "missing" path: $joined}
    }
    {status: "ok" path: $joined}
}

# Content check for a row that attests no sha256 — a directory, or "." itself.
#
# These rows carry only a content_cid, and nothing ever recomputed it: the
# branch returned null and `valid` stayed true. So the strongest configuration
# this tool offers answered `valid: true` for a bundle carrying alice's genuine
# root, her genuine signature and her genuine proof of the `src` row, with the
# attacker's own files written into src/. A directory absent from disk entirely
# gave the same answer. Four of this repo's own 42 rows are that shape,
# including "." — the CID of the whole repo.
#
# The enumeration must come from disk, not from the manifest: a UnixFS
# directory commits to its entries, so a file the attacker ADDED is exactly
# what has to be noticed, and it is by definition not in the catalogue. That
# means git — content-tree walks `git ls-files`, the same walk tree-hashes
# used to build the row.
#
# Hence "unverifiable" when the target is not a git repo. A portable bundle
# (README "Verifying without the origin repo") carries no working tree, so a
# directory row has nothing to check against — and a row whose only commitment
# cannot be checked must not read as verified. Returning null there would
# restore the exact hole this closes, since an attacker can ship a plain
# directory as easily as a repo.
def derive-dir-cid [target: path, leaf: record]: nothing -> any {
    if $leaf.content_cid == "" { return null }
    let git_check = do { ^git -C $target rev-parse --is-inside-work-tree } | complete
    if $git_check.exit_code != 0 { return "unverifiable" }
    # A directory CID is a function of the whole subtree, so this reads every
    # tracked file. Only rows that attest no sha256 reach it — file rows keep
    # the single-file hash.
    let nodes = (content-tree $target).nodes
    let node = $nodes | get --optional $leaf.filepath
    if $node == null { return "missing" }
    ($node | node-cid) == $leaf.content_cid
}

# Build the tree from the manifest and write the root statement file
# (multiproofs/tree-root.txt) — the artifact seal signs and stamps.
@example "derive and record the merkle root" { merkle write-root }
export def write-root [
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> record {
    let target = repo-root $repo
    let manifest = manifest-path $target
    let leaves = load-leaves $manifest
    # Why refuse an empty manifest here, at the one place a root is minted:
    # `mth []` is sha256 of nothing (e3b0c442…b855) — the same 64 hex for every
    # empty repo. A signature over that statement carries no repo in it, so it
    # replays into any other empty seal, and the OTS stamp then times an
    # attestation that says nothing. Reachable without trying: an empty repo,
    # and a bare repo, where `git ls-files` exits 0 with no output.
    if ($leaves | is-empty) {
        error make {msg: $"($manifest) lists no files — an empty tree hashes to sha256\(\"\") for every repo, so signing that root would state nothing about this one"}
    }
    let root_hex = mth ($leaves | each { leaf-hash $in }) | encode hex | str lowercase
    let out = merkle-root-path $target
    root-statement $root_hex | save --raw --force $out
    {root: $root_hex path: $out leaves: ($leaves | length)}
}

# Extract a compact inclusion proof for one manifest row. The consumer's full
# artifact set: this proof file + tree-root.txt + a .sig over it + the
# signer's pubkey (+ the tree-root OTS bundle for the time anchor).
@example "extract a compact inclusion proof" { merkle prove README.md }
export def prove [
    filepath: string # Manifest row to prove (as listed in tree-hashes.csv)
    --repo: path # Target git repo root (default: git root of current directory)
    --out: path # Proof destination (default: multiproofs/inclusion-proofs/<filepath>.multiproof.json)
]: nothing -> path {
    let target = repo-root $repo
    let leaves = load-leaves (manifest-path $target)
    let hit = $leaves | enumerate | where item.filepath == $filepath
    if ($hit | is-empty) {
        error make {msg: $"($filepath) is not in the manifest — see `tree-hashes --echo` for listed paths"}
    }
    let leaf_hashes = $leaves | each { leaf-hash $in }
    let proof = {
        schema: $MERKLE_SCHEMA
        leaf: $hit.0.item
        path: (
            audit-path $leaf_hashes $hit.0.index
            | each {|step| {side: $step.side hash: ($step.hash | encode hex | str lowercase)} }
        )
        # Self-description only — verify trusts the SIGNED root file, never this copy
        root: (mth $leaf_hashes | encode hex | str lowercase)
    }
    # Default under multiproofs/ (excluded from the manifest), never next to
    # the source file — that would pollute the worktree and the next manifest.
    let out = if $out != null { $out } else {
        inclusion-proofs-dir $target | path join $"($filepath).multiproof.json"
    }
    mkdir ($out | path dirname)
    $proof | to json --indent 2 | save --raw --force $out
    print $"Proof: ($out)"
    $out
}

# Verify an inclusion proof against the SIGNED root statement. Returns a
# result record, not a bare pass/fail:
#   valid            — structure ok AND the manifest (when present) rebuilding
#                      to the signed root AND an accepted signature AND content
#                      not contradicted. "Accepted" means >=1 valid signature from
#                      any key in --pubkeys-dir, or — with --signer — a valid
#                      signature from that principal.
#   structure_valid  — leaf hash folds up the path to the signed root
#   manifest_root    — the root rebuilt from tree-hashes.csv, or null when the
#                      manifest does not travel with the artifact (the portable
#                      bundle layout carries no CSV). A value differing from
#                      `root` means catalogue and signed statement are from
#                      different seals — blocks valid
#   content_verified — the on-disk content matches what the leaf attests: a
#                      file row against content_sha256, a directory row (and
#                      ".") against content_cid re-derived from the tracked
#                      files under it. null only when the leaf attests nothing
#                      checkable. Anything else is a divergence from the
#                      catalogue and blocks valid, same as a mismatch:
#                      "missing" (absent on disk), "symlink" (a link where the
#                      catalogue describes a regular file), "outside"
#                      (resolves out of the repo through a symlinked parent),
#                      "unverifiable" (a directory row with no git repo to
#                      re-derive its CID from)
#   signatures       — ssh-sign results over the root statement file
#   ots              — {status: absent|pending|anchored, ots} — a status, NOT
#                      pass/fail: a fresh seal stays pending for hours/days
#                      until Bitcoin confirms. Offline check only; run
#                      `ots verify` for the independent Bitcoin block check.
# A proof whose embedded root differs from the signed root is a proof for a
# DIFFERENT seal — that throws loudly instead of reporting invalid.
#
# The default trust list ships inside the artifact under examination, so a
# default `valid: true` states "this bundle is internally consistent", not
# "the signer I expect endorsed this". --pubkeys-dir and --signer are how the
# verifier states, from outside the bundle, which keys it actually trusts.
@example "verify a proof, failing on invalid (for CI)" { merkle verify proof.json --fail }
export def verify [
    proof_file: path
    --repo: path # Target git repo root (default: git root of current directory)
    --pubkeys-dir: path # Trusted *.pub directory (default: multiproofs/pubkeys of the target — i.e. the bundle's own keys)
    --signer: string # Require a valid signature from this principal (pubkey stem). Needs --pubkeys-dir
    --fail # Exit non-zero when the result is not valid (for CI)
]: nothing -> record {
    # Why --signer needs --pubkeys-dir: a principal is the *stem of a .pub
    # file*, so it names a key only as strongly as the directory that file came
    # from. Over the default list — the one travelling inside the artifact —
    # `--signer alice` asks no more than "did a file named alice.pub sign
    # this". Measured before this guard: mallory's key copied in as alice.pub
    # gave `alice: valid`, `valid: true`. Refuse the combination rather than
    # return a verdict that reads as an identity check and is not one; naming
    # --pubkeys-dir (even at the bundle's own path) makes the trust list the
    # verifier's stated choice. Pinned by tests/test_merkle.nu "signer
    # flag against a bundle-supplied trust list is refused, not answered".
    if $signer != null and $pubkeys_dir == null {
        error make {msg: $"--signer ($signer) needs --pubkeys-dir: a principal is a .pub filename stem, and the default trust list travels inside the artifact — anyone can fork it and file their own key as ($signer).pub. Point --pubkeys-dir at a list you control."}
    }
    let target = repo-root $repo
    # The trust list, settled before the artifact is even opened: it is the
    # verifier's own input, so a --signer this list holds no key for is an
    # operator error and must not be reported as something the proof failed.
    let trusted_dir = $pubkeys_dir | default (pubkeys-dir $target)
    if $signer != null { check-signer-known $signer $trusted_dir }

    let proof = open --raw $proof_file | from json
    let schema = $proof | get --optional schema | default "missing"
    if $schema != $MERKLE_SCHEMA {
        error make {msg: $"unsupported proof schema: ($schema) — expected ($MERKLE_SCHEMA)"}
    }
    # Verifier-side injectivity guard: a forged leaf must fail here even if it
    # folds to the root (see _merkle-helpers.nu validate-leaf).
    validate-leaf $proof.leaf

    let root_file = merkle-root-path $target
    if not ($root_file | path exists) {
        error make {msg: $"root statement not found: ($root_file) — run `merkle write-root` or `seal`"}
    }
    let signed_root = parse-root-statement $root_file
    if $proof.root != $signed_root {
        error make {msg: $"proof is for a different seal: proof commits to ($proof.root), signed root is ($signed_root)"}
    }

    let folded = fold-path (leaf-hash $proof.leaf) $proof.path | encode hex | str lowercase
    let structure_valid = $folded == $signed_root

    # The signed statement is a claim ABOUT the manifest, and nothing checked
    # the two against each other — verify read the root out of tree-root.txt and
    # trusted it. `seal` writes the CSV and the statement in two steps, so an
    # interrupt between them (or a bare `tree-hashes` run afterwards) leaves a
    # catalogue no signature covers, while proofs of the PREVIOUS seal still
    # fold to the still-present old statement: valid: true, content_verified:
    # true, error: null. Not tighter writes in seal, because: two files cannot
    # be renamed in one step, so a verifier must not assume the writer finished.
    # null is "not here to check" — the portable bundle layout (README
    # "Verifying without the origin repo") carries no CSV. A manifest
    # load-leaves refuses (duplicate rows, control bytes, uppercase hex) throws
    # instead: an unreadable catalogue compares to nothing.
    # Pinned by tests/test_merkle.nu "a manifest that no longer yields the
    # signed root is caught".
    let manifest = manifest-path $target
    let manifest_root = if ($manifest | path exists) {
        mth (load-leaves $manifest | each { leaf-hash $in }) | encode hex | str lowercase
    } else { null }
    let manifest_matches = $manifest_root == null or $manifest_root == $signed_root

    # Signatures over the root statement (the authority). A consumer holding
    # only the structural proof gets a reported absence, not a crash — but
    # valid stays false without at least one valid signature.
    let sig_check = try {
        {sigs: (ssh-sign verify $root_file --pubkeys-dir $trusted_dir) error: null}
    } catch {|e| {sigs: [] error: $e.msg} }
    # Why --signer narrows this: `any { $in.valid }` is the right rule only when
    # the trust list came from outside. A list travelling inside the artifact
    # proves internal consistency, not identity — fork, re-init with your own
    # key, re-seal, and any-key acceptance calls it valid. The guard above is
    # what makes the narrowing real: $signer is only ever compared against
    # stems the verifier chose, never against names the artifact carries.
    let signed_ok = if $signer != null {
        $sig_check.sigs | any {|s| $s.valid and $s.signer == $signer }
    } else {
        $sig_check.sigs | any { $in.valid }
    }

    # Content binding: without this the proof only shows the ROW was
    # catalogued, not that the on-disk FILE matches it.
    let target_file = $target | path join $proof.leaf.filepath
    let resolved = resolve-leaf-file $target $proof.leaf.filepath
    let content_verified = if $proof.leaf.content_sha256 == "" {
        derive-dir-cid $target $proof.leaf
    } else if $resolved.status != "ok" {
        # Why a status and not null: null means "nothing to check" (directory
        # rows). Every status here is a real divergence from the sealed
        # catalogue — folded into null they yielded `valid: true`, misleading
        # consumers keying only on .valid.
        $resolved.status
    } else {
        (open --raw $target_file | hash sha256) == $proof.leaf.content_sha256
    }

    # OTS status for the root statement, discovered by content commitment
    # (info.hash), not by bundle name — stale bundles from previous seals are
    # archival, so "no stamp commits to THIS root" is absent, not invalid.
    let root_hash = open --raw $root_file | hash sha256
    let root_stem = $MERKLE_ROOT_FILE | path parse | get stem
    let matching_ots = list-dirs (ots-dir $target)
        | where {|d| ($d | path basename | str starts-with $"($root_stem).") }
        | each {|d| list-files $d --suffix ".ots" }
        | flatten
        | each {|f|
            # A corrupt/truncated archival .ots must not block verification of
            # an unrelated proof — skip it with a note and keep looking.
            let info = try { ots info $f } catch {|e|
                print $"note: skipping unparsable OTS file ($f): ($e.msg)"
                null
            }
            if $info != null and $info.hash == $root_hash {
                {file: $f type: $info.attestation.type}
            } else { null }
        }
    let ots_status = if ($matching_ots | is-empty) {
        {status: "absent" ots: null}
    } else {
        # Prefer an anchored match: listing order can put an archived
        # still-pending <stem>.<timestamp>.ots before the anchored <stem>.ots.
        let anchored = $matching_ots | where type == "bitcoin"
        let pick = if ($anchored | is-not-empty) { $anchored | first } else { $matching_ots | first }
        {status: (if $pick.type == "bitcoin" { "anchored" } else { "pending" }) ots: $pick.file}
    }

    let valid = $structure_valid and $manifest_matches and $signed_ok and ($content_verified == true or $content_verified == null)
    let error = if not $structure_valid {
        "proof path does not fold to the signed root"
    } else if not $manifest_matches {
        $"($manifest) rebuilds to ($manifest_root), but the signed statement holds ($signed_root) — manifest and signed root are from different seals, so the signature covers neither this catalogue nor what a consumer would re-derive from it"
    } else if $content_verified == false and $proof.leaf.content_sha256 == "" {
        $"($proof.leaf.filepath) on disk does not reproduce the proven content_cid — the directory's tracked contents differ from the sealed catalogue"
    } else if $content_verified == false {
        $"on-disk ($proof.leaf.filepath) does not match the proven content_sha256"
    } else if $content_verified == "unverifiable" {
        $"($proof.leaf.filepath) attests only a content_cid, and ($target) is not a git repository — a directory CID commits to every tracked entry under it, so there is nothing here to re-derive it from"
    } else if $content_verified == "missing" and $proof.leaf.content_sha256 == "" {
        $"($proof.leaf.filepath) is proven as a directory but no tracked files sit under it"
    } else if $content_verified == "missing" {
        $"($proof.leaf.filepath) attests a content_sha256 but is absent on disk"
    } else if $content_verified == "symlink" {
        $"($proof.leaf.filepath) is a symlink on disk, and the catalogue describes regular files only — following it would verify content this bundle does not carry"
    } else if $content_verified == "outside" {
        $"($proof.leaf.filepath) resolves outside ($target) through a symlinked parent — a proof cannot verify against content the bundle does not contain"
    } else if not $signed_ok {
        $sig_check.error | default (
            if $signer != null {
                $"no valid signature from signer ($signer) over the root statement \(trusted keys: ($trusted_dir)\)"
            } else {
                $"no valid signature over the root statement \(trusted keys: ($trusted_dir)\)"
            }
        )
    } else { null }

    print $"structure: (if $structure_valid { 'ok' } else { 'FAIL' }) \(($proof.path | length)-step path\)"
    print $"manifest:  (if $manifest_root == null { 'not present (nothing to cross-check)' } else if $manifest_matches { 'rebuilds to the signed root' } else { 'DESYNC (rebuilds to a different root)' })"
    print $"content:   (match $content_verified { true => 'matches', false => 'MISMATCH', 'missing' => 'MISSING (file absent on disk)', 'symlink' => 'SYMLINK (not a catalogued regular file)', 'outside' => 'OUTSIDE (resolves out of the repo)', 'unverifiable' => 'UNVERIFIABLE (directory CID needs the tracked tree)', null => 'not checked' })"
    print $"ots:       ($ots_status.status)"

    if $fail and not $valid {
        error make {msg: $"proof not valid: ($error)"}
    }
    {
        valid: $valid
        structure_valid: $structure_valid
        root: $signed_root
        manifest_root: $manifest_root
        leaf: $proof.leaf
        content_verified: $content_verified
        signatures: $sig_check.sigs
        ots: $ots_status
        error: $error
    }
}
