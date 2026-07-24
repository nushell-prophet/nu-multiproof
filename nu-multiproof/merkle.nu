# Compact merkle inclusion proofs over tree-hashes.csv (RFC 6962 shape).
#
# The CSV stays the authoritative catalogue; the tree root is a pure function
# of it, so anyone holding the full CSV rebuilds the same root. seal signs and
# stamps only the one-line root statement — a consumer then proves one file
# with its row + ~log2(n) sibling hashes instead of keeping the whole CSV.
# Tree spec: README.md "Merkle inclusion proofs"; primitives: _merkle-helpers.nu.

use _repo.nu repo-root
use _fs.nu [list-files list-dirs]
use _layout.nu [manifest-path merkle-root-path inclusion-proofs-dir pubkeys-dir ots-dir MERKLE_ROOT_FILE]
use _merkle-helpers.nu [
    MERKLE_SCHEMA load-leaves leaf-hash mth audit-path fold-path
    root-statement parse-root-statement validate-leaf
]
use ssh-sign.nu
use ots.nu

# Build the tree from the manifest and write the root statement file
# (multiproofs/tree-root.txt) — the artifact seal signs and stamps.
@example "derive and record the merkle root" { merkle root }
export def root [
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> record {
    let target = repo-root $repo
    let leaves = load-leaves (manifest-path $target)
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
# result record (mirrors git-proof verify), not a bare pass/fail:
#   valid            — structure ok AND an accepted signature AND content not
#                      contradicted. "Accepted" means >=1 valid signature from
#                      any key in --pubkeys-dir, or — with --signer — a valid
#                      signature from that principal.
#   structure_valid  — leaf hash folds up the path to the signed root
#   content_verified — on-disk file matches leaf.content_sha256; null when the
#                      leaf attests no sha256 (directory rows and oversized
#                      files attest only content_git); "missing" when the leaf
#                      attests one but the file is absent on disk — blocks
#                      valid, same as a mismatch
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
    --signer: string # Require a valid signature from this principal (pubkey stem), not merely from any registered key
    --fail # Exit non-zero when the result is not valid (for CI)
]: nothing -> record {
    let target = repo-root $repo
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
        error make {msg: $"root statement not found: ($root_file) — run `merkle root` or `seal`"}
    }
    let signed_root = parse-root-statement $root_file
    if $proof.root != $signed_root {
        error make {msg: $"proof is for a different seal: proof commits to ($proof.root), signed root is ($signed_root)"}
    }

    let folded = fold-path (leaf-hash $proof.leaf) $proof.path | encode hex | str lowercase
    let structure_valid = $folded == $signed_root

    # Signatures over the root statement (the authority). A consumer holding
    # only the structural proof gets a reported absence, not a crash — but
    # valid stays false without at least one valid signature.
    let trusted_dir = $pubkeys_dir | default (pubkeys-dir $target)
    let sig_check = try {
        {sigs: (ssh-sign verify $root_file --pubkeys-dir $trusted_dir) error: null}
    } catch {|e| {sigs: [] error: $e.msg} }
    # Why --signer narrows this: `any { $in.valid }` is the right rule only when
    # the trust list came from outside. A list travelling inside the artifact
    # proves internal consistency, not identity — fork, re-init with your own
    # key, re-seal, and any-key acceptance calls it valid.
    let signed_ok = if $signer != null {
        $sig_check.sigs | any {|s| $s.valid and $s.signer == $signer }
    } else {
        $sig_check.sigs | any { $in.valid }
    }

    # Content binding: without this the proof only shows the ROW was
    # catalogued, not that the on-disk FILE matches it.
    let target_file = $target | path join $proof.leaf.filepath
    let content_verified = if $proof.leaf.content_sha256 == "" {
        null
    } else if not ($target_file | path exists) {
        # Why "missing", not null: null means "nothing to check" (directory
        # rows). A deleted/renamed file is a real divergence from the sealed
        # catalogue — folded into null it yielded `valid: true` for a proof
        # whose file is gone, misleading consumers keying only on .valid.
        "missing"
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

    let valid = $structure_valid and $signed_ok and ($content_verified == true or $content_verified == null)
    let error = if not $structure_valid {
        "proof path does not fold to the signed root"
    } else if $content_verified == false {
        $"on-disk ($proof.leaf.filepath) does not match the proven content_sha256"
    } else if $content_verified == "missing" {
        $"($proof.leaf.filepath) attests a content_sha256 but is absent on disk"
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
    print $"content:   (match $content_verified { true => 'matches', false => 'MISMATCH', 'missing' => 'MISSING (file absent on disk)', null => 'not checked' })"
    print $"ots:       ($ots_status.status)"

    if $fail and not $valid {
        error make {msg: $"proof not valid: ($error)"}
    }
    {
        valid: $valid
        structure_valid: $structure_valid
        root: $signed_root
        leaf: $proof.leaf
        content_verified: $content_verified
        signatures: $sig_check.sigs
        ots: $ots_status
        error: $error
    }
}
