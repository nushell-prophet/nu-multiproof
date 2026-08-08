# Compact merkle inclusion proofs over tree-hashes.csv (RFC 6962 shape).
#
# The CSV stays the authoritative catalogue; the tree root is a pure function
# of it, so anyone holding the full CSV rebuilds the same root. seal signs and
# stamps only the one-line root statement — a consumer then proves one file
# with its row + ~log2(n) sibling hashes instead of keeping the whole CSV.
# Tree spec: README.md "Merkle inclusion proofs"; primitives: _merkle-helpers.nu.

use _repo.nu repo-root
use _fs.nu [list-files list-dirs]
use _tracked.nu [content-tree resolve-leaf-file]
use _cid-helpers.nu node-cid
use _layout.nu [manifest-path merkle-root-path inclusion-proofs-dir pubkeys-dir ots-dir]
use _merkle-helpers.nu [
    MERKLE_SCHEMA load-leaves leaf-hash mth audit-path fold-path
    root-statement parse-root-statement validate-leaf
]
use _allowed-signers.nu check-signer-known
use _stamps.nu [scan-stamps pick-stamp]
use ssh-sign.nu
use ots.nu

# The refusal to follow a leaf path onto an object the catalogue cannot
# describe (symlink / outside / directory / missing) lives in _tracked.nu
# resolve-leaf-file, shared with content-tree's own enumeration — the builder
# must not be assumed to have run, and the verifier's file rows and its
# directory re-derivation must refuse identically.

# Content check for a row that attests no sha256 — a directory, or "." itself.
#
# These rows carry only a content_cid, and nothing ever recomputed it: the
# branch returned null and `valid` stayed true. So the strongest configuration
# this tool offers answered `valid: true` for a bundle carrying alice's genuine
# root, her genuine signature and her genuine proof of the `src` row, with the
# attacker's own tracked files in src/. A directory absent from disk entirely
# gave the same answer. Four of this repo's own 42 rows are that shape,
# including "." — the CID of the whole repo.
#
# The enumeration comes from disk, not from the manifest: a UnixFS directory
# commits to its entries, so a file added under it has to be noticed, and an
# added file is by definition not in the catalogue. `content-tree` walks
# `git ls-files` — the same walk tree-hashes used to build the row, because a
# directory CID is defined over the tracked tree and nothing else.
#
# What that scopes out, deliberately: an UNTRACKED file under the directory
# does not change the answer. It is not in the tracked tree, so it is not in
# the CID that was sealed, and it never was — the manifest has no opinion about
# untracked files anywhere in the repo. Making it a divergence would turn every
# build artifact into a failed verification. Note the consequence honestly: a
# directory verifying here means "the tracked contents are the sealed ones",
# not "nothing else sits in this directory", and `ipfs add` over the working
# tree would produce a different CID than the "." row whenever untracked files
# are present. Pinned by "an untracked file under a proven directory is outside
# what the row commits to".
#
# "unverifiable" when there is nothing to re-derive from — no git repo, or a
# leaf that commits to no content at all. A portable bundle (README "Verifying
# without the origin repo") carries no working tree, and validate-leaf permits
# a row whose content_cid is empty, which commits to nothing this can check. A
# row whose only commitment cannot be checked must not read as verified;
# returning null restores the exact hole this closes, and an attacker can ship
# a plain directory, or a hand-built manifest, as easily as a repo.
def derive-dir-cid [target: path, leaf: record]: nothing -> any {
    if $leaf.content_cid == "" { return "unverifiable" }
    # Why --show-toplevel compared against the target, and not
    # --is-inside-work-tree: that answers yes for any directory *under* a work
    # tree. A consumer who unpacks a genuine bundle inside any git repo — the
    # ordinary case — then had `git ls-files` run over the bundle path, which
    # lists whatever happens to be tracked there (usually nothing), and the
    # sealed, unmodified evidence was reported as tampered: `valid: false`,
    # "the directory's tracked contents differ from the sealed catalogue".
    # Claiming tampering about untouched evidence is the same defect class as
    # an explorer outage reading as an invalid proof. The manifest's paths are
    # relative to the repo root, so anything but the root is "unverifiable".
    let toplevel = do { ^git -C $target rev-parse --show-toplevel } | complete
    if $toplevel.exit_code != 0 { return "unverifiable" }
    if ($toplevel.stdout | str trim | path expand) != ($target | path expand) { return "unverifiable" }
    # A directory CID is a function of the whole subtree, so this reads every
    # tracked file. Only rows that attest no sha256 reach it — file rows keep
    # the single-file hash.
    # Why --lenient: the builder throws on a tracked path that no longer
    # resolves to a regular file inside the repo; here that disk state IS the
    # verdict. A proven directory swapped for a symlink reopens, one level up,
    # the containment hole resolve-leaf-file closes for file rows, and it must
    # be refused BEFORE any bytes are read — a MISMATCH/matches answer over
    # followed links doubles as an oracle about content the bundle does not
    # contain. Coarse by design: the problems cover the whole tracked tree,
    # not just this row's subtree — a partial re-derivation would need a
    # second, differing enumeration (see 785420b).
    let tree = content-tree $target --lenient
    if ($tree.problems | is-not-empty) { return $tree.problems.0.status }
    let node = $tree.nodes | get --optional $leaf.filepath
    if $node == null { return "missing" }
    ($node | node-cid) == $leaf.content_cid
}

# Build the tree from the manifest and write the root statement file
# (multiproofs/tree-root.txt) — the artifact seal signs and stamps.
@example "derive and record the merkle root" { nu-multiproof merkle write-root }
export def write-root [
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> record {
    let target = repo-root $repo
    let manifest = manifest-path $target
    let leaves = load-leaves $manifest
    # Why refuse a no-file manifest here, at the one place a root is minted:
    # the root of a tree with no tracked files is the same 64 hex for every
    # empty repo — sha256 of nothing for zero rows, and a constant
    # (ccc017f7de…) for the "." row build-tree now always appends over an
    # empty file set. A signature over that statement carries no repo in it,
    # so it replays into any other empty seal, and the OTS stamp then times an
    # attestation that says nothing. Reachable without trying: an empty repo,
    # and a bare repo, where `git ls-files` exits 0 with no output. Keyed on
    # "no rows besides '.'", not on zero rows: the unconditional "." append
    # bypassed the zero-row form of this guard one layer up.
    if ($leaves | where filepath != "." | is-empty) {
        error make {msg: $"($manifest) lists no files — the root of a no-file tree is the same for every empty repo, so signing it would state nothing about this one"}
    }
    let root_hex = mth ($leaves | each { leaf-hash $in }) | encode hex | str lowercase
    let out = merkle-root-path $target
    root-statement $root_hex | save --raw --force $out
    {root: $root_hex path: $out leaves: ($leaves | length)}
}

# Extract a compact inclusion proof for one manifest row. The consumer's full
# artifact set: this proof file + tree-root.txt + a .sig over it + the
# signer's pubkey (+ the tree-root OTS bundle for the time anchor).
@example "extract a compact inclusion proof" { nu-multiproof merkle prove README.md }
export def prove [
    filepath: string # Manifest row to prove (as listed in tree-hashes.csv; a trailing / is accepted for a directory row)
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> path {
    let target = repo-root $repo
    # A trailing slash reaches this argument from shell completion and never
    # from the manifest: `/` is the one byte a filename cannot contain, so no
    # row ends with one — `git ls-files` emits none and the "." row is appended
    # bare. So it is an artifact of the lookup KEY, trimmed here once for both
    # the row match and the output name. Normalizing it does not soften the
    # reject-never-normalize rule: the leaf written into the proof below still
    # comes from the matched row, never from this argument.
    let key = $filepath | str trim --right --char "/"
    # `/` and `//` trim to nothing, and the not-in-the-manifest throw below would
    # then name nothing either — a message that reads as if the argument were
    # missing rather than absolute. The repo root is the "." row, never "/".
    if ($key | is-empty) {
        error make {msg: $"($filepath) names no manifest row — paths are relative to the repo root, which is the \".\" row"}
    }
    let leaves = load-leaves (manifest-path $target)
    let hit = $leaves | enumerate | where item.filepath == $key
    if ($hit | is-empty) {
        error make {msg: $"($key) is not in the manifest — see `tree-hashes --echo` for listed paths"}
    }
    # The slash is one-way evidence, so it can only reject. Present, the caller
    # means a directory; absent, it says nothing at all, since `merkle prove
    # sub` is the equally ordinary way to ask for the same row — which is why
    # the trim above cannot instead be a rule that directory rows require it.
    # A file row under a directory argument is the caller and the catalogue
    # disagreeing about what that path IS, and handing back the file's proof
    # would answer a question nobody asked.
    if $key != $filepath and $hit.0.item.content_sha256 != "" {
        error make {msg: $"($filepath) names a directory, but the manifest lists ($key) as a file — drop the trailing slash to prove the file"}
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
    # Under multiproofs/ (excluded from the manifest), never next to the source
    # file — that would pollute the worktree and the next manifest. Not a
    # --out flag: nothing ever passed one, and `mv` is the escape hatch.
    # $key, not $filepath: a trailing slash here would write the hidden
    # inclusion-proofs/sub/.multiproof.json instead of sub.multiproof.json.
    let out = inclusion-proofs-dir $target | path join $"($key).multiproof.json"
    mkdir ($out | path dirname)
    $proof | to json --indent 2 | save --raw --force $out
    $out
}

# Verify an inclusion proof against the SIGNED root statement. Returns a
# result record, not a bare pass/fail:
#   valid            — structure ok AND the manifest (when present) rebuilding
#                      to the signed root AND an accepted signature AND content
#                      not contradicted. "Accepted" means >=1 valid signature from
#                      any key in --pubkeys-dir, or — with --signer — a valid
#                      signature from the key with that fingerprint.
#   structure_valid  — leaf hash folds up the path to the signed root
#   manifest_root    — the root rebuilt from tree-hashes.csv, or null when the
#                      manifest does not travel with the artifact (the portable
#                      bundle layout carries no CSV). A value differing from
#                      `root` means catalogue and signed statement are from
#                      different seals — blocks valid
#   content_verified — the on-disk content matches what the leaf attests: a
#                      file row against content_sha256, a directory row (and
#                      ".") against content_cid re-derived from the tracked
#                      files under it. Anything but true is a divergence from
#                      the catalogue, or a check that could not be made, and
#                      blocks valid either way: "missing" (absent on disk),
#                      "symlink" (a link where the catalogue describes a
#                      regular file), "outside" (resolves out of the repo
#                      through a symlinked parent), "directory" (a file row
#                      landing on a directory), "unverifiable" (nothing to
#                      re-derive the commitment from — the target is not a git
#                      repo root, or the row commits to no content at all)
#   signatures       — ssh-sign results over the root statement file
#   ots              — {status: absent|pending|anchored, ots, height} — a
#                      status, NOT pass/fail: a fresh seal stays pending for
#                      hours/days until Bitcoin confirms. `height` is the
#                      Bitcoin block the anchor binds to, null while pending.
#                      Offline check only; run
#                      `ots verify` for the independent Bitcoin block check.
#                      Dates the CONTENT: a stamp committing to tree-root.txt
#   endorsements     — one row {signer, status, ots, height} per signature that
#                      verified, saying when that endorsement was dated. Same
#                      status values, same offline-only caveat. An SSH
#                      signature carries no timestamp, so without a stamp over
#                      the signature itself a valid signature could have been
#                      made at any time — including after the key that made it
#                      was compromised. `absent` means the endorsement is real
#                      but undated. Signatures that did not verify get no row
# A proof whose embedded root differs from the signed root is a proof for a
# DIFFERENT seal — that throws loudly instead of reporting invalid.
#
# The default trust list ships inside the artifact under examination, so a
# default `valid: true` states "this bundle is internally consistent", not
# "the signer I expect endorsed this" — any key the bundle carries satisfies it,
# and anyone can fork a repo, `init` with their own key and re-`seal`.
# --pubkeys-dir points the check at a list the verifier holds; --signer names one
# key by fingerprint, which is a statement about key material and so holds even
# against the bundle's own list.
@example "verify a proof, failing on invalid (for CI)" { nu-multiproof merkle verify proof.json --fail }
export def verify [
    proof_file: path
    --repo: path # Target git repo root (default: git root of current directory)
    --pubkeys-dir: path # Trusted *.pub directory (default: multiproofs/pubkeys of the target — i.e. the bundle's own keys)
    --signer: string # Require a valid signature from the key with this fingerprint (see `pubkey fingerprint`)
    --fail # Exit non-zero when the result is not valid (for CI)
]: nothing -> record {
    # Why --signer no longer needs --pubkeys-dir, where it used to be refused
    # without it: a principal was the *stem of a .pub file*, so over the list
    # travelling inside the artifact `--signer alice` asked no more than "did a
    # file named alice.pub sign this" — and mallory's key copied in as alice.pub
    # answered `alice: valid`, `valid: true`. A principal is now the key's own
    # fingerprint, rendered from the key material rather than the file name, so
    # the same question is "did the holder of THIS key sign this" whichever
    # directory the key was read from. A bundle cannot rename a key into another
    # principal; the most it can do is not carry the key at all, which
    # check-signer-known reports as an error rather than a verdict. Pinned by
    # tests/test_merkle.nu "a bundle cannot file a key under another key's
    # fingerprint".
    let target = repo-root $repo
    # The trust list, settled before the artifact is even opened: it is the
    # verifier's own input, so a --signer this list holds no key for is an
    # operator error and must not be reported as something the proof failed.
    let trusted_dir = $pubkeys_dir | default (pubkeys-dir $target)
    if $signer != null { check-signer-known $signer $trusted_dir }

    let proof = open --raw $proof_file | from json
    if not ($proof | describe | str starts-with "record") {
        error make {msg: $"not a multiproof: ($proof_file) holds ($proof | describe) JSON, not a record"}
    }
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
    # key, re-seal, and any-key acceptance calls it valid. What makes the
    # narrowing real is where the compared name comes from: `$s.signer` is the
    # fingerprint of the key found inside the signature, so this compares key
    # material against the fingerprint the verifier typed.
    let signed_ok = if $signer != null {
        $sig_check.sigs | any {|s| $s.valid and $s.signer == $signer }
    } else {
        $sig_check.sigs | any { $in.valid }
    }

    # Content binding: without this the proof only shows the ROW was
    # catalogued, not that the on-disk FILE matches it.
    let target_file = $target | path join $proof.leaf.filepath
    let content_verified = if $proof.leaf.content_sha256 == "" {
        derive-dir-cid $target $proof.leaf
    } else {
        # Why a status and not null: null means "nothing to check". Every
        # status resolve-leaf-file returns is a real divergence from the sealed
        # catalogue — folded into null they yielded `valid: true`, misleading
        # consumers keying only on .valid.
        let resolved = resolve-leaf-file $target $proof.leaf.filepath
        if $resolved != "ok" {
            $resolved
        } else {
            (open --raw $target_file | hash sha256) == $proof.leaf.content_sha256
        }
    }

    # Stamps are discovered by content commitment (info.hash), never by bundle
    # name — stale bundles from previous seals are archival, so "no stamp
    # commits to THIS file" is absent, not invalid. One pass over every bundle,
    # because the same rule answers two questions: which stamp dates the root,
    # and which dates a given signature. Both now live in the same bundle
    # (`seal` stamps the signatures --into the root's), but nothing here depends
    # on that: a `.sig` stamped separately, or a bundle from before the merge, is
    # found by the same hash comparison. Filtering dirs by stem was an
    # optimization that would have excluded the endorsement anchors back when
    # they had bundles of their own — the comparison below is what decides, so
    # the filter only ever risked hiding evidence.
    let stamps = scan-stamps (ots-dir $target)

    let root_hash = open --raw $root_file | hash sha256
    let ots_status = pick-stamp ($stamps | where hash == $root_hash)

    # When each endorsement was made, one row per signature that actually
    # verified. An unverified signature is not an endorsement, so it gets no
    # row: an untrusted key's signature checks out cryptographically and comes
    # back with a principal attached, and listing it here would present
    # mallory's dated endorsement of your root beside the real one.
    #
    # Matched by hashing the signature file the verdict names — `sig` on the
    # row, so no second discovery pass and no re-verification. A stamp over a
    # signature says only "these bytes existed by T"; that it is an endorsement
    # OF THIS ROOT is what the signature check establishes, which is why both
    # halves have to hold before a row appears.
    let endorsements = $sig_check.sigs | where valid | each {|s|
        let sig_hash = open --raw $s.sig | hash sha256
        pick-stamp ($stamps | where hash == $sig_hash) | insert signer $s.signer
    }

    # No status branch returns null: only `$content_verified == true` passes.
    # A `== null` escape here once made "nothing checked" read as valid — the
    # fail-open hole 970f402 closed. Do not add one back for a new status.
    let valid = $structure_valid and $manifest_matches and $signed_ok and $content_verified == true
    let error = if not $structure_valid {
        "proof path does not fold to the signed root"
    } else if not $manifest_matches {
        $"($manifest) rebuilds to ($manifest_root), but the signed statement holds ($signed_root) — manifest and signed root are from different seals, so the signature covers neither this catalogue nor what a consumer would re-derive from it"
    } else if $content_verified == false and $proof.leaf.content_sha256 == "" {
        $"($proof.leaf.filepath) on disk does not reproduce the proven content_cid — the directory's tracked contents differ from the sealed catalogue"
    } else if $content_verified == false {
        $"on-disk ($proof.leaf.filepath) does not match the proven content_sha256"
    } else if $content_verified == "unverifiable" and $proof.leaf.content_cid == "" {
        $"($proof.leaf.filepath) commits to no content at all — the row carries neither a content_sha256 nor a content_cid, so there is nothing about it to check"
    } else if $content_verified == "unverifiable" {
        $"($proof.leaf.filepath) attests only a content_cid, and ($target) is not a git repository — a directory CID commits to every tracked entry under it, so there is nothing here to re-derive it from"
    } else if $content_verified == "missing" and $proof.leaf.content_sha256 == "" {
        # Two disk states share this verdict: a tracked file deleted from the
        # worktree (the ordinary mid-edit state, which used to crash the
        # re-derivation with a bare "Eval block failed"), and a row naming a
        # directory no tracked file sits under.
        $"($proof.leaf.filepath) is proven as a directory, but its sealed tracked content is not all on disk — a tracked file was deleted, or no tracked files sit under it at all"
    } else if $content_verified == "missing" {
        $"($proof.leaf.filepath) attests a content_sha256 but is absent on disk"
    } else if ($content_verified in ["symlink" "outside" "directory"]) and $proof.leaf.content_sha256 == "" {
        $"a tracked path under ($proof.leaf.filepath) does not resolve to a regular file inside ($target) \(($content_verified)\) — re-deriving the directory CID would read content the sealed catalogue does not describe"
    } else if $content_verified == "symlink" {
        $"($proof.leaf.filepath) is a symlink on disk, and the catalogue describes regular files only — following it would verify content this bundle does not carry"
    } else if $content_verified == "directory" {
        $"($proof.leaf.filepath) attests a content_sha256, but on disk it is a directory — no manifest this repo writes has that shape"
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
    print $"content:   (match $content_verified { true => 'matches', false => 'MISMATCH', 'missing' => 'MISSING (file absent on disk)', 'symlink' => 'SYMLINK (not a catalogued regular file)', 'outside' => 'OUTSIDE (resolves out of the repo)', 'directory' => 'DIRECTORY (a file row landing on a directory)', 'unverifiable' => 'UNVERIFIABLE (directory CID needs the tracked tree)' })"
    print $"ots:       ($ots_status.status)"
    for e in $endorsements {
        print $"endorsed:  ($e.status) — ($e.signer)"
    }

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
        endorsements: $endorsements
        error: $error
    }
}
