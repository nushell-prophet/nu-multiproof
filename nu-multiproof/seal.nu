use tree-hashes.nu
use merkle.nu
use ots.nu
use ssh-sign.nu
use _repo.nu repo-root
use _layout.nu [manifest-path merkle-root-path ots-dir pubkeys-dir]
use _sig.nu sig-files-for
use _key-helpers.nu with-signing-key

# Full seal pipeline: hash+root-cid → sign → stamp.
#
# Operations order:
#   1. Upgrade pending OTS — opportunistic; tries all .ots files, silent on failure
#      (Bitcoin confirmation takes hours/days, so this progresses previous seals)
#   2. tree-hashes — regenerate the manifest from current worktree files. With a
#      root CID, one `ipfs add -r` pass emits per-file, per-dir and the root "."
#      row together, so the manifest is written once, complete (--no-root-cid
#      uses the pure-nu path with no root row). Then derive the merkle root
#      statement (multiproofs/tree-root.txt) from the fresh manifest
#   3. ssh-sign — sign the root statement (--no-sign to skip)
#   4. ots stamp — timestamp the root statement (--no-stamp to skip)
#
# Committing is deliberately outside this pipeline. It's a user decision with
# context (message, scope, timing). Also avoids circularity: git-proof proves
# files existed in a signed commit, but seal artifacts would need to be in
# that commit — keeping them separate sidesteps the chicken-and-egg.
@example "full seal of the current repo" { seal }
@example "seal without IPFS or timestamping" { seal --no-root-cid --no-stamp }
export def main [
    --repo: path # Target git repo root (default: git root of current directory)
    --key: path # SSH private key (default: from git config user.signingKey)
    --no-root-cid # Skip IPFS root CID (on by default — opt out when ipfs CLI unavailable)
    --no-sign # Skip SSH signing (on by default — seal should be complete)
    --no-stamp # Skip OTS timestamping (on by default — seal should be complete)
    --publish-to-ipfs # Publish root CID to local IPFS daemon (default: only-hash, no daemon needed)
] {
    let root = repo-root $repo
    let manifest_path = manifest-path $root
    let root_statement_path = merkle-root-path $root
    let ots_dir = ots-dir $root

    # Fingerprint the signed artifact before regen: a sig covers exact bytes,
    # so it only goes stale when the bytes actually change. This is what lets
    # --no-sign mean "skip signing" instead of "remove still-valid signatures"
    # on an unchanged reseal (see the clearing step below).
    let sign_targets = [$root_statement_path]
    let pre_hashes = $sign_targets | each {|f|
        if ($f | path exists) { open --raw $f | hash sha256 } else { "" }
    }

    # 1. Upgrade pending OTS — every seal progresses previous seals automatically,
    #    so there's no need for a separate upgrade command
    if ($ots_dir | path exists) {
        glob ($ots_dir | path join "**/*.ots") | each {|ots_file|
            try { ots upgrade $ots_file } catch {|e|
                # Why: "not yet confirmed" is the normal case — Bitcoin
                # confirmation takes hours/days, so skip it quietly. Anything
                # else (corrupt proof, network misconfig, parse bug) is a real
                # problem; surface it instead of swallowing (fail-fast).
                if not ($e.msg | str contains "not yet confirmed") {
                    print $"upgrade failed for ($ots_file): ($e.msg)"
                }
            }
        }
    }

    # 2. Regenerate the manifest in one pass. With a root CID, --ipfs computes
    #    per-file, per-dir AND the root "." row together (build-tree/B2); the
    #    manifest is written once, complete, before any signature exists.
    #    --no-root-cid falls back to the pure-nu path (no daemon).
    mut result = {manifest: $manifest_path}
    if $no_root_cid {
        tree-hashes --repo $root
    } else {
        let root_cid = tree-hashes root-cid --repo $root --publish-to-ipfs=$publish_to_ipfs
        print $"Root CID: ($root_cid)"
        $result = ($result | insert root_cid $root_cid)
    }
    print $"Manifest: ($manifest_path)"

    # Derive the merkle root statement from the fresh manifest — the compact
    # signing target: consumers verify per-file inclusion proofs against this
    # 32-byte commitment instead of keeping the whole CSV (see merkle.nu).
    # Immediately after regen, so no window where the statement describes a
    # previous manifest.
    let merkle_result = merkle root --repo $root
    print $"Merkle root: ($merkle_result.root)"
    $result = ($result | insert merkle_root $merkle_result.root)

    # Why: a sig from a previous seal signs the previous bytes — stale exactly
    # when regen changed them. Clear those before step 3 signs fresh; sigs
    # over unchanged bytes are still valid and survive (so --no-sign doesn't
    # behave as "remove signatures"). Uses the shared discovery so the bare
    # `.sig` form is cleared too, not just `.<signer>.sig`.
    $sign_targets | zip $pre_hashes | each {|pair|
        if (open --raw $pair.0 | hash sha256) != $pair.1 {
            sig-files-for $pair.0 | each {|sig| rm $sig }
        }
    }

    # Legacy cleanup: the CSV itself is no longer signed (the root statement
    # covers every row — see step 3), so a live manifest sig can only be a
    # leftover from the transition era. Delete it rather than leave a stale
    # artifact; frozen copies inside OTS bundle dirs stay — they're archival.
    # Tag pre-drop-manifest-sig marks the last version that produced them.
    sig-files-for $manifest_path | each {|sig| rm $sig }

    # 3. Sign the root statement — the one signed artifact. The root is
    # derived from every manifest row (the "." root-CID row included), so it
    # authenticates the full CSV indirectly: rebuild the tree, compare roots.
    # The transitional whole-CSV signature was dropped as unneeded legacy.
    if not $no_sign {
        # Why resolve here and not let `ssh-sign sign` do it: the key comes from
        # --repo's git config, and ssh-sign reads the CWD's repo. The closure
        # form bounds an inline `key::` temp file to the signing call.
        # Why pass pubkeys-dir explicitly: ssh-sign sign defaults to the CWD's
        # git root, but seal may target a different repo via --repo.
        let root_sig = with-signing-key --key $key --root $root {|signing_key|
            ssh-sign sign $root_statement_path --key $signing_key --pubkeys-dir (pubkeys-dir $root)
        }
        $result = ($result | insert root_sig $root_sig)
    }

    # 4. OTS timestamp — anchors the root statement to Bitcoin. The manifest
    # is not stamped: the root is derived from every row, so its anchor
    # time-bounds the full CSV — the same argument that dropped the whole-CSV
    # signature. Archival tree-hashes.* bundles from the stamping era stay.
    # Why pass out-dir explicitly: ots stamp defaults it to the CWD's git root,
    # but seal may target a different repo via --repo (same fix as pubkeys-dir
    # in step 3). Without it, `seal --repo /other` writes the bundle into the
    # CWD's repo, or fails when CWD is not a repo.
    if not $no_stamp {
        let root_stamp = ots stamp $root_statement_path --out-dir $ots_dir
        $result = ($result | insert root_ots $root_stamp.ots)
    }

    $result
}
