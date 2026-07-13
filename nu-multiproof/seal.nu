# Full seal pipeline: hash+root-cid → sign → stamp.
#
# Operations order:
#   1. Upgrade pending OTS — opportunistic; tries all .ots files, silent on failure
#      (Bitcoin confirmation takes hours/days, so this progresses previous seals)
#   2. tree-hashes — regenerate the manifest from current worktree files. With a
#      root CID, one `ipfs add -r` pass emits per-file, per-dir and the root "."
#      row together, so the manifest is written once, complete (--no-root-cid
#      uses the pure-nu path with no root row)
#   3. ssh-sign — sign the manifest (on by default; --no-sign to skip)
#   4. ots stamp — timestamp the manifest (on by default; --no-stamp to skip)
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
    use tree-hashes.nu
    use ots.nu
    use ssh-sign.nu
    use _repo.nu repo-root
    use _layout.nu [manifest-path ots-dir pubkeys-dir]
    use _sig.nu sig-files-for
    use _key-helpers.nu resolve-signing-key

    let root = repo-root $repo
    let manifest_path = manifest-path $root
    let ots_dir = ots-dir $root

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

    # Why: a sig from a previous seal signs the now-regenerated (stale) manifest.
    # Clear it before step 4 signs fresh. Uses the shared discovery so the bare
    # `<manifest>.sig` form is cleared too, not just `<manifest>.<signer>.sig`.
    sig-files-for $manifest_path | each {|sig| rm $sig }

    # 3. Sign the manifest — covers root CID via the "." row
    if not $no_sign {
        let signing_key = if $key != null { $key | into string } else { resolve-signing-key --root $root }
        # Why pass pubkeys-dir explicitly: ssh-sign sign defaults to the CWD's
        # git root, but seal may target a different repo via --repo.
        let sig = ssh-sign sign $manifest_path --key $signing_key --pubkeys-dir (pubkeys-dir $root)
        $result = ($result | insert sig $sig)
    }

    # 4. OTS timestamp — anchors the manifest (with root CID) to Bitcoin
    # Why pass out-dir explicitly: ots stamp defaults it to the CWD's git root,
    # but seal may target a different repo via --repo (same fix as pubkeys-dir
    # in step 4). Without it, `seal --repo /other` writes the bundle into the
    # CWD's repo, or fails when CWD is not a repo.
    if not $no_stamp {
        let stamp_result = ots stamp $manifest_path --out-dir $ots_dir
        $result = ($result | insert ots $stamp_result.ots)
    }

    $result
}
