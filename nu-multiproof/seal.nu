# Resolve SSH signing key from git config (file path or inline key::).
# Why: `ssh-sign sign` derives the signer name from multiproofs/pubkeys/ when
# --name is omitted, so we return just the key path here.
def resolve-signing-key [root: path]: nothing -> record<key: string> {
    let git_key = (do { ^git -C $root config user.signingKey } | complete)
    if $git_key.exit_code != 0 {
        error make {msg: "no git signing key configured — use --no-sign or set user.signingKey"}
    }
    let raw = $git_key.stdout | str trim
    if ($raw | str starts-with "key::") {
        let key_data = $raw | str replace "key::" ""
        let tmp = $nu.temp-dir | path join "seal-signing-key.pub"
        $key_data | save --raw --force $tmp
        {key: $tmp}
    } else {
        let expanded = $raw | path expand
        let key_path = if ($expanded | path exists) {
            $expanded
        } else if ($"($expanded).pub" | path exists) {
            $"($expanded).pub"
        } else {
            error make {msg: $"signing key not found: ($raw)"}
        }
        {key: ($key_path | into string)}
    }
}

# Full seal pipeline: hash → root-cid → sign → stamp.
#
# Operations order:
#   1. Upgrade pending OTS — opportunistic; tries all .ots files, silent on failure
#      (Bitcoin confirmation takes hours/days, so this progresses previous seals)
#   2. tree-hashes — regenerate manifest from current worktree files
#   3. root-cid — compute IPFS root CID, append "." row to manifest
#   4. ssh-sign — sign the manifest (on by default; --no-sign to skip)
#   5. ots stamp — timestamp the manifest (on by default; --no-stamp to skip)
#
# Committing is deliberately outside this pipeline. It's a user decision with
# context (message, scope, timing). Also avoids circularity: git-proof proves
# files existed in a signed commit, but seal artifacts would need to be in
# that commit — keeping them separate sidesteps the chicken-and-egg.
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

    let root = if $repo != null { $repo | path expand } else {
        ^git rev-parse --show-toplevel | str trim
    }
    let manifest_path = $root | path join "multiproofs/tree-hashes.csv"
    let ots_dir = $root | path join "multiproofs/ots-timestamps"

    # 1. Upgrade pending OTS — every seal progresses previous seals automatically,
    #    so there's no need for a separate upgrade command
    if ($ots_dir | path exists) {
        glob ($ots_dir | path join "**/*.ots") | each {|ots_file|
            try { ots upgrade $ots_file } catch { }
        }
    }

    # 2. Regenerate manifest — must precede root-cid (provides the file list)
    tree-hashes --repo $root
    print $"Manifest: multiproofs/tree-hashes.csv"

    # Why: sigs from a previous seal sign the old manifest; root-cid refuses
    # to clobber them. seal owns the regeneration flow — clear stale sigs so
    # step 4 (sign) can produce fresh ones against the new manifest.
    glob $"($manifest_path).*.sig" | each {|sig| rm $sig }

    mut result = {manifest: $manifest_path}

    # 3. Compute root CID — single IPFS hash covering all manifest files
    if not $no_root_cid {
        let root_cid = tree-hashes root-cid --repo $root --publish-to-ipfs=$publish_to_ipfs
        print $"Root CID: ($root_cid)"
        $result = ($result | insert root_cid $root_cid)
    }

    # 4. Sign the manifest — covers root CID via the "." row
    if not $no_sign {
        let resolved = if $key != null {
            {key: ($key | into string)}
        } else {
            resolve-signing-key $root
        }
        # Why pass pubkeys-dir explicitly: ssh-sign sign defaults to the CWD's
        # git root, but seal may target a different repo via --repo.
        let sig = ssh-sign sign $manifest_path --key $resolved.key --pubkeys-dir ($root | path join "multiproofs/pubkeys")
        $result = ($result | insert sig $sig)
    }

    # 5. OTS timestamp — anchors the manifest (with root CID) to Bitcoin
    if not $no_stamp {
        let stamp_result = ots stamp $manifest_path
        $result = ($result | insert ots $stamp_result.ots)
    }

    $result
}
